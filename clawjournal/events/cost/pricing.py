"""Model normalization + versioned pricing table for the cost ledger.

`normalize_model(raw)` turns a vendor model id into a
`ModelInfo(family, tier, provider)` triple suitable for pricing-table
lookup. Handles Claude (`opus` / `sonnet` / `haiku`), OpenAI
(`o1`/`o3`/`o4`/`gpt-*`), and Gemini (`flash` / `pro` / `ultra`),
with an `unknown` fallback that preserves the raw id as the tier so
debug output stays meaningful.

Pricing is keyed by `(family, tier)` with provider expressed
explicitly per entry so cross-provider name collisions (e.g. an
OpenAI vs. a Google model that both happen to be called `flash`)
cannot accidentally share a row. `cost_estimate` is plainly an
estimate — never billed truth — and exported bundles carry
`PRICING_TABLE_VERSION` so off-machine review can pin the table that
produced the numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

# Bumped whenever a price changes. Persisted on every token_usage row
# and exported alongside bundles so consumers know which table the
# cost_estimate column was computed against.
PRICING_TABLE_VERSION = "2026-04-21"


@dataclass(frozen=True)
class ModelInfo:
    family: str
    tier: str
    provider: str


@dataclass(frozen=True)
class PricingEntry:
    """USD per 1M tokens by token kind. Reasoning is split out per
    open-question recommendation in 04-cost-ledger.md (vendors bill
    thinking separately)."""

    input: float
    output: float
    cache_read: float = 0.0
    cache_write: float = 0.0
    reasoning: float = 0.0


# Keyed by `(family, tier)` to avoid cross-provider collisions.
# Numbers reflect public list prices observed early 2026 and are
# treated by the rest of the ledger as estimates only — they are not
# a billing source of truth.
PRICING_TABLE: dict[tuple[str, str], PricingEntry] = {
    # --- Anthropic (Claude) ---
    ("claude", "opus"):   PricingEntry(input=15.00, output=75.00, cache_read=1.50,  cache_write=18.75, reasoning=75.00),
    ("claude", "sonnet"): PricingEntry(input=3.00,  output=15.00, cache_read=0.30,  cache_write=3.75,  reasoning=15.00),
    ("claude", "haiku"):  PricingEntry(input=1.00,  output=5.00,  cache_read=0.10,  cache_write=1.25,  reasoning=5.00),
    # --- OpenAI ---
    ("gpt", "5.4"):       PricingEntry(input=2.50,  output=15.00, cache_read=0.25,  reasoning=15.00),
    ("gpt", "5.4-mini"):  PricingEntry(input=0.75,  output=4.50,  cache_read=0.075, reasoning=4.50),
    ("gpt", "5.4-nano"):  PricingEntry(input=0.20,  output=1.25,  cache_read=0.02,  reasoning=1.25),
    ("gpt", "5.3-codex"): PricingEntry(input=1.75,  output=14.00, cache_read=0.175, reasoning=14.00),
    ("gpt", "5.2"):       PricingEntry(input=1.75,  output=14.00, cache_read=0.175, reasoning=14.00),
    ("gpt", "5.2-codex"): PricingEntry(input=1.75,  output=14.00, cache_read=0.175, reasoning=14.00),
    ("gpt", "5.1"):       PricingEntry(input=1.25,  output=10.00, cache_read=0.125, reasoning=10.00),
    ("gpt", "5.1-codex"): PricingEntry(input=1.25,  output=10.00, cache_read=0.125, reasoning=10.00),
    ("gpt", "5.1-codex-max"): PricingEntry(input=1.25, output=10.00, cache_read=0.125, reasoning=10.00),
    ("gpt", "5"):         PricingEntry(input=1.25,  output=10.00, cache_read=0.125, reasoning=10.00),
    ("gpt", "5-codex"):   PricingEntry(input=1.25,  output=10.00, cache_read=0.125, reasoning=10.00),
    ("gpt", "5-mini"):    PricingEntry(input=0.25,  output=2.00,  cache_read=0.025, reasoning=2.00),
    ("gpt", "5-nano"):    PricingEntry(input=0.05,  output=0.40,  cache_read=0.005, reasoning=0.40),
    ("gpt", "5-pro"):     PricingEntry(input=15.00, output=120.00, reasoning=120.00),
    ("gpt", "4.1"):       PricingEntry(input=2.00,  output=8.00,  cache_read=0.50,  reasoning=8.00),
    ("gpt", "4.1-mini"):  PricingEntry(input=0.40,  output=1.60, cache_read=0.10,  reasoning=1.60),
    ("gpt", "4o"):        PricingEntry(input=2.50,  output=10.00, cache_read=1.25, reasoning=10.00),
    ("gpt", "4o-mini"):   PricingEntry(input=0.15,  output=0.60, cache_read=0.075, reasoning=0.60),
    ("o", "1"):           PricingEntry(input=15.00, output=60.00, reasoning=60.00),
    ("o", "1-mini"):      PricingEntry(input=3.00,  output=12.00, reasoning=12.00),
    ("o", "3"):           PricingEntry(input=2.00,  output=8.00,  reasoning=8.00),
    ("o", "3-mini"):      PricingEntry(input=1.10,  output=4.40,  reasoning=4.40),
    ("o", "4-mini"):      PricingEntry(input=1.10,  output=4.40,  reasoning=4.40),
    # --- Google (Gemini) ---
    ("gemini", "pro"):    PricingEntry(input=1.25,  output=10.00),
    ("gemini", "flash"):  PricingEntry(input=0.30,  output=2.50),
    ("gemini", "ultra"):  PricingEntry(input=7.00,  output=21.00),
}


def normalize_model(raw: str | None) -> ModelInfo:
    """Map a vendor model id to a `(family, tier, provider)` triple.

    The raw id may include provider prefixes (`anthropic/...`),
    snapshot dates (`...-20241022`), or marketing suffixes. The
    normalizer tries to extract `family` (`claude` / `gpt` / `o` /
    `gemini`) and `tier` (`opus`/`sonnet`/`haiku`/`4o`/`pro`/...)
    deterministically. Anything it cannot place returns
    `ModelInfo(family="unknown", tier=<raw>, provider="unknown")` so
    the original string survives in pricing-table-lookup misses for
    debugging.
    """
    if not raw or not isinstance(raw, str):
        return ModelInfo(family="unknown", tier="", provider="unknown")

    cleaned = raw.strip()
    if not cleaned:
        return ModelInfo(family="unknown", tier="", provider="unknown")

    lowered = cleaned.lower()
    if "/" in lowered:
        lowered = lowered.rsplit("/", 1)[-1]

    # --- Anthropic (Claude) ---
    if "claude" in lowered:
        for tier in ("opus", "sonnet", "haiku"):
            if tier in lowered:
                return ModelInfo(family="claude", tier=tier, provider="anthropic")
        return ModelInfo(family="claude", tier=lowered, provider="anthropic")

    # --- OpenAI o-series (must check before "gpt" because "o3" et al
    # do not contain "gpt"). Order matters: longer tiers first so that
    # `o3-mini` doesn't collapse to `3`.
    o_tiers = ("4-mini", "3-mini", "1-mini", "4", "3", "1")
    for tier in o_tiers:
        prefix = f"o{tier}"
        if lowered == prefix or lowered.startswith(f"{prefix}-") or lowered.startswith(f"{prefix}_"):
            return ModelInfo(family="o", tier=tier, provider="openai")

    # --- OpenAI GPT-4-class ---
    if "gpt" in lowered:
        # Match longer tiers first so suffixed Codex / mini variants don't
        # collapse onto shorter parents.
        for tier in (
            "5.4-mini",
            "5.4-nano",
            "5.4",
            "5.3-codex",
            "5.2-codex",
            "5.2",
            "5.1-codex-max",
            "5.1-codex",
            "5.1",
            "5-codex",
            "5-pro",
            "5-mini",
            "5-nano",
            "5",
            "4.1-mini",
            "4.1",
            "4o-mini",
            "4o",
            "4-turbo",
            "4",
            "3.5",
        ):
            prefix = f"gpt-{tier}"
            if lowered == prefix or lowered.startswith(f"{prefix}-") or lowered.startswith(f"{prefix}_"):
                return ModelInfo(family="gpt", tier=tier, provider="openai")
        return ModelInfo(family="gpt", tier=lowered, provider="openai")

    # --- Gemini ---
    if "gemini" in lowered:
        for tier in ("flash", "pro", "ultra"):
            if tier in lowered:
                return ModelInfo(family="gemini", tier=tier, provider="google")
        return ModelInfo(family="gemini", tier=lowered, provider="google")

    return ModelInfo(family="unknown", tier=cleaned, provider="unknown")


def estimate_cost(
    model_info: ModelInfo,
    *,
    input_tokens: int | None,
    output_tokens: int | None,
    cache_read_tokens: int | None = None,
    cache_write_tokens: int | None = None,
    reasoning_tokens: int | None = None,
) -> float | None:
    """Return USD cost estimate, or None if the model isn't priced.

    `None` token counts are treated as 0 for the cost arithmetic only.
    Persistence layer keeps them as NULL so confidence semantics
    survive — this helper is purely the dollars math.
    """
    entry = PRICING_TABLE.get((model_info.family, model_info.tier))
    if entry is None:
        return None
    inp = input_tokens or 0
    out = output_tokens or 0
    cr = cache_read_tokens or 0
    cw = cache_write_tokens or 0
    rs = reasoning_tokens or 0
    cost = (
        inp * entry.input
        + out * entry.output
        + cr * entry.cache_read
        + cw * entry.cache_write
        + rs * entry.reasoning
    ) / 1_000_000
    return cost
