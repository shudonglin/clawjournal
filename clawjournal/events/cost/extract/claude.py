"""Claude (and OpenClaw) JSONL token-usage extractor.

Anthropic's wire format puts the usage block on assistant messages:

    {
      "type": "assistant",
      "message": {
        "model": "claude-opus-4-6",
        "usage": {
          "input_tokens": 3,
          "output_tokens": 621,
          "cache_creation_input_tokens": 12263,
          "cache_read_input_tokens": 11895,
          "service_tier": "standard",
          ...
        }
      }
    }

Older client versions used `cache_creation_tokens` / `cache_read_tokens`
without the `_input` infix. Both spellings are accepted; the canonical
spelling per current vendor docs is the `_input` form. Reasoning
tokens are not surfaced separately by Anthropic today (they roll
into `output_tokens`); we leave `reasoning=None` rather than guess.
"""

from __future__ import annotations

from typing import Any

from clawjournal.events.cost.types import DATA_SOURCE_API, TokenUsage


def extract_tokens(line: dict) -> TokenUsage | None:
    if line.get("type") != "assistant":
        return None
    message = line.get("message")
    if not isinstance(message, dict):
        return None
    usage = message.get("usage")
    if not isinstance(usage, dict):
        return None

    model = _as_str(message.get("model")) or _as_str(line.get("model"))
    input_tokens = _as_int(usage.get("input_tokens"))
    output_tokens = _as_int(usage.get("output_tokens"))
    cache_read = _first_int(
        usage.get("cache_read_input_tokens"),
        usage.get("cache_read_tokens"),
    )
    cache_write = _first_int(
        usage.get("cache_creation_input_tokens"),
        usage.get("cache_creation_tokens"),
    )
    reasoning = _as_int(usage.get("reasoning_tokens"))
    service_tier = _as_str(usage.get("service_tier"))

    if all(
        v is None
        for v in (input_tokens, output_tokens, cache_read, cache_write, reasoning)
    ):
        return None

    return TokenUsage(
        model=model,
        input=input_tokens,
        output=output_tokens,
        cache_read=cache_read,
        cache_write=cache_write,
        reasoning=reasoning,
        service_tier=service_tier,
        data_source=DATA_SOURCE_API,
    )


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):  # bool is a subclass of int — reject it
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _first_int(*values: Any) -> int | None:
    for v in values:
        out = _as_int(v)
        if out is not None:
            return out
    return None


def _as_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
