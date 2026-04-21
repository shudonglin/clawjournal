"""Golden-file tests for the model normalizer + pricing-table lookups."""

from __future__ import annotations

import pytest

from clawjournal.events.cost import (
    PRICING_TABLE,
    PRICING_TABLE_VERSION,
    ModelInfo,
    estimate_cost,
    normalize_model,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        # --- Anthropic ---
        ("claude-3-5-sonnet-20241022", ModelInfo("claude", "sonnet", "anthropic")),
        ("claude-opus-4-6", ModelInfo("claude", "opus", "anthropic")),
        ("claude-haiku-4-5-20251001", ModelInfo("claude", "haiku", "anthropic")),
        ("anthropic/claude-haiku-4-5", ModelInfo("claude", "haiku", "anthropic")),
        # --- OpenAI o-series ---
        ("o1", ModelInfo("o", "1", "openai")),
        ("o1-mini", ModelInfo("o", "1-mini", "openai")),
        ("o3", ModelInfo("o", "3", "openai")),
        ("o3-mini-2025-01-31", ModelInfo("o", "3-mini", "openai")),
        ("o4-mini", ModelInfo("o", "4-mini", "openai")),
        # --- OpenAI GPT ---
        ("gpt-4o", ModelInfo("gpt", "4o", "openai")),
        ("gpt-4o-mini", ModelInfo("gpt", "4o-mini", "openai")),
        ("gpt-4.1", ModelInfo("gpt", "4.1", "openai")),
        ("gpt-4.1-mini", ModelInfo("gpt", "4.1-mini", "openai")),
        ("gpt-5-codex", ModelInfo("gpt", "5-codex", "openai")),
        ("gpt-5.3-codex", ModelInfo("gpt", "5.3-codex", "openai")),
        ("gpt-5.4", ModelInfo("gpt", "5.4", "openai")),
        ("gpt-5.4-mini", ModelInfo("gpt", "5.4-mini", "openai")),
        ("openai/gpt-4o", ModelInfo("gpt", "4o", "openai")),
        # --- Gemini ---
        ("gemini-2.5-flash", ModelInfo("gemini", "flash", "google")),
        ("gemini-2.5-pro", ModelInfo("gemini", "pro", "google")),
        ("gemini-ultra", ModelInfo("gemini", "ultra", "google")),
        # --- fallback ---
        ("some-novel-frontier-model", ModelInfo("unknown", "some-novel-frontier-model", "unknown")),
        ("", ModelInfo("unknown", "", "unknown")),
        (None, ModelInfo("unknown", "", "unknown")),
    ],
)
def test_normalize_model_golden(raw, expected):
    assert normalize_model(raw) == expected


def test_pricing_table_version_is_a_string():
    assert isinstance(PRICING_TABLE_VERSION, str)
    assert PRICING_TABLE_VERSION  # non-empty


def test_pricing_table_covers_canonical_families():
    assert ("claude", "opus") in PRICING_TABLE
    assert ("claude", "sonnet") in PRICING_TABLE
    assert ("claude", "haiku") in PRICING_TABLE
    assert ("o", "3") in PRICING_TABLE
    assert ("gpt", "4o") in PRICING_TABLE
    assert ("gpt", "5-codex") in PRICING_TABLE
    assert ("gpt", "5.3-codex") in PRICING_TABLE
    assert ("gemini", "flash") in PRICING_TABLE


def test_estimate_cost_known_model():
    info = normalize_model("claude-sonnet-4-6")
    cost = estimate_cost(
        info,
        input_tokens=1_000_000,
        output_tokens=1_000_000,
    )
    # Sonnet is $3 input + $15 output per 1M.
    assert cost == pytest.approx(3.00 + 15.00)


def test_estimate_cost_returns_none_for_unknown_model():
    info = normalize_model("future-model-xyz")
    assert (
        estimate_cost(info, input_tokens=1, output_tokens=1) is None
    )


def test_estimate_cost_treats_none_counts_as_zero():
    info = normalize_model("claude-haiku-4-5")
    cost = estimate_cost(
        info,
        input_tokens=None,
        output_tokens=None,
        cache_read_tokens=None,
        cache_write_tokens=None,
        reasoning_tokens=None,
    )
    assert cost == 0.0


def test_estimate_cost_includes_cache_read_and_write():
    info = normalize_model("claude-opus-4-6")
    entry = PRICING_TABLE[("claude", "opus")]
    cost = estimate_cost(
        info,
        input_tokens=0,
        output_tokens=0,
        cache_read_tokens=1_000_000,
        cache_write_tokens=1_000_000,
    )
    assert cost == pytest.approx(entry.cache_read + entry.cache_write)


def test_estimate_cost_includes_reasoning_for_gpt_codex():
    info = normalize_model("gpt-5.3-codex")
    entry = PRICING_TABLE[("gpt", "5.3-codex")]
    cost = estimate_cost(
        info,
        input_tokens=0,
        output_tokens=0,
        reasoning_tokens=1_000_000,
    )
    assert cost == pytest.approx(entry.reasoning)
