"""Per-client token-extractor unit tests."""

from __future__ import annotations

from clawjournal.events.cost import DATA_SOURCE_API, extract_tokens
from clawjournal.events.cost.extract import extract_tokens as direct_extract


def test_claude_assistant_with_full_usage_block():
    line = {
        "type": "assistant",
        "message": {
            "model": "claude-opus-4-6",
            "usage": {
                "input_tokens": 3,
                "output_tokens": 621,
                "cache_creation_input_tokens": 12263,
                "cache_read_input_tokens": 11895,
                "service_tier": "standard",
            },
        },
    }
    usage = extract_tokens("claude", line)
    assert usage is not None
    assert usage.model == "claude-opus-4-6"
    assert usage.input == 3
    assert usage.output == 621
    assert usage.cache_read == 11895
    assert usage.cache_write == 12263
    assert usage.reasoning is None
    assert usage.service_tier == "standard"
    assert usage.data_source == DATA_SOURCE_API


def test_claude_legacy_field_aliases():
    """Older client versions emit cache_*_tokens without the
    `_input` infix — the extractor must accept both spellings."""
    line = {
        "type": "assistant",
        "message": {
            "model": "claude-sonnet-4",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_tokens": 7,
                "cache_read_tokens": 3,
            },
        },
    }
    usage = extract_tokens("claude", line)
    assert usage is not None
    assert usage.cache_read == 3
    assert usage.cache_write == 7


def test_claude_canonical_field_takes_precedence_over_legacy():
    line = {
        "type": "assistant",
        "message": {
            "model": "claude-sonnet-4",
            "usage": {
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_read_input_tokens": 999,
                "cache_read_tokens": 1,
                "cache_creation_input_tokens": 888,
                "cache_creation_tokens": 1,
            },
        },
    }
    usage = extract_tokens("claude", line)
    assert usage.cache_read == 999
    assert usage.cache_write == 888


def test_claude_missing_field_stays_none_not_zero():
    """A vendor field that wasn't emitted must stay None so the
    capability layer can surface it as `confidence=missing`."""
    line = {
        "type": "assistant",
        "message": {
            "model": "claude-opus-4-6",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
            },
        },
    }
    usage = extract_tokens("claude", line)
    assert usage is not None
    assert usage.input == 10
    assert usage.cache_read is None
    assert usage.cache_write is None
    assert usage.reasoning is None


def test_claude_non_assistant_returns_none():
    assert extract_tokens("claude", {"type": "user"}) is None


def test_claude_no_usage_block_returns_none():
    assert (
        extract_tokens(
            "claude", {"type": "assistant", "message": {"model": "x"}}
        )
        is None
    )


def test_codex_token_count_event_extracts_last_turn_usage():
    line = {
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {
                "last_token_usage": {
                    "input_tokens": 3655,
                    "cached_input_tokens": 2048,
                    "output_tokens": 105,
                    "reasoning_output_tokens": 64,
                },
                "total_token_usage": {
                    "input_tokens": 9999,
                    "output_tokens": 999,
                },
            },
        },
    }
    usage = extract_tokens("codex", line)
    assert usage is not None
    # Per-turn delta wins over cumulative, otherwise we'd double-count.
    assert usage.input == 3655
    assert usage.cache_read == 2048
    assert usage.output == 105
    assert usage.reasoning == 64
    assert usage.cache_write is None
    assert usage.model is None  # threaded in by the ingest layer
    assert usage.data_source == DATA_SOURCE_API


def test_codex_token_count_with_no_info_returns_none():
    line = {
        "type": "event_msg",
        "payload": {"type": "token_count", "info": None},
    }
    assert extract_tokens("codex", line) is None


def test_codex_unrelated_event_returns_none():
    line = {"type": "turn_context", "payload": {"model": "gpt-5-codex"}}
    assert extract_tokens("codex", line) is None


def test_dispatcher_unknown_client_returns_none():
    assert direct_extract("not-a-client", {"type": "assistant"}) is None


def test_dispatcher_handles_non_dict_line():
    assert direct_extract("claude", "not a dict") is None  # type: ignore[arg-type]


def test_openclaw_uses_claude_extractor():
    """OpenClaw mirrors Claude's wire format; sanity-check the alias."""
    line = {
        "type": "assistant",
        "message": {
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 1, "output_tokens": 2},
        },
    }
    usage = extract_tokens("openclaw", line)
    assert usage is not None
    assert usage.model == "claude-haiku-4-5"
