"""Codex rollout token-usage extractor.

Codex emits per-turn usage as an `event_msg` of type `token_count`:

    {
      "type": "event_msg",
      "payload": {
        "type": "token_count",
        "info": {
          "last_token_usage": {
            "input_tokens": 3655,
            "cached_input_tokens": 2048,
            "output_tokens": 105,
            "reasoning_output_tokens": 64
          },
          "total_token_usage": {...},
          "model_context_window": 272000
        }
      }
    }

We attribute the per-turn delta (`last_token_usage`) to the row.
Codex does NOT carry the model id on this event — the model is
declared earlier in `turn_context`. The ingest layer threads the
most-recently-seen model into the row; this extractor leaves
`model=None`.

Codex doesn't currently surface `service_tier`. Kept as None.
"""

from __future__ import annotations

from typing import Any

from clawjournal.events.cost.types import DATA_SOURCE_API, TokenUsage


def extract_tokens(line: dict) -> TokenUsage | None:
    if line.get("type") != "event_msg":
        return None
    payload = line.get("payload")
    if not isinstance(payload, dict):
        return None
    if payload.get("type") != "token_count":
        return None
    info = payload.get("info")
    if not isinstance(info, dict):
        return None

    # `last_token_usage` is the per-turn delta — what we actually want
    # to attribute to a single events row. `total_token_usage` is the
    # session-cumulative figure and would double-count if we used it
    # across rows.
    usage = info.get("last_token_usage")
    if not isinstance(usage, dict):
        return None

    input_tokens = _as_int(usage.get("input_tokens"))
    output_tokens = _as_int(usage.get("output_tokens"))
    cache_read = _as_int(usage.get("cached_input_tokens"))
    reasoning = _as_int(usage.get("reasoning_output_tokens"))
    service_tier = _as_str(usage.get("service_tier"))

    if all(
        v is None
        for v in (input_tokens, output_tokens, cache_read, reasoning)
    ):
        return None

    return TokenUsage(
        model=None,
        input=input_tokens,
        output=output_tokens,
        cache_read=cache_read,
        cache_write=None,  # Codex/OpenAI don't bill cache writes today
        reasoning=reasoning,
        service_tier=service_tier,
        data_source=DATA_SOURCE_API,
    )


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _as_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
