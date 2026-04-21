"""Dataclasses + constants for the cost ledger (phase-1 plan 04)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DATA_SOURCE_API = "api"
DATA_SOURCE_ESTIMATED = "estimated"
VALID_DATA_SOURCES = {DATA_SOURCE_API, DATA_SOURCE_ESTIMATED}


@dataclass(frozen=True)
class TokenUsage:
    """Token counts attributable to a single `events` row.

    A `None` count is "the vendor did not emit this field" — it must
    NOT be coerced to 0, since 03's capability_join needs to surface
    these as `confidence=missing` rather than as legitimate zero usage.

    `data_source='api'` means the values came verbatim from the
    vendor's usage block (Anthropic `usage`, OpenAI `token_count`,
    etc). `data_source='estimated'` means they were inferred from
    content length and downstream anomaly detectors must skip them.
    """

    model: str | None
    input: int | None
    output: int | None
    cache_read: int | None
    cache_write: int | None
    reasoning: int | None
    service_tier: str | None
    data_source: str

    def __post_init__(self) -> None:
        if self.data_source not in VALID_DATA_SOURCES:
            raise ValueError(
                f"Invalid data_source: {self.data_source!r} "
                f"(valid: {sorted(VALID_DATA_SOURCES)})"
            )


@dataclass(frozen=True)
class CostAnomaly:
    """A detected divergence between adjacent token-usage rows."""

    session_id: int
    turn_event_id: int | None
    kind: str
    confidence: str
    evidence: dict[str, Any] = field(default_factory=dict)
