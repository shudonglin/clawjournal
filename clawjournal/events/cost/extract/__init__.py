"""Per-client token-usage extractors.

Each extractor takes a parsed JSONL line dict and returns a
`TokenUsage` populated from the vendor's own usage block, or `None`
when the line carries no extractable usage. The dispatcher
`extract_tokens(client, line)` picks the right extractor for the
client.

Estimation (`data_source='estimated'`) is NOT performed in the
extractors — that's the ingest layer's call, when no extractor
returned anything for a turn the user is asking about. Extractors
only emit `data_source='api'`.
"""

from __future__ import annotations

from typing import Callable

from clawjournal.events.cost.extract.claude import extract_tokens as _claude
from clawjournal.events.cost.extract.codex import extract_tokens as _codex
from clawjournal.events.cost.types import TokenUsage

_EXTRACTORS: dict[str, Callable[[dict], TokenUsage | None]] = {
    "claude": _claude,
    "codex": _codex,
    # OpenClaw mirrors Claude's wire format closely; reuse the same
    # extractor until the client diverges enough to justify a peer.
    "openclaw": _claude,
}


def extract_tokens(client: str, line: dict) -> TokenUsage | None:
    """Dispatch to the appropriate per-client extractor.

    Returns None when the client is unknown or when the line has no
    usage block to report. Callers MUST treat None as "no API-source
    data" rather than as zero counts.
    """
    extractor = _EXTRACTORS.get(client)
    if extractor is None:
        return None
    if not isinstance(line, dict):
        return None
    return extractor(line)


__all__ = ["extract_tokens"]
