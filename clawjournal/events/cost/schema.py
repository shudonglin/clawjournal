"""SQLite schema for the cost ledger (phase-1 plan 04).

Three tables:

- `token_usage` — one row per `events.id` that carried a usage block.
  Columns mirror the spec, with `data_source` CHECK-constrained to
  `api` / `estimated`. Numeric columns are nullable so that a vendor
  field the client doesn't emit can stay NULL (and surface as
  `confidence=missing` via the 03 layer) rather than being coerced to
  zero.

- `cost_anomalies` — one row per detected anomaly (cache_read_collapse,
  input_spike, model_shift, service_tier_shift). `evidence_json`
  carries the per-anomaly context (e.g. previous + current token
  counts, threshold used).

- `cost_ingest_state` — lightweight cursor state for the cost-ledger
  consumer so already-examined non-usage events do not get rescanned on
  every run.

All tables live in `~/.clawjournal/index.db` alongside 02's
`events` / `event_sessions`.
"""

from __future__ import annotations

import sqlite3

TOKEN_USAGE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS token_usage (
    event_id              INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    session_id            INTEGER NOT NULL REFERENCES event_sessions(id) ON DELETE CASCADE,
    model                 TEXT,
    model_family          TEXT,
    model_tier            TEXT,
    model_provider        TEXT,
    input                 INTEGER,
    output                INTEGER,
    cache_read            INTEGER,
    cache_write           INTEGER,
    reasoning             INTEGER,
    service_tier          TEXT,
    data_source           TEXT    NOT NULL CHECK (data_source IN ('api','estimated')),
    cost_estimate         REAL,
    pricing_table_version TEXT,
    event_at              TEXT
);
CREATE INDEX IF NOT EXISTS idx_token_usage_session
    ON token_usage(session_id, event_at);
CREATE INDEX IF NOT EXISTS idx_token_usage_data_source
    ON token_usage(session_id, data_source);
"""

COST_INGEST_STATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cost_ingest_state (
    consumer_id   TEXT PRIMARY KEY,
    last_event_id INTEGER NOT NULL
);
"""

COST_ANOMALIES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cost_anomalies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     INTEGER NOT NULL REFERENCES event_sessions(id) ON DELETE CASCADE,
    turn_event_id  INTEGER REFERENCES events(id) ON DELETE SET NULL,
    kind           TEXT    NOT NULL,
    confidence     TEXT    NOT NULL,
    evidence_json  TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    UNIQUE (session_id, kind, turn_event_id)
);
CREATE INDEX IF NOT EXISTS idx_cost_anomalies_session
    ON cost_anomalies(session_id, kind);
"""


def ensure_cost_schema(conn: sqlite3.Connection) -> None:
    """Create cost-ledger tables if absent. Safe to call repeatedly."""
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(TOKEN_USAGE_TABLE_SQL)
    conn.executescript(COST_INGEST_STATE_TABLE_SQL)
    conn.executescript(COST_ANOMALIES_TABLE_SQL)
