'campaign.db schema v2: event-sourced attempts ledger.\n\nEvent kinds (attempt.* kinds rebuild the attempts table via fold; all other\nkinds are operational only and never mutate it):\n\n    attempt.reserved | attempt.dispatched | attempt.reconciled\n    attempt.voided   | attempt.expired_spent        -> attempts\n    campaign.init | campaign.amended | campaign.migrated\n    slice.planned | slice.reconciled | detection.annotated -> (no table)\n\nEVENT_KINDS is a CLOSED tuple: the ledger\'s _append_event refuses unlisted\nkinds, and the v2->... ordering above is load-bearing documentation only —\nthe tuple order itself is just chronological by introduction.\n\nSchema invariants: one kind -> one table, every sourced event carries its\ntable PK inside payload["snapshot"], and fold() == materialized rows is the\ninvariant `babayaga events --verify` checks. BABAYAGA has NO unsourced\ntable — attempts are a permanent compliance ledger, the opposite of\ndisposable.\n\nMigration defaults (V2_ATTEMPT_DEFAULTS) are applied to pre-v2 snapshots on\nBOTH sides of verify(): the materialized rows acquire them from the ALTER,\nand the ledger\'s fold() applies the same map to pre-v2 event snapshots, so\nthe comparison stays like-shaped and deterministic. `action_kind` backfills\nto \'guess\' (true by construction: v1 had no exec path); instrument identity\nand the per-attempt roe_digest stay NULL — unrecorded is unknown and is\nnever backfilled with a fabrication (CATEGORY.md errata 18).\n\nSeal interplay: migration appends one event and changes the materialized\nrows, so every digest of a pre-v2 seal drifts at the first v2 open —\nverify_seal reports the drift (fail-closed) and the operator re-seals\n(seal.py docstring).\n'

from __future__ import annotations

import json
import sqlite3
import time

SCHEMA_VERSION = 2

EVENT_KINDS = (
    "campaign.init",
    "campaign.amended",
    "campaign.migrated",
    "slice.planned",
    "slice.reconciled",
    "detection.annotated",
    "attempt.reserved",
    "attempt.dispatched",
    "attempt.reconciled",
    "attempt.voided",
    "attempt.expired_spent",
)
ATTEMPT_KINDS = tuple(k for k in EVENT_KINDS if k.startswith("attempt."))

# kinds that mutate the attempts table when folded (kind -> source table)
EVENT_TABLE_BY_KIND = {k: "attempts" for k in ATTEMPT_KINDS}
# tables with no sourcing events (must stay empty in v2)
EVENT_UNSOURCED_TABLES: frozenset[str] = frozenset()

ACTION_KINDS = ("guess", "exec")
OUTCOMES_BY_KIND = {
    "guess": ("valid", "invalid", "locked", "error"),
    "exec": ("effect_confirmed", "effect_denied", "locked", "error"),
}

# Defaults a pre-v2 attempts row/snapshot acquires at migration. Only
# action_kind is knowable ('guess': v1 could only guess); the rest stay
# NULL (module docstring).
V2_ATTEMPT_DEFAULTS = {
    "action_kind": "guess",
    "instrument": None,
    "instrument_version": None,
    "roe_digest": None,
}

DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    kind      TEXT    NOT NULL,
    entity_id TEXT    NOT NULL,
    payload   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS events_kind_idx ON events(kind);
CREATE INDEX IF NOT EXISTS events_entity_idx ON events(entity_id);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id      TEXT PRIMARY KEY,
    slice_id        TEXT NOT NULL,
    principal       TEXT NOT NULL,
    target_host     TEXT NOT NULL,
    target_port     INTEGER NOT NULL,
    material_digest TEXT NOT NULL,
    state           TEXT NOT NULL,
    outcome         TEXT,
    reserved_ts     REAL NOT NULL,
    dispatched_ts   REAL,
    resolved_ts     REAL,
    action_kind     TEXT NOT NULL DEFAULT 'guess',
    instrument      TEXT,
    instrument_version TEXT,
    roe_digest      TEXT
);
CREATE INDEX IF NOT EXISTS attempts_state_idx ON attempts(state);
CREATE INDEX IF NOT EXISTS attempts_principal_idx ON attempts(principal);
"""

ATTEMPT_COLUMNS = (
    "attempt_id", "slice_id", "principal", "target_host", "target_port",
    "material_digest", "state", "outcome", "reserved_ts", "dispatched_ts", "resolved_ts",
    "action_kind", "instrument", "instrument_version", "roe_digest",
)


class SchemaError(Exception):
    """Unexpected schema state (exit 1): a db newer than this engine, or a
    migration that could not complete. Fail-closed, never a guess."""


def _migrate_1_to_2(conn: sqlite3.Connection) -> None:
    """ALTER attempts to the v2 shape + exactly ONE campaign.migrated event.

    SQLite DDL is transactional, so the BEGIN IMMEDIATE block is
    all-or-nothing: a crash mid-migration rolls the db back to v1.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "ALTER TABLE attempts ADD COLUMN action_kind TEXT NOT NULL DEFAULT 'guess'")
        conn.execute("ALTER TABLE attempts ADD COLUMN instrument TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN instrument_version TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN roe_digest TEXT")
        # Entity: the engagement from campaign.init when one exists, else the
        # campaign itself (an initialized-less db still migrates).
        row = conn.execute(
            "SELECT entity_id FROM events WHERE kind='campaign.init' "
            "ORDER BY id LIMIT 1").fetchone()
        entity = row[0] if row else "campaign"
        kind = "campaign.migrated"
        if kind not in EVENT_KINDS:  # mirrors the ledger's closed-kind gate
            raise SchemaError(f"{kind!r} is not a declared event kind")
        payload = {
            "from_version": 1,
            "to_version": SCHEMA_VERSION,
            "added_columns": list(V2_ATTEMPT_DEFAULTS),
            "defaults": V2_ATTEMPT_DEFAULTS,
        }
        conn.execute(
            "INSERT INTO events(ts, kind, entity_id, payload) VALUES(?,?,?,?)",
            (time.time(), kind, entity,
             json.dumps(payload, sort_keys=True, separators=(",", ":"))))
        conn.execute(
            "UPDATE meta SET value=? WHERE key='schema_version'",
            (str(SCHEMA_VERSION),))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)  # explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(DDL)  # fresh dbs get the v2 shape; existing dbs no-op
    row = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        return conn
    try:
        version = int(row[0])
    except ValueError as exc:
        raise SchemaError(f"meta.schema_version unreadable: {row[0]!r}") from exc
    if version == SCHEMA_VERSION:
        return conn
    if version > SCHEMA_VERSION:
        raise SchemaError(
            f"campaign.db schema_version {version} is newer than this engine "
            f"understands ({SCHEMA_VERSION}) — refusing to open it")
    if version == 1:
        _migrate_1_to_2(conn)
        return conn
    raise SchemaError(f"no migration path from schema_version {version}")
