'Attempts ledger: event + row in ONE transaction, fold == materialized.\n\nEvery mutation writes the sourcing event (with a full row snapshot carrying\nthe table PK) and updates the materialized attempts row inside a single\nBEGIN IMMEDIATE transaction, so the ledger can always be rebuilt by fold()\nand compared by verify().'

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path

from . import budget as budget_mod
from . import schema
from .state_machine import IllegalTransition, transition


class LedgerError(Exception):
    """Unexpected ledger failure (exit 1)."""


class LedgerRefusal(Exception):
    """Ledger-side refusal (exit 2): illegal per state machine."""


def _canonical(obj: object) -> bytes:
    """Canonical bytes for digesting: JSON, sorted keys, compact separators.

    REAL columns arrive as Python floats and render through CPython's
    shortest-round-trip float repr, which is exact for IEEE-754 doubles and
    therefore byte-stable across processes and platforms. NaN/Inf would
    serialize as bare tokens (invalid JSON), so they are rejected outright:
    a ledger carrying them is corrupt, and digesting must fail closed.
    """
    try:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except ValueError as exc:
        raise LedgerError(f"uncanonizable ledger content: {exc}") from exc


def _now() -> float:
    return time.time()


class Ledger:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = schema.connect(self.path)

    def close(self) -> None:
        self.conn.close()

    # -- events ---------------------------------------------------------

    def _append_event(self, kind: str, entity_id: str, payload: dict) -> None:
        if kind not in schema.EVENT_KINDS:
            raise LedgerError(f"unknown event kind {kind!r}")
        self.conn.execute(
            "INSERT INTO events(ts, kind, entity_id, payload) VALUES(?,?,?,?)",
            (_now(), kind, entity_id, json.dumps(payload, sort_keys=True, separators=(",", ":"))),
        )

    def events(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM events ORDER BY id").fetchall()

    # -- campaign -------------------------------------------------------

    def init_campaign(self, roe_digest: str, engagement_id: str) -> None:
        ''
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._meta("roe_digest")
            if current is not None:
                raise LedgerRefusal(
                    f"campaign already initialized under roe_digest "
                    f"{current[:12]}… — re-init is refused; a governed ROE "
                    "change goes through amend_campaign (operator re-attestation)")
            self._append_event(
                "campaign.init",
                engagement_id,
                {"engagement_id": engagement_id, "roe_digest": roe_digest},
            )
            self.conn.execute("INSERT INTO meta(key, value) VALUES('roe_digest', ?)", (roe_digest,))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def _engagement_id(self) -> str:
        row = self.conn.execute(
            "SELECT entity_id FROM events WHERE kind='campaign.init' "
            "ORDER BY id LIMIT 1").fetchone()
        if row is None:
            raise LedgerError("campaign.init event missing — ledger corrupt")
        return row[0]

    def amend_campaign(self, old_digest: str, new_draft: dict) -> str:
        "        Amendments chain linearly: old_digest must equal the currently\n        governing digest (compare-and-swap), the campaign.amended event\n        records old -> new plus the fresh attestation block as evidence, and\n        attempts already recorded keep the digest that governed them.\n        Returns the new governing digest.\n\n        An amendment re-terms the SAME engagement: the draft's\n        engagement_id must equal the campaign's (bound immutably by\n        campaign.init). A draft authored for another engagement is refused —\n        cross-campaign digest binding would attest this campaign under an\n        authorization issued to a different scope.\n        "
        from . import roe as roe_mod

        if not isinstance(old_digest, str) or not old_digest:
            raise LedgerRefusal(
                "old_digest must be a non-empty string (the compare-and-swap "
                "base the amendment chains from)")
        errors = roe_mod.validate(new_draft)
        if errors:
            raise LedgerRefusal(
                "amendment draft is not a valid ROE: " + "; ".join(errors))
        new_digest = roe_mod.digest(new_draft)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._meta("roe_digest")
            if current is None:
                raise LedgerRefusal(
                    "campaign was never initialized — init_campaign first, "
                    "amendment is a change of an existing governing ROE")
            if current != old_digest:
                raise LedgerRefusal(
                    f"stale amendment base: campaign governs at "
                    f"{current[:12]}… but the draft claims old_digest "
                    f"{old_digest[:12]}… — amendments chain linearly; "
                    "re-draft against the current ROE")
            if new_digest == current:
                raise LedgerRefusal(
                    "digest-identical draft carries no fresh re-attestation "
                    "— the flip is conditional on the operator's fresh "
                    "attestation, and an unchanged ROE proves none")
            engagement = self._engagement_id()
            if new_draft["engagement_id"] != engagement:
                raise LedgerRefusal(
                    f"amendment draft is scoped to engagement "
                    f"{new_draft['engagement_id']!r} but this campaign is "
                    f"{engagement!r} — an amendment re-terms the SAME "
                    "engagement; a different engagement is a different "
                    "campaign (init it under its own ROE)")
            self._append_event(
                "campaign.amended",
                engagement,
                {"engagement_id": engagement,
                 "old_roe_digest": current,
                 "new_roe_digest": new_digest,
                 "attestation": new_draft["attestation"]},
            )
            self.conn.execute(
                "UPDATE meta SET value=? WHERE key='roe_digest'", (new_digest,))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        return new_digest

    # -- attempts -------------------------------------------------------

    def _meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def reserve(self, slice_id: str, principal: str, host: str, port: int,
                material_digest: str, *, action_kind: str = "guess",
                instrument: str | None = None,
                instrument_version: str | None = None) -> str:
        """Reserve one attempt on an action axis (schema.ACTION_KINDS).

        The row is stamped with the campaign's CURRENT governing roe_digest
        (read from meta by the ledger itself, never supplied by the caller —
        an attempt's governance is bound, not asserted). Before any
        campaign.init the stamp is NULL and seal/export gates refuse.
        """
        if action_kind not in schema.ACTION_KINDS:
            raise LedgerRefusal(
                f"unknown action_kind {action_kind!r} (closed: {schema.ACTION_KINDS})")
        attempt_id = uuid.uuid4().hex
        row = {
            "attempt_id": attempt_id, "slice_id": slice_id, "principal": principal,
            "target_host": host, "target_port": port, "material_digest": material_digest,
            "state": "reserved", "outcome": None, "reserved_ts": _now(),
            "dispatched_ts": None, "resolved_ts": None,
            "action_kind": action_kind, "instrument": instrument,
            "instrument_version": instrument_version,
            "roe_digest": self._meta("roe_digest"),
        }
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._append_event("attempt.reserved", attempt_id, {"snapshot": row})
            self._insert_row(row)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        return attempt_id

    def _insert_row(self, row: dict) -> None:
        cols = ",".join(schema.ATTEMPT_COLUMNS)
        ph = ",".join("?" for _ in schema.ATTEMPT_COLUMNS)
        self.conn.execute(
            f"INSERT INTO attempts({cols}) VALUES({ph})",
            [row[c] for c in schema.ATTEMPT_COLUMNS],
        )

    def _current(self, attempt_id: str) -> dict:
        cur = self.conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        if cur is None:
            raise LedgerError(f"unknown attempt {attempt_id}")
        return dict(cur)

    def _apply(self, attempt_id: str, event: str, kind: str, mutate, outcome: str | None = None) -> dict:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._current(attempt_id)
            try:
                new_state = transition(row["state"], event, outcome=outcome,
                                       action_kind=row["action_kind"])
            except IllegalTransition as exc:
                raise LedgerRefusal(str(exc)) from exc
            mutate(row)
            row["state"] = new_state
            self._append_event(kind, attempt_id, {"snapshot": row})
            sets = ",".join(f"{c}=?" for c in schema.ATTEMPT_COLUMNS)
            self.conn.execute(
                f"UPDATE attempts SET {sets} WHERE attempt_id=?",
                [row[c] for c in schema.ATTEMPT_COLUMNS] + [attempt_id],
            )
            self.conn.execute("COMMIT")
            return row
        except LedgerRefusal:
            self.conn.execute("ROLLBACK")
            raise
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def dispatch(self, attempt_id: str) -> None:
        """Evidence-first: call BEFORE spawning the instrument."""
        def mutate(row: dict) -> None:
            row["dispatched_ts"] = _now()
        self._apply(attempt_id, "dispatch", "attempt.dispatched", mutate)

    def reconcile(self, attempt_id: str, outcome: str) -> None:
        def mutate(row: dict) -> None:
            row["outcome"] = outcome
            row["resolved_ts"] = _now()
        self._apply(attempt_id, "reconcile", "attempt.reconciled", mutate, outcome=outcome)

    def void(self, attempt_id: str) -> None:
        def mutate(row: dict) -> None:
            row["resolved_ts"] = _now()
        self._apply(attempt_id, "void", "attempt.voided", mutate)

    def expire_spent(self, attempt_id: str) -> None:
        def mutate(row: dict) -> None:
            row["resolved_ts"] = _now()
        self._apply(attempt_id, "expire_spent", "attempt.expired_spent", mutate)

    # -- detection (operational event, no table) -------------------------

    def annotate_detection(self, entity_id: str, detail: str) -> None:
        "        detection.annotated is an OPERATIONAL event: it never mutates the\n        attempts table and `detected` is never a reconcile outcome\n        (state_machine.py docstring). The ROE's on_detect declares the\n        policy (annotate|cooldown|halt); at v2 the engine's behavior never\n        exceeds recording the annotation — pacing/stopping is post-v2.\n        entity_id: the attempt or engagement the annotation concerns.\n        "
        if not isinstance(entity_id, str) or not entity_id.strip():
            raise LedgerRefusal("detection.annotated requires an entity id")
        if not isinstance(detail, str) or not detail.strip():
            raise LedgerRefusal("detection.annotated requires a non-empty detail")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._append_event("detection.annotated", entity_id, {"detail": detail})
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    # -- slice bookkeeping (operational events, no table) ---------------

    def plan_slice(self, slice_id: str, pairs_digest: str) -> None:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._append_event("slice.planned", slice_id, {"pairs_digest": pairs_digest})
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def reconcile_slice(self, slice_id: str, summary: str) -> None:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._append_event("slice.reconciled", slice_id, {"summary": summary})
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    # -- queries ---------------------------------------------------------

    def open_attempts(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM attempts WHERE state IN ('reserved','dispatched')"
        ).fetchall()
        return [dict(r) for r in rows]

    def spent(self, principal: str, action_kind: str | None = None) -> int:
        """Attempts charged to a principal; action_kind scopes to one axis
        (None = all axes). Voided rows never count (proof the attempt never
        left the machine)."""
        if action_kind is None:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE principal=? AND state != 'voided'",
                (principal,),
            )
        else:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE principal=? AND state != 'voided' "
                "AND action_kind=?",
                (principal, action_kind),
            )
        return int(cur.fetchone()[0])

    def has_lockout(self, principal: str) -> bool:
        ''
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE principal=? AND outcome='locked'",
            (principal,),
        )
        return int(cur.fetchone()[0]) > 0

    def counts_by_state(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT state, COUNT(*) AS n FROM attempts GROUP BY state").fetchall()
        return {r["state"]: int(r["n"]) for r in rows}

    # -- fold / verify ----------------------------------------------------

    def fold(self) -> dict[str, dict]:
        """Rebuild attempts rows from attempt.* events (last snapshot wins).

        Version-aware (schema v2): pre-v2 snapshots lack the columns added
        by the v1->v2 migration, so the migration defaults are applied to
        them here — the same values the ALTER put into the materialized
        rows — keeping both sides of verify() like-shaped. History is never
        rewritten: the stored events stay untouched.
        """
        out: dict[str, dict] = {}
        for ev in self.events():
            if ev["kind"] not in schema.EVENT_TABLE_BY_KIND:
                continue
            payload = json.loads(ev["payload"])
            snapshot = payload.get("snapshot")
            if not isinstance(snapshot, dict) or "attempt_id" not in snapshot:
                raise LedgerError(f"event {ev['id']} lacks a snapshot carrying the table PK")
            for key, value in schema.V2_ATTEMPT_DEFAULTS.items():
                snapshot.setdefault(key, value)
            out[snapshot["attempt_id"]] = snapshot
        return out

    def materialized(self) -> dict[str, dict]:
        rows = self.conn.execute("SELECT * FROM attempts").fetchall()
        return {r["attempt_id"]: dict(r) for r in rows}

    def verify(self) -> tuple[bool, str]:
        folded, material = self.fold(), self.materialized()
        if folded == material:
            return True, f"fold == materialized ({len(material)} attempts)"
        only_fold = set(folded) - set(material)
        only_mat = set(material) - set(folded)
        diff = set()
        for k in set(folded) & set(material):
            if folded[k] != material[k]:
                diff.add(k)
        return False, (
            f"fold != materialized: only-in-fold={sorted(only_fold)} "
            f"only-in-table={sorted(only_mat)} differing={sorted(diff)}"
        )

    def resolve_expired(self, ttl: float = budget_mod.DEFAULT_TTL_SECONDS, now: float | None = None) -> dict[str, str]:
        resolutions = budget_mod.resolve_expiry(self.open_attempts(), now=now, ttl=ttl)
        for attempt_id, resolution in resolutions.items():
            if resolution == budget_mod.VOIDED:
                self.void(attempt_id)
            else:
                self.expire_spent(attempt_id)
        return resolutions

    # -- digests (seal substrate) -----------------------------------------

    def events_digest(self) -> str:
        """sha256 over the canonical event log, in row (id) order.

        The payload contributes as the exact stored text (already canonical
        JSON at append time), so the digest binds what the db holds, not a
        re-parse of it.
        """
        h = hashlib.sha256()
        for ev in self.events():
            h.update(_canonical({
                "id": ev["id"], "ts": ev["ts"], "kind": ev["kind"],
                "entity_id": ev["entity_id"], "payload": ev["payload"],
            }))
            h.update(b"\n")
        return h.hexdigest()

    def attempts_digest(self) -> str:
        """sha256 over the materialized attempts rows, sorted by attempt_id."""
        h = hashlib.sha256()
        material = self.materialized()
        for attempt_id in sorted(material):
            h.update(_canonical(material[attempt_id]))
            h.update(b"\n")
        return h.hexdigest()

    def digest(self) -> str:
        """Overall ledger digest: composition of the two substrate digests."""
        h = hashlib.sha256()
        h.update(f"events:{self.events_digest()}\n".encode())
        h.update(f"attempts:{self.attempts_digest()}\n".encode())
        return h.hexdigest()
