"""Campaign sealing: attestation manifest over campaign.db + ROE binding.

A sealed campaign is the babayaga product unit: campaign.db plus
campaign.seal.json written next to it. The
manifest binds the ledger's logical state (event-log digest, materialized
attempts digest, event count, schema version) to the roe_digest recorded by
campaign.init — the authorization the campaign ran under — and carries an
overall manifest_sha256 so the manifest file itself is tamper-evident.

Design choices of this seal:

- Digests are LOGICAL (canonical content), not file bytes, so WAL sidecar
  state is irrelevant to verification and the result is stable across
  processes.
- The seal is a FILE, not an event: schema.EVENT_KINDS is a closed tuple
  (schema v2) and no "campaign.sealed" kind is declared, so sealing never
  appends to the log it attests.
- Sealing is gated on fold == materialized (the ledger's replay invariant)
  and a set roe_digest; both failures are refusals (exit 2), never
  best-guesses. Re-sealing is idempotent: gates re-run and the manifest is
  atomically rewritten.

Schema migrations (v1 -> v2, schema.py docstring): migration appends exactly
ONE campaign.migrated event and ALTERs the attempts rows, so event_count,
events_digest, attempts_digest, and schema_version all change at the first
v2 open — a seal taken over the pre-v2 db DRIFTS. That is deliberate:
verify_seal reports the drift (fail-closed, deterministic — migration
defaults are fixed constants applied on both sides of the fold) and the
operator re-seals to re-attest the migrated campaign. History itself is
never rewritten; the seal is simply re-taken over the extended log. The same
drift-then-re-seal flow applies after `babayaga amend` flips the governing
roe_digest.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .ledger import Ledger
from .roe import canonical

MANIFEST_NAME = "campaign.seal.json"
FORMAT_VERSION = "babayaga-seal/1"


class SealRefusal(Exception):
    """Seal/verify refused (exit 2): the campaign is not in a sealable state."""


class SealError(Exception):
    """Unexpected seal failure (exit 1): corrupt db or manifest internals."""


def _resolve_db(target: str | Path) -> Path:
    """Accept a campaign directory or the campaign.db file itself."""
    p = Path(target)
    db = p / "campaign.db" if p.is_dir() else p
    if not db.is_file():
        raise SealRefusal(f"no campaign.db at {db}")
    return db


def manifest_path(target: str | Path) -> Path:
    return _resolve_db(target).parent / MANIFEST_NAME


def _meta_value(led: Ledger, key: str) -> str | None:
    row = led.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def _schema_version(led: Ledger) -> int:
    raw = _meta_value(led, "schema_version")
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise SealError(f"meta.schema_version unreadable: {raw!r}") from exc


def _state(led: Ledger) -> dict:
    """The attested logical state: what the manifest binds and verify recomputes."""
    return {
        "schema_version": _schema_version(led),
        "roe_digest": _meta_value(led, "roe_digest"),
        "event_count": led.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "events_digest": led.events_digest(),
        "attempts_digest": led.attempts_digest(),
    }


def _with_self_digest(manifest: dict) -> dict:
    """manifest_sha256 over the canonical form of every other field."""
    body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    manifest["manifest_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
    return manifest


def seal_campaign(target: str | Path) -> dict:
    """Seal one campaign. Returns the manifest; raises SealRefusal on a gate
    failure (fold broken, roe_digest unset) and SealError on corruption."""
    db = _resolve_db(target)
    led = Ledger(db)
    try:
        ok, detail = led.verify()
        if not ok:
            raise SealRefusal(f"ledger fold broken — {detail}")
        roe_digest = _meta_value(led, "roe_digest")
        if not roe_digest:
            raise SealRefusal(
                "roe_digest unset: campaign was never initialized against a "
                "validated ROE — nothing to attest")
        manifest = {
            "format_version": FORMAT_VERSION,
            "campaign": db.parent.name,
            "schema_version": _schema_version(led),
            "roe_digest": roe_digest,
            "event_count": led.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "events_digest": led.events_digest(),
            "attempts_digest": led.attempts_digest(),
            "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "engine_version": __version__,
        }
        _with_self_digest(manifest)
    finally:
        led.close()

    # Atomic manifest write: temp file in the same directory, then rename.
    fd, tmp = tempfile.mkstemp(dir=str(db.parent), prefix=".seal-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(canonical(manifest) + b"\n")
        os.replace(tmp, db.parent / MANIFEST_NAME)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return manifest


def verify_seal(target: str | Path) -> tuple[bool, str]:
    """Recompute the attested state and compare it against the manifest.

    Every negative is a refusal (exit 2 at the CLI): a seal that cannot be
    reproduced says nothing about the db, and fail-closed means no
    best-guesses. Unexpected db corruption raises (exit 1) instead.
    """
    try:
        db = _resolve_db(target)
    except SealRefusal as exc:
        return False, str(exc)
    path = db.parent / MANIFEST_NAME
    if not path.is_file():
        return False, f"never sealed (no {MANIFEST_NAME})"
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"manifest unreadable: {exc}"
    if not isinstance(m, dict):
        return False, "manifest is not a JSON object"
    if m.get("format_version") != FORMAT_VERSION:
        return False, f"unknown format_version {m.get('format_version')!r}"
    sealed_digest = m.get("manifest_sha256")
    body = {k: v for k, v in m.items() if k != "manifest_sha256"}
    if not isinstance(sealed_digest, str) or hashlib.sha256(canonical(body)).hexdigest() != sealed_digest:
        return False, "manifest_sha256 mismatch: the manifest file itself drifted after sealing"

    led = Ledger(db)
    try:
        current = _state(led)
    finally:
        led.close()
    drift = [k for k in current if m.get(k) != current[k]]
    if drift:
        return False, (f"sealed state drifted: {', '.join(drift)} — campaign.db "
                       f"changed after sealing (re-seal to re-attest)")
    return True, (f"manifest match (campaign {m.get('campaign')}, "
                  f"sealed {m.get('sealed_at')}, engine {m.get('engine_version')})")
