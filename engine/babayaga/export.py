'For every attempt reconciled `valid` the export carries one record shaped\nfor that ingest vocabulary:\n\n    access:         the entity kind\'s data fields — principal, level\n                    ("user": a validated credential grants user-level access),\n                    valid — plus target addressing (target_host/target_port)\n                    for the counterpart\'s ingest to resolve its own asset_id;\n    grants_access:  the edge rel\'s provenance — source_attempt_id,\n                    material_digest, the governing roe_digest (the attempt\'s\n                    own stamp; migrated pre-v2 rows fall back to the\n                    campaign\'s meta binding, never a fabrication), and the\n                    instrument identity (NULL when unrecorded — errata 18).\n\nHard rules:'

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import roe as roe_mod
from . import seal as seal_mod
from .ledger import Ledger

FORMAT_VERSION = "babayaga-access-export/1"


class ExportRefusal(Exception):
    """Export refused (exit 2): the campaign is not in an exportable state."""


def export_access(target: str | Path) -> dict:
    """Build the sealed access-export payload for one campaign.

    Raises ExportRefusal on a gate failure (missing db, broken fold, unset
    roe_digest, absent/drifted seal); SealError/LedgerError bubble as exit 1.
    """
    try:
        db = seal_mod._resolve_db(target)
    except seal_mod.SealRefusal as exc:
        raise ExportRefusal(str(exc)) from exc

    ok, detail = seal_mod.verify_seal(db)
    if not ok:
        raise ExportRefusal(
            f"campaign seal gate: {detail} — the export is sealed JSON over "
            "attested state; (re-)seal with `babayaga seal` first")

    led = Ledger(db)
    try:
        ok, detail = led.verify()
        if not ok:
            raise ExportRefusal(f"ledger fold broken — {detail}")
        campaign_digest = led._meta("roe_digest")
        if not campaign_digest:
            raise ExportRefusal(
                "roe_digest unset: campaign was never initialized against a "
                "validated ROE — nothing governs these attempts")
        engagement = led.conn.execute(
            "SELECT entity_id FROM events WHERE kind='campaign.init' "
            "ORDER BY id LIMIT 1").fetchone()
        schema_version = led._meta("schema_version") or "0"
        rows = led.conn.execute(
            "SELECT * FROM attempts WHERE state='reconciled' AND outcome='valid' "
            "ORDER BY resolved_ts, attempt_id").fetchall()
        records = []
        for row in rows:
            governing = row["roe_digest"] or campaign_digest
            records.append({
                "access": {
                    "principal": row["principal"],
                    "level": "user",
                    "valid": True,
                    "target_host": row["target_host"],
                    "target_port": row["target_port"],
                },
                "grants_access": {
                    "source_attempt_id": row["attempt_id"],
                    "material_digest": row["material_digest"],
                    "roe_digest": governing,
                    "instrument": row["instrument"],
                    "instrument_version": row["instrument_version"],
                },
            })
    finally:
        led.close()

    manifest = json.loads(seal_mod.manifest_path(db).read_text(encoding="utf-8"))
    payload = {
        "format_version": FORMAT_VERSION,
        "campaign": db.parent.name,
        "engagement_id": engagement[0] if engagement else None,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engine_version": __version__,
        "schema_version": int(schema_version),
        "roe_digest": campaign_digest,
        "campaign_seal": {"manifest_sha256": manifest["manifest_sha256"]},
        "records": records,
    }
    body = {k: v for k, v in payload.items() if k != "export_sha256"}
    payload["export_sha256"] = hashlib.sha256(roe_mod.canonical(body)).hexdigest()
    return payload
