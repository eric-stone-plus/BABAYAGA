'`babayaga` console script: the ops-safe surface the plugin shells out to.'

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import EXIT_ERROR, EXIT_OK, EXIT_REFUSAL, LAB_ONLY, __version__
from . import roe as roe_mod


def _repo_root() -> Path:
    # engine/babayaga/cli.py -> engine/babayaga -> engine -> repo root
    return Path(__file__).resolve().parents[2]


def home_dir() -> Path:
    env = os.environ.get("BABAYAGA_HOME")
    return Path(env).expanduser() if env else _repo_root() / "tasks"


def _emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for key, value in payload.items():
            print(f"{key}: {value}")


# ---------------------------------------------------------------- doctor

def cmd_doctor(args: argparse.Namespace) -> int:
    from . import config as config_mod
    from . import manifests as manifests_mod

    checks: list[dict] = []

    py = sys.version_info
    checks.append({"check": "python", "pass": py >= (3, 11),
                   "detail": f"{py.major}.{py.minor}.{py.micro} (need >=3.11)"})

    home = home_dir()
    try:
        home.mkdir(parents=True, exist_ok=True)
        probe = home / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks.append({"check": "babayaga_home", "pass": True, "detail": str(home)})
    except OSError as exc:
        checks.append({"check": "babayaga_home", "pass": False, "detail": f"{home}: {exc}"})

    # Tools anchoring (PC K3): hydra must NOT resolve on the session PATH;
    # the anchored tools dir (config.tools_dir: BABAYAGA_TOOLS env >
    # babayaga.toml > <repo>/tools) is the only legal resolver. Fail-closed.
    hydra_on_path = shutil.which("hydra")
    checks.append({
        "check": "hydra_off_session_path",
        "pass": hydra_on_path is None,
        "detail": (f"hydra resolves on PATH at {hydra_on_path} — relocate it under "
                   f"the tools anchor (one-time operator action)")
        if hydra_on_path else "not on PATH",
    })

    hydra_bin: Path | None = None
    try:
        tools = config_mod.tools_dir()
        candidate = config_mod.instrument_path("hydra")
        if candidate.is_file() and os.access(candidate, os.X_OK):
            hydra_bin = candidate
            checks.append({"check": "hydra_anchored", "pass": True,
                           "detail": f"{candidate} (tools_dir: {tools})"})
        else:
            checks.append({"check": "hydra_anchored", "pass": False,
                           "detail": f"no executable hydra at {candidate} — anchor it "
                                     f"(symlink into the build tree); doctor fails "
                                     f"closed until then (the internal design notes)"})
    except config_mod.ConfigError as exc:
        checks.append({"check": "hydra_anchored", "pass": False, "detail": str(exc)})

    # Manifest version-range check against the real binary's probe banner
    # (B18): out-of-range or unparseable output is a refusal, never a guess.
    if hydra_bin is not None:
        try:
            manifest = manifests_mod.load("hydra")
            proc = subprocess.run(
                [str(hydra_bin), *manifest["version"]["probe_argv"]],
                capture_output=True, text=True, timeout=15)
            discovered = manifests_mod.extract_version(
                manifest, proc.stdout + proc.stderr)
            ok, detail = manifests_mod.check_version(manifest, discovered)
            checks.append({"check": "hydra_version", "pass": ok, "detail": detail})
        except (manifests_mod.ManifestError, OSError, subprocess.SubprocessError) as exc:
            checks.append({"check": "hydra_version", "pass": False, "detail": str(exc)})

    # Opportunistic capability probes (info only, never load-bearing):
    caps: dict[str, str] = {}
    try:
        fd = os.open(tempfile.gettempdir(), os.O_RDWR | os.O_TMPFILE, 0o600)
        os.close(fd)
        caps["o_tmpfile"] = "supported (primary list transport)"
    except OSError as exc:
        caps["o_tmpfile"] = f"unsupported ({exc}) — 0600+shred fallback"
    if hydra_bin is not None:
        caps["hydra_o_jsonv1"] = probe_hydra_output(str(hydra_bin))
    checks.append({"check": "capabilities", "pass": True, "detail": caps})

    payload = {"version": __version__, "lab_only": LAB_ONLY,
               "status": "ok" if all(c["pass"] for c in checks) else "refusal",
               "checks": checks}
    _emit(payload, args.json)
    return EXIT_OK if payload["status"] == "ok" else EXIT_REFUSAL


def probe_hydra_output(hydra_bin: str) -> str:
    """The anchored hydra build has a measured `-o` EINVAL defect (a local
    hardening patch opens O_WRONLY|O_APPEND then fdopen "a+"). Streams stay
    the primary parser; this probe decides whether jsonv1 is opportunistic."""
    with tempfile.TemporaryDirectory(prefix="babayaga-doctor-") as td:
        out = Path(td) / "out.json"
        try:
            proc = subprocess.run(
                [hydra_bin, "-l", "probe", "-p", "probe", "-o", str(out),
                 "-b", "jsonv1", "127.0.0.1", "-s", "1", "http-get", "/"],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            return "probe-timeout"
        if "outputfile" in (proc.stdout + proc.stderr).lower() and "error" in (proc.stdout + proc.stderr).lower():
            return "broken (-o EINVAL on this build): stream parsing primary"
        return "ok: jsonv1 opportunistic"


# ---------------------------------------------------------------- status

def cmd_status(args: argparse.Namespace) -> int:
    from .ledger import Ledger

    home = home_dir()
    campaigns = []
    if home.is_dir():
        for db in sorted(home.glob("*/campaign.db")):
            entry: dict = {"campaign": db.parent.name}
            try:
                led = Ledger(db)
                entry["roe_digest"] = (led.conn.execute(
                    "SELECT value FROM meta WHERE key='roe_digest'").fetchone() or ["-"])[0]
                entry["attempts"] = led.counts_by_state()
                ok, detail = led.verify()
                entry["fold_eq_materialized"] = ok
                entry["ledger_digest"] = led.digest()
                led.close()
            except Exception as exc:  # status is read-only ops: report, don't crash
                entry["error"] = str(exc)
            campaigns.append(entry)
    _emit({"home": str(home), "campaigns": campaigns}, args.json)
    return EXIT_OK


# -------------------------------------------------------------- roe-check

def cmd_roe_check(args: argparse.Namespace) -> int:
    try:
        obj = roe_mod.load(args.roe_file)
    except roe_mod.RoeError as exc:
        _emit({"valid": False, "error": str(exc)}, args.json)
        return EXIT_REFUSAL
    window_ok, window_detail = roe_mod.check_window(obj)
    payload = {
        "valid": True,
        "engagement_id": obj["engagement_id"],
        "roe_digest": roe_mod.digest(obj),
        "lab_only": LAB_ONLY,
        "targets": len(obj["targets"]),
        "principals": len(obj["principals"]),
        "budget_per_principal_per_run": roe_mod.per_principal_budget(obj),
        "lockout_observed_threshold": obj["lockout"]["observed_threshold"],
        "window": window_detail,
    }
    _emit(payload, args.json)
    return EXIT_OK if window_ok else EXIT_REFUSAL


# ------------------------------------------------------------------ seal

def cmd_seal(args: argparse.Namespace) -> int:
    from . import seal as seal_mod

    if args.verify:
        ok, detail = seal_mod.verify_seal(args.target)
        _emit({"verify": ok, "detail": detail}, args.json)
        return EXIT_OK if ok else EXIT_REFUSAL
    try:
        manifest = seal_mod.seal_campaign(args.target)
    except seal_mod.SealRefusal as exc:
        _emit({"refusal": str(exc)}, args.json)
        return EXIT_REFUSAL
    _emit({**manifest, "manifest_path": str(seal_mod.manifest_path(args.target))}, args.json)
    return EXIT_OK


# -------------------------------------------------------------- campaigns

def _resolve_campaign_db(arg: str) -> Path:
    """Campaign selector shared by amend/export-access: an existing path
    (campaign dir or campaign.db), else a campaign name under BABAYAGA_HOME."""
    p = Path(arg).expanduser()
    if not p.exists():
        p = home_dir() / arg
    db = p / "campaign.db" if p.is_dir() else p
    if not db.is_file():
        from .ledger import LedgerRefusal
        raise LedgerRefusal(f"no campaign.db for {arg!r} (looked at {db})")
    return db


# ----------------------------------------------------------------- amend

def cmd_amend(args: argparse.Namespace) -> int:
    from .ledger import Ledger, LedgerRefusal

    try:
        db = _resolve_campaign_db(args.target)
        obj = roe_mod.load(args.roe)  # validates; RoeError -> exit 2 in main
        new_digest = roe_mod.digest(obj)
        led = Ledger(db)
        try:
            row = led.conn.execute(
                "SELECT value FROM meta WHERE key='roe_digest'").fetchone()
            if row is None:
                raise LedgerRefusal(
                    f"campaign {args.target!r} was never initialized — nothing to amend")
            led.amend_campaign(row[0], obj)
        finally:
            led.close()
    except LedgerRefusal as exc:
        _emit({"refusal": str(exc)}, args.json)
        return EXIT_REFUSAL
    _emit({
        "campaign": db.parent.name,
        "amended": True,
        "old_roe_digest": row[0],
        "new_roe_digest": new_digest,
        "note": ("governing digest flipped after the draft's fresh attestation "
                 "validated — the prior seal now drifts; re-seal with "
                 "`babayaga seal` to re-attest"),
    }, args.json)
    return EXIT_OK


# ------------------------------------------------------------ export-access

def cmd_export_access(args: argparse.Namespace) -> int:
    from . import export as export_mod
    from .ledger import LedgerRefusal

    try:
        db = _resolve_campaign_db(args.campaign)
        payload = export_mod.export_access(db)
    except (export_mod.ExportRefusal, LedgerRefusal) as exc:
        _emit({"refusal": str(exc)}, args.json)
        return EXIT_REFUSAL
    document = roe_mod.canonical(payload) + b"\n"
    if args.out:
        Path(args.out).write_bytes(document)
        _emit({"exported": args.out, "records": len(payload["records"]),
               "export_sha256": payload["export_sha256"]}, args.json)
    else:
        sys.stdout.write(document.decode("utf-8"))
    return EXIT_OK


# ------------------------------------------------------------------ run

def cmd_run(args: argparse.Namespace) -> int:
    if not args.lab:
        _emit({"refusal": "v0 is LAB-ONLY (the internal design notes): `babayaga run` "
                          "requires --lab; engaging a non-lab target is not "
                          "implemented and never defaultable"}, args.json)
        return EXIT_REFUSAL
    from . import config as config_mod
    from . import manifests as manifests_mod
    from . import run as run_mod
    from . import seal as seal_mod
    from .ledger import LedgerRefusal

    try:
        payload = run_mod.run_lab(roe_path=args.roe, home=home_dir())
    except (run_mod.RunRefusal, roe_mod.RoeError, config_mod.ConfigError,
            manifests_mod.ManifestError, seal_mod.SealRefusal,
            LedgerRefusal) as exc:
        _emit({"refusal": str(exc)}, args.json)
        return EXIT_REFUSAL
    _emit(payload, args.json)
    if not payload["verify"]["ok"]:
        return EXIT_ERROR
    return EXIT_OK if payload["run_status"] == "completed" else EXIT_REFUSAL


# --------------------------------------------------------------- adapter

def _boundary_exit(code: int) -> int:
    """Map the adapter's in-frame exit granularity (0/2/3/124/130) onto
    Boundary A's process contract: 0 ok, 2 refusal/protocol error, 1 failure."""
    return EXIT_OK if code == 0 else EXIT_REFUSAL if code == 2 else EXIT_ERROR


def cmd_adapter(args: argparse.Namespace) -> int:
    """babayaga/1 framed host protocol: one request frame, or the stdio loop."""
    from . import adapter as adapter_mod

    if getattr(args, "stdio", False):
        return _boundary_exit(adapter_mod.serve_lines(
            disconnect_cancels=args.disconnect_cancels))
    if args.disconnect_cancels:
        _emit({"refusal": "--disconnect-cancels requires --stdio"}, True)
        return EXIT_REFUSAL
    result = adapter_mod.handle_frame(args.request)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return _boundary_exit(int(result.get("exit_code") or 0))


# ------------------------------------------------------------------ main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="babayaga", description=__doc__)
    parser.add_argument("--version", action="version", version=f"babayaga {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, fn in (("doctor", cmd_doctor), ("status", cmd_status)):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true")
        p.set_defaults(fn=fn)

    p = sub.add_parser("roe-check", help="validate a ROE file and print its digest")
    p.add_argument("roe_file")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_roe_check)

    p = sub.add_parser("seal", help="seal campaign.db into a campaign.seal.json attestation manifest")
    p.add_argument("target", help="campaign directory or campaign.db path")
    p.add_argument("--verify", action="store_true",
                   help="recompute and compare against the manifest instead of sealing")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("amend", help="governed ROE change: append campaign.amended chaining to "
                                     "a re-attested draft (a recorded follow-up)")
    p.add_argument("target", help="campaign name under BABAYAGA_HOME, campaign dir, or campaign.db path")
    p.add_argument("--roe", required=True, metavar="FILE",
                   help="the amended ROE draft; the digest flip is conditional on its "
                        "fresh operator attestation (validated here, never engine-side)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_amend)

    p = sub.add_parser("export-access",
                       help="B16 bridge: sealed access JSON of valid attempts, shaped for "
                            "the reconnaissance engine counterpart's access/grants_access "
                            "ingest (stdout or --out FILE)")
    p.add_argument("campaign", help="campaign name under BABAYAGA_HOME, campaign dir, or campaign.db path")
    p.add_argument("--out", metavar="FILE",
                   help="write the export document to FILE instead of stdout")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_export_access)

    p = sub.add_parser("run", help="the attempt runner (never a plugin tool, the internal design notes)")
    p.add_argument("--lab", action="store_true",
                   help="REQUIRED at v0: engage the loopback lab fixture "
                        "(engine/lab/http_get_lab.py, spawned as a subprocess)")
    p.add_argument("--roe", metavar="FILE",
                   help="ROE file (one target, one port; the fixture binds that "
                        "port). Default: engine/babayaga/defaults/roe.example.json "
                        "adapted to the fixture's ephemeral port")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("adapter", help="framed stdio host protocol (babayaga/1): "
                                       "ops-safe reads only; run/amend are refused at "
                                       "the protocol layer")
    transport = p.add_mutually_exclusive_group(required=True)
    transport.add_argument("--request", metavar="JSON",
                           help="dispatch one request frame and exit")
    transport.add_argument("--stdio", action="store_true",
                           help="serve newline-delimited JSON frames on stdin/stdout")
    p.add_argument("--disconnect-cancels", action="store_true",
                   help="with --stdio: stdin closure cancels in-flight engine work")
    p.set_defaults(fn=cmd_adapter)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.fn(args))
    except roe_mod.RoeError as exc:
        _emit({"refusal": str(exc)}, getattr(args, "json", False))
        return EXIT_REFUSAL
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        _emit({"error": f"{type(exc).__name__}: {exc}"}, getattr(args, "json", False))
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
