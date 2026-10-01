'    ROE load/validate -> window gate -> target gate (LAB_ONLY loopback) ->\n    rule selection (spray pack, B10 throttle) -> budget slice plan (explicit\n    pairs) -> ledger init/reserve/dispatch (evidence-first) -> executor\n    spawn (O_TMPFILE pair transport, fresh cwd, wall-clock kill) -> stream\n    parse -> reconcile -> seal + verify -> scrub captures.\n\nv0 engages exactly ONE slice = ONE hydra invocation carrying every planned\npair (password-outer across the lab candidate list), so the rules\'\nslice_cadence_seconds (spacing BETWEEN invocations) is never violated; a\ncadenced multi-invocation scheduler is post-v0.\n\nLab-fixture lifecycle\n---------------------\nThe fixture (engine/lab/http_get_lab.py) runs as a SUBPROCESS, never\nin-process: a fresh process per run means fresh lockout counters, which is\nwhat makes the invalid-reconcile claim below sound for the lab. The runner\nspawns `sys.executable lab/http_get_lab.py <port>` (port 0 = ephemeral when\nno --roe pins one), reads the fixture\'s stdout readiness line\n("127.0.0.1 <port>") — printed only after the listen socket is live — with\na bounded select, and terminate()/kill()s the child in a finally. Fixture\nstderr lands in run_dir/lab.stderr (request lines only, no credentials) and\nis scrubbed with the instrument captures.\n\nROE source: `--roe FILE` (must declare exactly one target with exactly one\nport; the fixture binds that port) or the default — the shipped example ROE\nadapted to the fixture\'s ephemeral port. NOTE: the adapted digest changes\nwith the port, so default-mode re-runs against an existing campaign dir hit\nthe re-init guard below by design; `--roe` with a fixed port gives a stable\ndigest and a RESUMED campaign (prior spend counts toward the budget).\n\nReconciliation policy (the conservative core)\n---------------------------------------------\nOnly stream-proven outcomes are reconciled; everything else expires:\n\nIn particular, a run with a find reconciles the found pair "valid" and\nexpires the rest: hydra -f stops the target after the first find, so the\nwire state of the remaining planned pairs is genuinely unknown — claiming\n"invalid" would be a guess, and guessing is worse than spending budget.\n\nExit contract (via cli): 0 completed pipeline (whatever the credential\noutcome), 2 refusal — gates, planning, or a refused reconciliation — with\nthe campaign still sealed, 1 unexpected failure (fixture bind, spawn,\npost-seal verify mismatch).\n'

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import select
import subprocess
import sys
import uuid
from collections.abc import Collection
from pathlib import Path

from . import budget, config, executor, manifests, rulecheck
from . import roe as roe_mod
from . import seal as seal_mod
from .ledger import Ledger
from .parsers import hydra_stdout

SERVICE = "http-get"
LAB_PATH = "/"
LAB_READY_TIMEOUT_S = 10.0
LAB_STOP_TIMEOUT_S = 3.0
PROBE_TIMEOUT_S = 15.0


class RunRefusal(Exception):
    """Run-time refusal (exit 2): gate, planning, or reconciliation refused."""


def _engine_root() -> Path:
    # engine/babayaga/run.py -> engine/babayaga -> engine
    return Path(__file__).resolve().parents[1]


def _owner_only(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


# ---------------------------------------------------------------- fixture

@contextlib.contextmanager
def _lab_fixture(port: int, run_dir: Path):
    """Spawn the http-get lab fixture; yield (host, port) once it is ready.

    Subprocess-per-run is load-bearing: it resets the fixture's lockout
    counters, which (with budget < observed_threshold) makes "invalid"
    provable in lab mode — see the module docstring.
    """
    script = _engine_root() / "lab" / "http_get_lab.py"
    err_path = run_dir / "lab.stderr"
    with open(err_path, "wb", opener=_owner_only) as err_f:
        proc = subprocess.Popen(
            [sys.executable, str(script), str(port)],
            stdout=subprocess.PIPE, stderr=err_f, stdin=subprocess.DEVNULL,
            text=True,
        )
        try:
            ready, _, _ = select.select([proc.stdout], [], [], LAB_READY_TIMEOUT_S)
            line = proc.stdout.readline().strip() if ready else ""
            host, _, port_s = line.partition(" ")
            if not port_s.isdigit():
                tail = ""
                try:
                    tail = err_path.read_text(encoding="utf-8", errors="replace")[-400:]
                except OSError:
                    pass
                raise RuntimeError(
                    f"lab fixture did not report a bound port "
                    f"(exit {proc.poll()}, readiness line {line!r}); "
                    f"lab.stderr tail: {tail!r}")
            yield host, int(port_s)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=LAB_STOP_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()


# ------------------------------------------------------------------- gates

def _load_roe(roe_path: str | None):
    """Return (roe_obj, declared_host, declared_port | None)."""
    if roe_path is not None:
        obj = roe_mod.load(roe_path)  # RoeError -> exit 2 at the CLI
        targets = obj["targets"]
        if len(targets) != 1 or len(targets[0]["ports"]) != 1:
            raise RunRefusal(
                "v0 lab mode engages exactly one declared (host, port): the "
                "ROE must carry one target with one port")
        return obj, targets[0]["host"], targets[0]["ports"][0]
    src = Path(__file__).parent / "defaults" / "roe.example.json"
    obj = json.loads(src.read_text(encoding="utf-8"))
    return obj, None, None  # port adapted to the fixture below


def _select_rule(rules_dir: Path, budget_per_run: int) -> dict:
    """The tightest spray-pack rule covering the ROE budget; refuse if none."""
    report = rulecheck.check_corpus(rules_dir)
    if not report.ok:
        raise RunRefusal(
            f"rule corpus refuses: {json.dumps(report.to_dict(), sort_keys=True)}")
    covering = []
    for path in sorted(rules_dir.rglob("*.json")):
        rule = json.loads(path.read_text(encoding="utf-8"))
        if rule.get("pack") != "spray" or rule.get("match", {}).get("service") != SERVICE:
            continue
        if rule["budget"]["per_principal_per_run_max"] >= budget_per_run:
            covering.append(rule)
    if not covering:
        raise RunRefusal(
            f"no spray rule covers service {SERVICE!r} at per-principal "
            f"budget {budget_per_run} — a run no rule covers is refused, "
            "never improvised")
    return min(covering, key=lambda r: (
        r["budget"]["per_principal_per_run_max"],
        r["throttle"]["slice_cadence_seconds"], r["id"]))


def _anchored_hydra() -> tuple[Path, str]:
    """The anchored hydra binary + its manifest-checked version. Fail-closed."""
    path = config.instrument_path("hydra")
    if not (path.is_file() and os.access(path, os.X_OK)):
        raise RunRefusal(
            f"hydra not anchored at {path} (tools_dir: {config.tools_dir()}) — "
            "the anchor is the only legal resolver (the internal design notes); see doctor")
    manifest = manifests.load("hydra")  # ManifestError -> exit 2
    proc = subprocess.run(
        [str(path), *manifest["version"]["probe_argv"]],
        capture_output=True, text=True, timeout=PROBE_TIMEOUT_S)
    discovered = manifests.extract_version(manifest, proc.stdout + proc.stderr)
    ok, detail = manifests.check_version(manifest, discovered)
    if not ok:
        raise RunRefusal(detail)
    return path, discovered


def _lab_passwords() -> list[str]:
    src = _engine_root() / "lab" / "demo_passwords.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    if (not isinstance(data, list) or not data
            or not all(isinstance(p, str) and p for p in data)):
        raise RunRefusal(f"lab candidate list {src} must be a non-empty list of strings")
    return data


def _plan(principals: list[str], passwords: list[str], spent: dict[str, int],
          budget_per_run: int, locked: Collection[str] = ()) -> list[tuple[str, str]]:
    ''
    pairs: list[tuple[str, str]] = []
    projected = dict(spent)
    for password in passwords:
        slice_pairs = budget.plan_slice(principals, password, projected,
                                        budget_per_run, locked=locked)
        if len(slice_pairs) != len(principals):
            blocked = sorted(p for p in principals if p in locked)
            short = sorted(p for p in principals if p not in locked
                           and budget.remaining(p, projected, budget_per_run) <= 0)
            raise RunRefusal(
                f"budget refusal: per-principal budget {budget_per_run} does "
                f"not cover the planned {len(passwords)} pair(s) per principal "
                f"(exhausted: {short or 'none'}; locked-out: {blocked or 'none'}) "
                "— a shrunk slice is never planned (budget-or-refuse)")
        pairs.extend(slice_pairs)
        for principal in principals:
            projected[principal] = projected.get(principal, 0) + 1
    return pairs


# ------------------------------------------------------------------ scrub

def _scrub_file(path: Path) -> None:
    """Zero-overwrite + unlink (executor._pair_list_path fallback shred)."""
    try:
        size = path.stat().st_size
        fd = os.open(path, os.O_WRONLY)
        try:
            view = memoryview(b"\x00" * size)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        path.unlink()
    except OSError:
        pass


def _scrub_run_dir(run_dir: Path) -> None:
    ''
    if not run_dir.is_dir():
        return
    for entry in run_dir.iterdir():
        if entry.is_file():
            _scrub_file(entry)
    try:
        run_dir.rmdir()
    except OSError:
        pass


# -------------------------------------------------------------------- run

def run_lab(*, roe_path: str | None, home: Path) -> dict:
    """Drive the full pipeline (module docstring); return the summary payload.

    Raises RunRefusal / roe.RoeError / config.ConfigError /
    manifests.ManifestError / seal.SealRefusal (all exit 2); anything else
    bubbles to the CLI boundary as exit 1.
    """
    home = Path(home)
    obj, declared_host, declared_port = _load_roe(roe_path)
    engagement_id = obj["engagement_id"]
    if "/" in engagement_id or "\x00" in engagement_id:
        raise RunRefusal(f"engagement_id {engagement_id!r} is not path-safe")

    # -- gates that need no fixture -------------------------------------
    window_ok, window_detail = roe_mod.check_window(obj)
    if not window_ok:
        raise RunRefusal(f"window gate: {window_detail}")
    if declared_host is not None:
        target_ok, target_detail = roe_mod.check_target(obj, declared_host, declared_port)
        if not target_ok:
            raise RunRefusal(f"target gate: {target_detail}")

    budget_per_run = roe_mod.per_principal_budget(obj)
    principals = list(obj["principals"])
    passwords = _lab_passwords()
    rule = _select_rule(_engine_root() / "rules", budget_per_run)
    hydra_bin, hydra_version = _anchored_hydra()

    campaign_dir = home / engagement_id
    campaign_dir.mkdir(parents=True, exist_ok=True)
    run_dir = campaign_dir / "runs" / uuid.uuid4().hex
    run_dir.mkdir(parents=True, exist_ok=True)
    slice_id = run_dir.name

    with _lab_fixture(declared_port or 0, run_dir) as (host, port):
        try:
            if declared_host is None:
                # Default ROE: adapt the example to the fixture's ephemeral
                # port, then run the remaining gates against the adapted object.
                obj["targets"][0]["ports"] = [port]
                errors = roe_mod.validate(obj)
                if errors:
                    raise RuntimeError("adapted example ROE invalid: " + "; ".join(errors))
                declared_host = obj["targets"][0]["host"]
                target_ok, target_detail = roe_mod.check_target(obj, declared_host, port)
                if not target_ok:
                    raise RunRefusal(f"target gate: {target_detail}")
            roe_digest = roe_mod.digest(obj)

            led = Ledger(campaign_dir / "campaign.db")
            try:
                # -- re-init guard (friendly pre-check; the ledger itself
                # is fail-closed since schema v2 — module docstring)
                row = led.conn.execute(
                    "SELECT value FROM meta WHERE key='roe_digest'").fetchone()
                if row is not None and row[0] != roe_digest:
                    raise RunRefusal(
                        f"campaign {engagement_id!r} was initialized under a "
                        f"different roe_digest ({row[0][:12]}… != "
                        f"{roe_digest[:12]}…) — refusing to re-init over it; "
                        "a governed ROE change is `babayaga amend`")

                spent = {p: led.spent(p, action_kind="guess") for p in principals}
                locked = {p for p in principals if led.has_lockout(p)}
                pairs = _plan(principals, passwords, spent, budget_per_run,
                              locked=locked)
                pairs_digest = hashlib.sha256(
                    ("\n".join(sorted(budget.material_digest(u, p) for u, p in pairs)))
                    .encode("utf-8")).hexdigest()

                # -- ledger: init, slice plan, reserve, dispatch (evidence-first)
                if row is None:
                    led.init_campaign(roe_digest, engagement_id)
                led.plan_slice(slice_id, pairs_digest)
                planned = []  # (principal, password, attempt_id, material_digest)
                for principal, password in pairs:
                    digest = budget.material_digest(principal, password)
                    attempt_id = led.reserve(
                        slice_id=slice_id, principal=principal, host=declared_host,
                        port=port, material_digest=digest,
                        instrument="hydra", instrument_version=hydra_version)
                    planned.append((principal, password, attempt_id, digest))
                for _, _, attempt_id, _ in planned:
                    led.dispatch(attempt_id)

                argv = [
                    str(hydra_bin), "-C", executor.PAIR_LIST_TOKEN, "-K", "-I", "-f",
                    *rule["throttle"]["instrument_flags"],
                    "-s", str(port), declared_host, SERVICE, LAB_PATH,
                ]
                problems = budget.check_flags(argv)
                if problems:
                    raise RunRefusal("instrument argv violates flag policy: "
                                     + "; ".join(problems))

                return _execute_and_reconcile(
                    led=led, argv=argv, pairs=[(u, p) for u, p, _, _ in planned],
                    planned=planned, run_dir=run_dir, campaign_dir=campaign_dir,
                    slice_id=slice_id, obj=obj, roe_digest=roe_digest, rule=rule,
                    hydra_bin=hydra_bin, hydra_version=hydra_version,
                    host=declared_host, port=port, budget_per_run=budget_per_run)
            finally:
                led.close()
        finally:
            _scrub_run_dir(run_dir)
            try:
                run_dir.parent.rmdir()  # runs/ itself, once empty
            except OSError:
                pass


def _execute_and_reconcile(*, led, argv, pairs, planned, run_dir, campaign_dir,
                           slice_id, obj, roe_digest, rule, hydra_bin,
                           hydra_version, host, port, budget_per_run) -> dict:
    exec_error = None
    result = None
    try:
        result = executor.run(argv, run_dir=run_dir,
                              credential_pairs=pairs)
    except executor.ExecutorError as exc:
        exec_error = exc

    counts = {"valid": 0, "invalid": 0, "locked": 0}
    expired: dict[str, str] = {}
    parse_info: dict = {}
    stream_digests: dict[str, str] = {}
    run_status = "reconcile_refused"
    refusal_reasons: list[str] = []

    parsed = None
    if result is not None:
        for name, path in result.stream_paths.items():
            stream_digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        parsed = hydra_stdout.parse_streams(
            result.stream_paths["stdout"].read_text(encoding="utf-8", errors="replace"),
            result.stream_paths["stderr"].read_text(encoding="utf-8", errors="replace"))
        s = parsed.summary
        parse_info = {
            "status": s.status, "refusal_reasons": list(s.refusal_reasons),
            "announced_tries": s.announced_tries, "attempts_seen": s.attempts_seen,
            "found_principals": list(s.found_principals),
            "valid_passwords_found": s.valid_passwords_found,
        }

    if exec_error is not None:
        refusal_reasons.append(f"instrument never started: {exec_error}")
    elif result.killed or result.output_capped:
        refusal_reasons.append(
            f"executor ended the run (killed={result.killed} "
            f"timed_out={result.timed_out} output_capped={result.output_capped}): "
            "partial evidence never reconciles")
    elif parsed is not None and parsed.summary.status == "ok":
        s = parsed.summary
        by_digest = {dg: aid for _, _, aid, dg in planned}
        unmatched = [dg for dg in s.found_digests if dg not in by_digest]
        locked_signals = [r for r in parsed.records
                          if r.line_class == "signal_lockout"]
        if unmatched:
            refusal_reasons.append(
                f"{len(unmatched)} found digest(es) match no planned pair: "
                "contradictory evidence — nothing reconciled")
        elif s.valid_passwords_found:
            # -f stopped the target after the find: non-found pairs are
            # dispatched-but-unproven -> expired_spent, never "invalid".
            for dg in s.found_digests:
                led.reconcile(by_digest[dg], "valid")
                counts["valid"] += 1
            run_status = "completed"
        elif locked_signals:
            for _, _, aid, _ in planned:
                led.reconcile(aid, "locked")
                counts["locked"] += 1
            run_status = "completed"
        elif s.announced_tries == len(planned):
            # Zero found with the full announced list run and clean
            # streams: every pair provably tried-and-failed (lab-fresh
            # lockout counters + budget < threshold make locked
            # unreachable here — module docstring).
            for _, _, aid, _ in planned:
                led.reconcile(aid, "invalid")
                counts["invalid"] += 1
            run_status = "completed"
        else:
            refusal_reasons.append(
                f"announced tries {s.announced_tries} != planned pairs "
                f"{len(planned)}: cannot prove which pairs hit the wire")
    elif parsed is not None:
        refusal_reasons.extend(parsed.summary.refusal_reasons)

    # Conservative resolution of everything still open (module docstring):
    # dispatched-unreconciled -> expired_spent (budget consumed);
    # never-dispatched -> voided. Also crash-sweeps earlier runs' rows.
    expired = led.resolve_expired(ttl=0.0)

    reconcile_summary = (
        f"{run_status}: valid={counts['valid']} invalid={counts['invalid']} "
        f"locked={counts['locked']} expired={len(expired)} "
        f"(hydra {hydra_version}, rule {rule['id']}"
        + ("; " + "; ".join(refusal_reasons) if refusal_reasons else "")
        + ")")
    led.reconcile_slice(slice_id, reconcile_summary)

    manifest = seal_mod.seal_campaign(campaign_dir)
    verify_ok, verify_detail = seal_mod.verify_seal(campaign_dir)

    return {
        "run_status": run_status if verify_ok else "seal_verify_failed",
        "mode": "lab",
        "target": f"{host}:{port}", "service": SERVICE,
        "engagement_id": obj["engagement_id"],
        "campaign_dir": str(campaign_dir),
        "roe_digest": roe_digest,
        "rule_id": rule["id"],
        "slice_id": slice_id,
        "budget_per_principal_per_run": budget_per_run,
        "planned_pairs": len(planned),
        "instrument": {
            "path": str(hydra_bin), "version": hydra_version,
            "exit_code": result.exit_code if result else None,
            "duration_s": result.duration_s if result else None,
            "killed": result.killed if result else None,
            "timed_out": result.timed_out if result else None,
            "output_capped": result.output_capped if result else None,
        },
        "parse": parse_info,
        "reconcile": {**counts,
                      "expired_spent": sum(1 for v in expired.values()
                                           if v == budget.EXPIRED_SPENT),
                      "voided": sum(1 for v in expired.values()
                                    if v == budget.VOIDED)},
        "refusal_reasons": refusal_reasons,
        "streams_sha256": stream_digests,
        "captures": "scrubbed (zero-overwrite + unlink, the internal design notes)",
        "seal": {"manifest_sha256": manifest["manifest_sha256"],
                 "path": str(seal_mod.manifest_path(campaign_dir))},
        "verify": {"ok": verify_ok, "detail": verify_detail},
    }
