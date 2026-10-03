'ROE (rules of engagement) object: load, validate, digest, coverage checks.\n\nThe ROE is per-engagement authorization-as-data. Fail-closed everywhere:\n- an absent or malformed field is a refusal, never a default;\n- digest() is what gets hashed into sealed campaign evidence;\n- check_target enforces target coverage on top of the\n  ROE\'s own target list.\n\n- `on_detect` (optional): one of ON_DETECT = annotate|cooldown|halt — a\n  CLOSED vocabulary, validated when present. Detection is an operational\n  signal (the ledger\'s detection.annotated event), never a reconcile\n  outcome. Engine-side behavior at v2 never exceeds `annotate`: cooldown\n  and halt are operator-declared policy the engine records but does not yet\n  act on (post-v2); declaring them is valid, expecting the engine to pace\n  or stop on them is not yet wired.\n- `actions` (optional): subset of schema.ACTION_KINDS; absent = guess-only\n  (every v1 ROE). When "exec" is declared, `budgets.per_action` and\n  `targets[].tier` become require-or-refuse — see validate().\n'

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

from . import LAB_ONLY
from .schema import ACTION_KINDS, OUTCOMES_BY_KIND

PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}\$?$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$")

REQUIRED_TOP = (
    "engagement_id", "operator", "attestation", "targets",
    "principals", "budgets", "window", "lockout",
)
# The guess-axis reconcile vocabulary (the parser contract — hydra_stdout's
# hints map onto exactly this set). Sourced from schema so the per-kind
# vocabularies have ONE owner; exec outcomes are schema.OUTCOMES_BY_KIND["exec"].
OUTCOMES = OUTCOMES_BY_KIND["guess"]
# Detection policy vocabulary (item 5): validated when present; engine-side
# behavior beyond "annotate" is post-v2 (module docstring).
ON_DETECT = ("annotate", "cooldown", "halt")


class RoeError(Exception):
    """ROE is missing, malformed, or refuses the request. Always a refusal (exit 2)."""


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj: dict) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def load(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise RoeError(f"ROE file not found: {p}")
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RoeError(f"ROE file unreadable/invalid JSON: {exc}") from exc
    errors = validate(obj)
    if errors:
        raise RoeError("ROE invalid: " + "; ".join(errors))
    return obj


def _check_iso(value: object, where: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not ISO_RE.match(value):
        errors.append(f"{where}: expected ISO-8601 datetime string with timezone")
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{where}: unparseable datetime {value!r}")


def validate(obj: object) -> list[str]:
    """Return a list of problems; empty list means the ROE object is valid."""
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["ROE must be a JSON object"]
    for key in REQUIRED_TOP:
        if key not in obj:
            errors.append(f"missing required key: {key}")

    if "engagement_id" in obj and (not isinstance(obj["engagement_id"], str) or not obj["engagement_id"].strip()):
        errors.append("engagement_id: non-empty string required")

    att = obj.get("attestation")
    if not isinstance(att, dict):
        errors.append("attestation: object required")
    else:
        for sub in ("statement", "authorized_by", "date"):
            v = att.get(sub)
            if not isinstance(v, str) or not v.strip():
                errors.append(f"attestation.{sub}: non-empty string required")
        if isinstance(att.get("date"), str):
            _check_iso(att["date"], "attestation.date", errors)

    targets = obj.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("targets: non-empty list required")
    else:
        for i, t in enumerate(targets):
            if not isinstance(t, dict):
                errors.append(f"targets[{i}]: object required")
                continue
            host = t.get("host")
            if not isinstance(host, str) or not host.strip():
                errors.append(f"targets[{i}].host: non-empty string required")
            else:
                # A signed /0 is total coverage the day LAB_ONLY flips — refuse
                # the degenerate "entire internet" networks outright.
                try:
                    net = ipaddress.ip_network(host, strict=False)
                    if net.prefixlen == 0:
                        errors.append(f"targets[{i}].host: /0 networks are not authorizable")
                except ValueError:
                    pass  # non-CIDR hosts (DNS names) checked at attempt time
            ports = t.get("ports")
            if (not isinstance(ports, list) or not ports
                    or not all(isinstance(p_, int) and 1 <= p_ <= 65535 for p_ in ports)):
                errors.append(f"targets[{i}].ports: non-empty list of ints 1-65535 required")
            tier = t.get("tier")
            if tier is not None and (not isinstance(tier, int)
                                     or isinstance(tier, bool) or tier < 0):
                errors.append(f"targets[{i}].tier: int >= 0 required when present")

    principals = obj.get("principals")
    if not isinstance(principals, list) or not principals:
        errors.append("principals: non-empty explicit list required (no wildcards)")
    elif not all(isinstance(p_, str) and PRINCIPAL_RE.match(p_) for p_ in principals):
        errors.append("principals: entries must match " + PRINCIPAL_RE.pattern)
    elif len(set(principals)) != len(principals):
        errors.append("principals: duplicate entries")

    budgets = obj.get("budgets")
    if not isinstance(budgets, dict):
        errors.append("budgets: object required")
    else:
        pp = budgets.get("per_principal_per_run")
        if not isinstance(pp, int) or isinstance(pp, bool) or not 1 <= pp <= 100:
            errors.append("budgets.per_principal_per_run: int in [1,100] required (NIST SP 800-63B-4 anchor)")
        pa = budgets.get("per_action")
        if pa is not None:
            if not isinstance(pa, dict):
                errors.append("budgets.per_action: object required when present")
            else:
                for axis, value in pa.items():
                    if axis not in ACTION_KINDS:
                        errors.append(
                            f"budgets.per_action: unknown axis {axis!r} "
                            f"(closed: {ACTION_KINDS}) — never silently ignored")
                    elif not isinstance(value, int) or isinstance(value, bool) or value < 1:
                        errors.append(f"budgets.per_action.{axis}: int >= 1 required")

    # Action axes (v2 item 7). Absent `actions` = guess-only (every v1 ROE).
    # When exec is declared, budgets.per_action and targets[].tier are
    # REQUIRE-OR-REFUSE: an absent field is a refusal, never a
    # silently-ignored extra. Axes: guess = auth attempts; exec = instrument
    # invocations = credential-uses. The tier field IS the explicit exec
    # grant for that target (check_target refuses exec without it).
    actions = obj.get("actions")
    declared: list[str] = []
    if actions is not None:
        if (not isinstance(actions, list) or not actions
                or not all(isinstance(a, str) for a in actions)):
            errors.append(f"actions: non-empty list subset of {ACTION_KINDS} required when present")
        elif any(a not in ACTION_KINDS for a in actions):
            errors.append(f"actions: unknown kinds {sorted(set(actions) - set(ACTION_KINDS))} (closed: {ACTION_KINDS})")
        elif len(set(actions)) != len(actions):
            errors.append("actions: duplicate entries")
        else:
            declared = list(actions)
    if "exec" in declared:
        pa = budgets.get("per_action") if isinstance(budgets, dict) else None
        if not isinstance(pa, dict) or any(axis not in pa for axis in declared):
            errors.append(
                "budgets.per_action: required with an int budget per declared "
                "axis when exec actions are authorized (absent = refusal)")
        if isinstance(targets, list):
            for i, t in enumerate(targets):
                if isinstance(t, dict) and "tier" not in t:
                    errors.append(
                        f"targets[{i}].tier: required when exec actions are "
                        "authorized — the tier field is the explicit exec "
                        "grant (absent = refusal)")

    window = obj.get("window")
    if window is not None:
        if not isinstance(window, dict):
            errors.append("window: object or null required")
        else:
            for sub in ("start", "end"):
                if sub in window:
                    _check_iso(window[sub], f"window.{sub}", errors)
            start, end = window.get("start"), window.get("end")
            if isinstance(start, str) and isinstance(end, str) and not errors:
                s = datetime.fromisoformat(start.replace("Z", "+00:00"))
                e = datetime.fromisoformat(end.replace("Z", "+00:00"))
                if e <= s:
                    errors.append("window: end must be after start")

    lockout = obj.get("lockout")
    if not isinstance(lockout, dict):
        errors.append("lockout: object required (observed policy; probe it, do not guess)")
    else:
        thr = lockout.get("observed_threshold")
        if not isinstance(thr, int) or isinstance(thr, bool) or thr < 1:
            errors.append("lockout.observed_threshold: int >= 1 required")
        rm = lockout.get("reset_minutes")
        if not isinstance(rm, int) or isinstance(rm, bool) or rm < 1:
            errors.append("lockout.reset_minutes: int >= 1 required")
        budget_pp = obj.get("budgets", {}).get("per_principal_per_run") if isinstance(obj.get("budgets"), dict) else None
        if isinstance(thr, int) and isinstance(budget_pp, int) and budget_pp >= thr:
            errors.append("budgets.per_principal_per_run must stay below lockout.observed_threshold")

    on_detect = obj.get("on_detect")
    if on_detect is not None and on_detect not in ON_DETECT:
        errors.append(
            f"on_detect: one of {ON_DETECT} when present (closed vocabulary; "
            "engine-side behavior beyond 'annotate' is post-v2)")
    return errors


def resolve_host(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    for info in infos:
        try:
            return ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
    return None


def check_target(obj: dict, host: str, port: int,
                 action_kind: str = "guess") -> tuple[bool, str]:
    'Refusal tuple for a (host, port) attempt request on an action axis.'
    if action_kind not in ACTION_KINDS:
        return False, f"unknown action_kind {action_kind!r} (closed: {ACTION_KINDS})"
    addr = resolve_host(host)
    if addr is None:
        return False, f"cannot resolve target host {host!r}"
    if LAB_ONLY and not addr.is_loopback:
        return False, f"v0 is LAB-ONLY: target {host} is not loopback (the internal design notes)"
    for t in obj.get("targets", []):
        if not isinstance(t, dict):
            continue
        if port not in (t.get("ports") or []):
            continue
        try:
            net = ipaddress.ip_network(t["host"], strict=False)
        except ValueError:
            if t.get("host") != host:
                continue
            net = None
        if net is None or addr in net:
            if action_kind == "exec":
                declared = obj.get("actions") or ["guess"]
                if "exec" not in declared:
                    return False, (
                        f"exec against {host}:{port} refused: the ROE does not "
                        "authorize exec actions (actions lacks 'exec')")
                if "tier" not in t:
                    return False, (
                        f"exec against {host}:{port} refused: the target carries "
                        "no explicit tier grant (targets[].tier absent)")
            return True, "covered"
    return False, f"target {host}:{port} is not covered by the ROE target list"


def check_principal(obj: dict, principal: str) -> tuple[bool, str]:
    if not isinstance(principal, str) or not PRINCIPAL_RE.match(principal or ""):
        return False, f"malformed principal {principal!r}"
    if principal in obj.get("principals", []):
        return True, "covered"
    return False, f"principal {principal!r} is not in the ROE principal list"


def check_window(obj: dict, now: datetime | None = None) -> tuple[bool, str]:
    window = obj.get("window")
    if not window:
        return True, "no window declared"
    now = now or datetime.now(timezone.utc)
    start, end = window.get("start"), window.get("end")
    if start:
        s = datetime.fromisoformat(start.replace("Z", "+00:00"))
        if now < s:
            return False, f"engagement window not open yet (start {start})"
    if end:
        e = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if now > e:
            return False, f"engagement window closed (end {end})"
    return True, "within window"


def per_principal_budget(obj: dict) -> int:
    return obj["budgets"]["per_principal_per_run"]
