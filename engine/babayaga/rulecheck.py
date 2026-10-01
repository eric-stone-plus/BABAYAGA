'Static validator for the rules/ corpus — the B10 inversion as code.\n\n- packs and services are CLOSED vocabularies (PACKS / SERVICES below): an\n  unknown value is an ambiguous instrument request and refuses, it is never\n  resolved by best guess;\n- the field set is closed at every nesting level, because a typo\'d key\n  ("budjet") would otherwise be silently ignored — the fail-open shape this\n  corpus exists to kill;\n- instrument flags are judged against budget.py\'s measured policy: the -e\n  family (attempt multiplier) is forbidden anywhere, and the runner-owned\n  flags (-C/-K/-I/-f, budget.REQUIRED_FLAGS) must not be re-declared by a\n  rule.\n\nExit codes (babayaga/__init__.py): 0 clean corpus,\n2 any refusal issue, 1 bad invocation (e.g. missing directory).\n\nRun:  python -m babayaga.rulecheck engine/rules [--json]\n\nThis module is deliberately standalone: no CLI subcommand, no schema event\nkinds. The runner consumes check_corpus() when the run milestone lands.\n'

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from . import EXIT_ERROR, EXIT_OK, EXIT_REFUSAL, budget

# --------------------------------------------------------------------------
# Closed vocabularies (v1). Widening one is a deliberate corpus change: add
# the value here, ship a rule that uses it, extend tests/test_rulecheck.py.
# --------------------------------------------------------------------------

# Rule intent families. spray = password-outer across principals (the shape
# budget.plan_slice emits); stuff = replay of already-known pairs, one shot
# each; brute = multi-password pressure on a narrow principal set, the
# highest lockout-risk shape.
PACKS = ("spray", "stuff", "brute")

# Hydra module names the corpus may match on. v1 is exactly the lab demo
# path (engine/lab/http_get_lab.py); this host's hydra has no ssh support,
# so nothing else is declarable yet.
SERVICES = ("http-get",)

# id shape: R-CRED-<PACK uppercased>-<three digits>; the pack segment must
# agree with the "pack" field (checked as id_pack_mismatch).
ID_RE = re.compile(r"^R-CRED-([A-Z]+)-(\d{3})$")

ALLOWED_TOP = (
    "id", "name", "pack", "match", "throttle", "budget",
    "lockout_abort_after", "refusal_rationale",
)
ALLOWED_MATCH = ("service",)
ALLOWED_THROTTLE = ("instrument_flags", "slice_cadence_seconds")
ALLOWED_BUDGET = ("per_principal_per_run_max",)

# The instrument-side throttle the B10 inversion demands: hydra -t (parallel
# connects, default 16). A rule must pin it explicitly, and low.
THROTTLE_FLAGS = ("-t",)
MAX_PARALLEL_TASKS = 4

# Engine-side throttle floor: seconds between spray slices. Zero is no
# cadence, and an undeclared cadence is no cadence.
MIN_SLICE_CADENCE_SECONDS = 1.0

# Same NIST SP 800-63B-4 ceiling roe.validate enforces on the ROE side.
BUDGET_MIN, BUDGET_MAX = 1, 100

# Flags the runner injects (budget.REQUIRED_FLAGS: -C/-K/-I/-f). A rule
# re-declaring one makes flag precedence ambiguous -> refusal.
RUNNER_OWNED_FLAGS = budget.REQUIRED_FLAGS


@dataclass
class RuleIssue:
    code: str
    rule_id: str
    path: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "rule_id": self.rule_id,
                "path": self.path, "message": self.message}


@dataclass
class CorpusReport:
    issues: list[RuleIssue]
    rules_checked: int

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict:
        return {"ok": self.ok, "rules_checked": self.rules_checked,
                "issues": [i.to_dict() for i in self.issues]}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_num(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_rule(data: object, path: str = "<memory>") -> list[RuleIssue]:
    """Refusal issues for one parsed rule object; empty list means clean."""
    if not isinstance(data, dict):
        return [RuleIssue(
            "unparseable_rule", "<non-dict>", path,
            f"top-level JSON is {type(data).__name__}, not an object")]
    rid = str(data.get("id") or "<no-id>")
    issues: list[RuleIssue] = []

    def add(code: str, message: str) -> None:
        issues.append(RuleIssue(code, rid, path, message))

    for key in sorted(data):
        if key not in ALLOWED_TOP:
            add("unknown_field",
                f"unknown top-level key {key!r} — the rule shape is closed: "
                f"{', '.join(ALLOWED_TOP)}")

    id_match = None
    idv = data.get("id")
    if not isinstance(idv, str) or not idv.strip():
        add("bad_rule_id", 'missing or empty "id"')
    else:
        id_match = ID_RE.match(idv)
        if not id_match:
            add("bad_rule_id",
                f"id {idv!r} must match R-CRED-<PACK>-<NNN> "
                f"(e.g. R-CRED-SPRAY-001)")

    if not isinstance(data.get("name"), str) or not data["name"].strip():
        add("missing_field", '"name": non-empty string required')

    pack = data.get("pack")
    if pack not in PACKS:
        add("unknown_pack",
            f"pack {pack!r} is not one of the closed packs: "
            f"{', '.join(PACKS)}")
    elif id_match and id_match.group(1) != str(pack).upper():
        add("id_pack_mismatch",
            f"id segment {id_match.group(1)!r} disagrees with pack {pack!r}")

    match = data.get("match")
    if not isinstance(match, dict):
        add("missing_field", '"match": object with a "service" key required')
    else:
        for key in sorted(match):
            if key not in ALLOWED_MATCH:
                add("unknown_field",
                    f"match.{key}: unknown key (closed: "
                    f"{', '.join(ALLOWED_MATCH)})")
        service = match.get("service")
        if service not in SERVICES:
            add("unknown_service",
                f"service {service!r} is not in the closed v1 vocabulary "
                f"({', '.join(SERVICES)}) — an unknown module is a refusal, "
                "never a best guess")

    issues.extend(_check_throttle(data.get("throttle"), rid, path))
    issues.extend(_check_budget(data.get("budget"), rid, path))

    abort_after = data.get("lockout_abort_after")
    if not _is_int(abort_after) or abort_after < 1:
        add("bad_lockout_abort",
            "lockout_abort_after: int >= 1 required — the count of locked "
            "outcomes that halts the run against the target (fail closed)")

    rationale = data.get("refusal_rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        add("missing_refusal_rationale",
            "refusal_rationale: non-empty string required — the sentence "
            "recorded when this rule's limits force a refusal")

    return issues


def _check_throttle(throttle: object, rid: str, path: str) -> list[RuleIssue]:
    """The B10 inversion: a rule without explicit throttle flags refuses."""
    issues: list[RuleIssue] = []

    def add(code: str, message: str) -> None:
        issues.append(RuleIssue(code, rid, path, message))

    if not isinstance(throttle, dict) or not throttle:
        add("missing_throttle_flags",
            "throttle block missing or empty — B10: a rule without explicit "
            "throttle flags is a refusal, not a default cadence")
        return issues

    for key in sorted(throttle):
        if key not in ALLOWED_THROTTLE:
            add("unknown_field",
                f"throttle.{key}: unknown key (closed: "
                f"{', '.join(ALLOWED_THROTTLE)})")

    flags = throttle.get("instrument_flags")
    if (not isinstance(flags, list) or not flags
            or not all(isinstance(f, str) for f in flags)):
        add("missing_throttle_flags",
            'throttle.instrument_flags: non-empty list of flag tokens '
            'required (e.g. ["-t", "1"])')
    else:
        for tok in flags:
            if tok.startswith("-e"):
                add("forbidden_instrument_flag",
                    f"flag {tok!r} is forbidden — the -e family multiplies "
                    "attempts beyond the explicit pair list (budget.py, "
                    "measured 3x)")
            if tok in RUNNER_OWNED_FLAGS:
                add("runner_owned_flag",
                    f"flag {tok!r} is injected by the runner "
                    "(budget.REQUIRED_FLAGS); a rule re-declaring it makes "
                    "flag precedence ambiguous")
        present = [f for f in THROTTLE_FLAGS if f in flags]
        if not present:
            add("missing_throttle_flags",
                f"instrument_flags carry no throttle flag: hydra "
                f"{'/'.join(THROTTLE_FLAGS)} (parallel connects) must be "
                "pinned explicitly")
        elif "-t" in flags:
            i = flags.index("-t")
            value = flags[i + 1] if i + 1 < len(flags) else None
            if (not isinstance(value, str) or not value.isdigit()
                    or not 1 <= int(value) <= MAX_PARALLEL_TASKS):
                add("bad_throttle_flag",
                    f"-t requires an integer value in "
                    f"[1,{MAX_PARALLEL_TASKS}]; the hydra default (16) is "
                    "not a throttle")

    cadence = throttle.get("slice_cadence_seconds")
    if not _is_num(cadence) or cadence < MIN_SLICE_CADENCE_SECONDS:
        add("missing_throttle_flags",
            f"throttle.slice_cadence_seconds: number >= "
            f"{MIN_SLICE_CADENCE_SECONDS} required — an undeclared cadence "
            "is no cadence")
    return issues


def _check_budget(budget_block: object, rid: str, path: str) -> list[RuleIssue]:
    issues: list[RuleIssue] = []

    def add(code: str, message: str) -> None:
        issues.append(RuleIssue(code, rid, path, message))

    if not isinstance(budget_block, dict):
        add("bad_budget",
            '"budget": object with per_principal_per_run_max required')
        return issues
    for key in sorted(budget_block):
        if key not in ALLOWED_BUDGET:
            add("unknown_field",
                f"budget.{key}: unknown key (closed: "
                f"{', '.join(ALLOWED_BUDGET)})")
    ceiling = budget_block.get("per_principal_per_run_max")
    if not _is_int(ceiling) or not BUDGET_MIN <= ceiling <= BUDGET_MAX:
        add("bad_budget",
            f"budget.per_principal_per_run_max: int in "
            f"[{BUDGET_MIN},{BUDGET_MAX}] required (NIST SP 800-63B-4 "
            "anchor, the same ceiling roe.validate enforces)")
    return issues


def check_corpus(rules_dir: str | Path) -> CorpusReport:
    """Validate every *.json rule under rules_dir. Never raises on a bad rule."""
    issues: list[RuleIssue] = []
    seen_ids: dict[str, str] = {}
    checked = 0
    for path in sorted(Path(rules_dir).rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(RuleIssue(
                "unparseable_rule", f"<unparseable:{path.name}>", str(path),
                f"rule file does not parse: {exc}"))
            continue
        checked += 1
        issues.extend(validate_rule(data, str(path)))
        rid = data.get("id") if isinstance(data, dict) else None
        if isinstance(rid, str) and rid.strip():
            if rid in seen_ids:
                issues.append(RuleIssue(
                    "duplicate_rule_id", rid, str(path),
                    f"rule id {rid!r} is also defined in {seen_ids[rid]} — "
                    "retire one copy to rules.retired/"))
            else:
                seen_ids[rid] = str(path)
    return CorpusReport(issues=issues, rules_checked=checked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="babayaga.rulecheck",
        description="Validate the babayaga rule corpus (B10: throttle flags "
                    "are REQUIRED; their absence is a refusal).")
    parser.add_argument("rules_dir", help="corpus directory (e.g. engine/rules)")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON")
    args = parser.parse_args(argv)

    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"error: rules directory not found: {rules_dir}", file=sys.stderr)
        return EXIT_ERROR

    report = check_corpus(rules_dir)
    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        for issue in report.issues:
            print(f"REFUSAL {issue.code} {issue.rule_id} "
                  f"({issue.path}): {issue.message}")
        verdict = "ok" if report.ok else "refused"
        print(f"rulecheck: {report.rules_checked} rules, "
              f"{len(report.issues)} refusals -> {verdict}")
    return EXIT_OK if report.ok else EXIT_REFUSAL


if __name__ == "__main__":
    sys.exit(main())
