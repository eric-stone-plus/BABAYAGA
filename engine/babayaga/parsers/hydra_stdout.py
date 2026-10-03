'hydra v9.8dev stdout/stderr stream parser (http-get profile).\n\n- On this build banners/[DATA]/[ATTEMPT]/found/[STATUS]/summary all go to\n  stdout; [ERROR] lines go to stderr (stock builds split differently —\n  a recorded pitfall — so the grammar below is stream-agnostic on purpose).\n- Found line (http-get carries the path as misc):\n      [18080][http-get] host: 127.0.0.1   misc: /   login: <u>   password: <p>\n- Run summary ("successfully " only when found > 0; singular/plural varies):\n      1 of 1 target successfully completed, 1 valid password found\n      1 of 1 target completed, 0 valid password found'

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

HINTS = ("valid", "invalid", "locked", "error", "unknown")

LINE_CLASSES = (
    "banner", "data", "status", "verbose", "debug",   # recognized chrome
    "attempt", "attempt_error", "found",              # attempt-level evidence
    "error", "warning", "signal_lockout",             # run/attempt signals
    "unknown",                                        # refuse path
)


@dataclass(frozen=True)
class AttemptRecord:
    'One classified stream line with attempt-level meaning.'

    principal: str | None
    outcome_hint: str  # one of HINTS
    line_class: str    # one of LINE_CLASSES


@dataclass(frozen=True)
class RunSummary:
    """Completeness/consistency verdict for one hydra run's streams.

    status "ok" means the output was complete and self-consistent — NOT that
    credentials were found. status "refused" means ambiguous or incomplete
    output; the caller must treat every attempt of the run as unproven.
    """

    status: str                       # "ok" | "refused"
    refusal_reasons: tuple[str, ...]
    announced_tries: int | None       # from [DATA] "N login tries"
    attempts_seen: int
    found_principals: tuple[str, ...]
    found_digests: tuple[str, ...]
    valid_passwords_found: int | None
    targets_completed: int | None
    targets_total: int | None
    errors: int
    warnings: int
    unknown_lines: int
    summary_seen: bool
    finished_seen: bool


@dataclass(frozen=True)
class ParsedRun:
    records: tuple[AttemptRecord, ...]
    summary: RunSummary


_FOUND_RE = re.compile(
    r"^\[(?P<port>\d+)\]\[(?P<service>[\w-]+)\] host: (?P<host>\S+)"
    r"(?:   misc: \S*)?"
    r"   login: (?P<login>\S+)   password: (?P<password>.*)$"
)
# Numeric fields are bounded (\d{1,18}): a longer digit run stops matching,
# so the line falls to "unknown" and poisons the run. An unbounded \d+ would
# let a forged 4300+-digit count crash int() at classification time (Python's
# int<->str digit cap) — a parser must never raise on adversarial output.
_SUMMARY_RE = re.compile(
    r"^(?P<done>\d{1,18}) of (?P<total>\d{1,18}) targets? (?:successfully )?completed, "
    r"(?P<found>\d{1,18}) valid passwords? found$"
)
_DATA_RE = re.compile(
    r"^\[DATA\] max \d{1,18} tasks? per \d{1,18} servers?, overall \d{1,18} tasks?, "
    r"(?P<tries>\d{1,18}) login (?:try|tries)"
)
_DATA_ATTACKING_RE = re.compile(r"^\[DATA\] attacking \S+")
def _redact(line: str) -> str:
    ''
    out = re.sub(r'"[^"]*"', '"***"', line)
    return out[:160]


_ATTEMPT_RE = re.compile(
    r"^\[(?:REDO-|RE-)?ATTEMPT\] target \S+ - login \"(?P<login>[^\"]*)\""
    r" - pass \"[^\"]*\" - \d+ of \d+ \[child \d+\] \(\d+/\d+\)$"
)
_STATUS_RE = re.compile(r"^\[STATUS\] ")
_ATTEMPT_ERROR_RE = re.compile(
    r"^\[ATTEMPT-ERROR\] target \S+ - login \"(?P<login>[^\"]*)\""
    r" - pass \"[^\"]*\" - child \d+ - \d+ of \d+$"
)
_ERROR_RE = re.compile(r"^\[ERROR\] ")
# [WARNING] lines (e.g. hydra-http.c "Unusual return code: <code> for
# login:pass") can carry plaintext material; they are counted and poison the
# run, never stored. A warning means the target behaved outside the modeled
# grammar, which is ambiguous instrument output: refusal path.
_WARNING_RE = re.compile(r"^\[WARNING\] ")
# -v/-d chatter. Recognized as chrome so mixed-verbose runs parse, but the
# raw -d dump lines (hexdumps, S:/C: protocol echoes, DEBUG_CONNECT_OK)
# intentionally stay "unknown": -d is not a supported run profile and its
# interleaved dump refuses the run, as it should.
_VERBOSE_RE = re.compile(r"^\[VERBOSE\] ")
_DEBUG_RE = re.compile(r"^\[DEBUG\] ")
# hydra 9.8dev prints [INFO] chrome on every run (providers warning etc.)
# and this build has no other [NOTE]-class shapes; both are non-evidence.
_INFO_RE = re.compile(r"^\[(?:INFO|NOTE)\] ")
_LOCKOUT_RES = (
    re.compile(r"^X-Lab-Lockout:\s*true\s*$", re.IGNORECASE),
    re.compile(r"^X-Lab-Outcome:\s*locked\s*$", re.IGNORECASE),
)
_BANNER_RE = re.compile(
    r"^(Hydra v[\d.]+|Hydra \(https://github\.com/vanhauser-thc/thc-hydra\) )"
)


class HydraStreamParser:
    """Incremental line-fed parser; the executor feeds pipe lines as they
    arrive and calls finish() after the process exits (or is killed)."""

    def __init__(self) -> None:
        self._records: list[AttemptRecord] = []
        self._found_digests: list[str] = []
        self._announced_tries: int | None = None
        self._attempts_seen = 0
        self._unknown_samples: list[str] = []
        self._errors = 0
        self._warnings = 0
        self._unknown = 0
        self._summary: tuple[int, int, int] | None = None
        self._finished_seen = False
        # Duplicate verdict-bearing lines: an identical re-print is tolerated
        # (stream-split duplication), a CONTRADICTING one is ambiguous
        # instrument output — last-wins would let a forged trailing summary
        # overturn the real verdict, so conflicts poison the run.
        self._summary_conflicts = 0
        self._tries_conflicts = 0

    def feed(self, line: str) -> AttemptRecord | None:
        ''
        line = line.rstrip("\r\n")
        if not line.strip():
            return None
        record = self._classify(line)
        if record is not None:
            self._records.append(record)
        return record

    @property
    def records(self) -> tuple[AttemptRecord, ...]:
        """Every record fed so far (immutable snapshot)."""
        return tuple(self._records)

    def _classify(self, line: str) -> AttemptRecord | None:
        m = _FOUND_RE.match(line)
        if m:
            try:
                digest = hashlib.sha256(
                    f"{m.group('login')}:{m.group('password')}".encode("utf-8")
                ).hexdigest()
            except UnicodeEncodeError:
                # Undecodable bytes (e.g. surrogate escapes) bled into a
                # found-shaped line: ambiguous evidence — poison the run,
                # never crash and never emit a valid hint for it.
                self._unknown += 1
                return AttemptRecord(None, "unknown", "unknown")
            self._found_digests.append(digest)
            return AttemptRecord(m.group("login"), "valid", "found")
        m = _SUMMARY_RE.match(line)
        if m:
            summary = (int(m.group("done")), int(m.group("total")),
                       int(m.group("found")))
            if self._summary is None:
                self._summary = summary
            elif summary != self._summary:
                self._summary_conflicts += 1
            return None
        m = _DATA_RE.match(line)
        if m:
            tries = int(m.group("tries"))
            if self._announced_tries is None:
                self._announced_tries = tries
            elif tries != self._announced_tries:
                self._tries_conflicts += 1
            return None
        if _DATA_ATTACKING_RE.match(line):
            return None
        m = _ATTEMPT_ERROR_RE.match(line)
        if m:
            self._errors += 1
            return AttemptRecord(m.group("login"), "error", "attempt_error")
        m = _ATTEMPT_RE.match(line)
        if m:
            self._attempts_seen += 1
            # Dispatch evidence only: the -V grammar carries no per-attempt
            # result, so the hint is "unknown", never a guessed "invalid".
            return AttemptRecord(m.group("login"), "unknown", "attempt")
        if _STATUS_RE.match(line):
            return None
        if _ERROR_RE.match(line):
            self._errors += 1
            return AttemptRecord(None, "error", "error")
        if _WARNING_RE.match(line):
            self._warnings += 1
            return AttemptRecord(None, "unknown", "warning")
        if any(r.match(line) for r in _LOCKOUT_RES):
            return AttemptRecord(None, "locked", "signal_lockout")
        if (_VERBOSE_RE.match(line) or _DEBUG_RE.match(line)
                or _INFO_RE.match(line)):
            return None
        if _BANNER_RE.match(line):
            if " finished at " in line:
                self._finished_seen = True
            return None
        self._unknown += 1
        if len(self._unknown_samples) < 3:
            self._unknown_samples.append(_redact(line))
        return AttemptRecord(None, "unknown", "unknown")

    def finish(self) -> RunSummary:
        reasons: list[str] = []
        found = tuple(r.principal for r in self._records
                      if r.line_class == "found" and r.principal is not None)
        done = total = valid_found = None
        if self._summary is not None:
            done, total, valid_found = self._summary
        if self._summary is None:
            reasons.append("no run summary line: hydra was killed, hung, or "
                           "crashed — never reconcile partial output "
                           "(a recorded pitfall/#5)")
        if self._summary is not None and not self._finished_seen:
            reasons.append("no 'finished at' line: hydra did not exit "
                           "gracefully after the summary")
        if self._summary_conflicts:
            reasons.append(f"{self._summary_conflicts} contradictory run "
                           "summary line(s): ambiguous instrument output is "
                           "a refusal path")
        if self._tries_conflicts:
            reasons.append(f"{self._tries_conflicts} contradictory [DATA] "
                           "login-tries announcement(s): ambiguous instrument "
                           "output is a refusal path")
        if self._unknown:
            sample = (" | samples: " + "; ".join(self._unknown_samples)
                      if self._unknown_samples else "")
            reasons.append(f"{self._unknown} unrecognized line(s): ambiguous "
                           f"instrument output is a refusal path{sample}")
        if self._warnings:
            reasons.append(f"{self._warnings} warning line(s): instrument "
                           "reported unmodeled behavior")
        if self._errors:
            reasons.append(f"{self._errors} error line(s): per-attempt wire "
                           "state is no longer provable")
        if (valid_found is not None and valid_found != len(found)):
            reasons.append(f"summary claims {valid_found} valid password(s) "
                           f"but the stream shows {len(found)} found line(s): "
                           "contradictory output")
        if done is not None and total is not None and done != total:
            reasons.append(f"only {done} of {total} target(s) completed")
        if (self._announced_tries is not None
                and self._attempts_seen > self._announced_tries):
            reasons.append(f"{self._attempts_seen} attempt lines exceed the "
                           f"{self._announced_tries} announced login tries: "
                           "contradictory output")
        return RunSummary(
            status="refused" if reasons else "ok",
            refusal_reasons=tuple(reasons),
            announced_tries=self._announced_tries,
            attempts_seen=self._attempts_seen,
            found_principals=found,
            found_digests=tuple(self._found_digests),
            valid_passwords_found=valid_found,
            targets_completed=done,
            targets_total=total,
            errors=self._errors,
            warnings=self._warnings,
            unknown_lines=self._unknown,
            summary_seen=self._summary is not None,
            finished_seen=self._finished_seen,
        )


def parse_streams(stdout: str, stderr: str = "") -> ParsedRun:
    """Parse a completed run's captured streams (stream-agnostic grammar:
    this build routes almost everything to stdout, stock builds split —
    both are fed through the same classifier)."""
    parser = HydraStreamParser()
    for line in stdout.splitlines():
        parser.feed(line)
    for line in stderr.splitlines():
        parser.feed(line)
    return ParsedRun(records=parser.records, summary=parser.finish())
