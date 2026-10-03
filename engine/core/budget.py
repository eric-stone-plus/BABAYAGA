'Budget semantics: exact-pair planning and lease expiry resolution.\n\nLease expiry follows the proof-in-the-log rule: an attempt with no dispatch\nevent provably never left the machine -> voided (budget restored); a\ndispatched-but-unreconciled attempt has unknown wire state -> expired_spent\n(budget consumed, fail closed).'

from __future__ import annotations

import time
from collections.abc import Collection

VOIDED = "voided"
EXPIRED_SPENT = "expired_spent"
OPEN_STATES = ("reserved", "dispatched")

# Default lease TTL for unreconciled attempts (seconds). Deliberately long:
# expiry resolution is for crash recovery, not pacing.
DEFAULT_TTL_SECONDS = 3600.0


class BudgetExhausted(Exception):
    """No principal has remaining budget. A refusal, never a silent shrink."""


def remaining(principal: str, spent: dict[str, int], budget_per_run: int) -> int:
    return max(0, budget_per_run - spent.get(principal, 0))


def plan_slice(
    principals: list[str],
    password: str,
    spent: dict[str, int],
    budget_per_run: int,
    locked: Collection[str] = (),
) -> list[tuple[str, str]]:
    'One spray slice: the next single password for every principal that still\n    has budget. Returns explicit (principal, password) pairs; empty list means\n    the budget is exhausted everywhere (caller must refuse, not improvise).'
    pairs: list[tuple[str, str]] = []
    for principal in principals:
        if principal in locked:
            continue
        if remaining(principal, spent, budget_per_run) > 0:
            pairs.append((principal, password))
    return pairs


def resolve_expiry(
    attempts: list[dict],
    now: float | None = None,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> dict[str, str]:
    """Map attempt_id -> resolution for open attempts older than TTL.

    `attempts` rows carry at least: attempt_id, state, dispatched_ts (nullable),
    resolved_ts (nullable), reserved_ts.
    """
    now = now if now is not None else time.time()
    out: dict[str, str] = {}
    for row in attempts:
        if row.get("state") not in OPEN_STATES:
            continue
        anchor = row.get("dispatched_ts") or row.get("reserved_ts") or 0.0
        if now - anchor < ttl:
            continue
        if row.get("dispatched_ts") is None:
            # Proof in the log: nothing was ever dispatched -> never left the box.
            out[row["attempt_id"]] = VOIDED
        else:
            # Wire state unknown -> fail closed.
            out[row["attempt_id"]] = EXPIRED_SPENT
    return out


def material_digest(principal: str, secret: str) -> str:
    ''
    import hashlib

    return hashlib.sha256(f"{principal}:{secret}".encode("utf-8")).hexdigest()


# Instrument flag policy (Boundary B contract). `-e` multiplies attempts
# beyond the explicit pair list; `-K` stops redo of failed-connection
# attempts; `-I` skips the 10s hydra.restore wait; fresh cwd per slice.
FORBIDDEN_FLAGS = ("-e", "-e nsr", "-e ns", "-e nr", "-e sr", "-e n", "-e s", "-e r")
REQUIRED_FLAGS = ("-C", "-K", "-I", "-f")


def check_flags(argv: list[str]) -> list[str]:
    """Return list of policy violations in an instrument argv.

    `-C` is the budget-binding flag (explicit pairs) — a missing `-C` is a
    violation, not a default; the adjacent list-file argument is checked
    when present.
    """
    problems: list[str] = []
    for tok in argv:
        if tok == "-e" or tok.startswith("-e"):
            problems.append(f"forbidden flag {tok!r} (attempt multiplier, measured 3x)")
    for flag in REQUIRED_FLAGS:
        if flag not in argv:
            problems.append(f"required flag {flag} missing")
    if "-C" in argv:
        i = argv.index("-C")
        if i + 1 >= len(argv):
            problems.append("-C present without a list file argument")
    return problems
