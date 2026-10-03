"Attempt lifecycle state machine (pure).\n\nreserved -> dispatched -> reconciled{per-kind vocabulary}\nreserved -> voided                      (lease expired, provably never dispatched)\ndispatched -> expired_spent             (lease expired, wire state unknown)\n\nEvidence-first ordering is enforced by the ledger, not here: the dispatch\nevent is written BEFORE the instrument spawns, so reserved->reconciled\nwithout a dispatch is always an illegal transition.\n\n    guess -> valid | invalid | locked | error\n    exec  -> effect_confirmed | effect_denied | locked | error\n\n`detected` is deliberately in NO vocabulary (CATEGORY.md errata 18: moral\nhazard + wrong layer) — detection is an operational signal recorded as a\ndetection.annotated event under the ROE's on_detect policy, never a\nreconcile outcome.\n"

from __future__ import annotations

from .schema import OUTCOMES_BY_KIND

STATES = ("reserved", "dispatched", "reconciled", "voided", "expired_spent")
TERMINAL = ("reconciled", "voided", "expired_spent")

_TRANSITIONS: dict[str, set[str]] = {
    "reserved": {"dispatched", "voided"},
    "dispatched": {"reconciled", "expired_spent"},
    "reconciled": set(),
    "voided": set(),
    "expired_spent": set(),
}


class IllegalTransition(Exception):
    """A transition the ledger refuses. Surfaced through the ledger it is a
    LedgerRefusal (exit 2: the request itself is illegal); hit directly as a
    pure function it is a programming error."""


def transition(state: str, event: str, outcome: str | None = None,
               action_kind: str = "guess") -> str:
    if state not in STATES:
        raise IllegalTransition(f"unknown state {state!r}")
    target = {
        "dispatch": "dispatched",
        "reconcile": "reconciled",
        "void": "voided",
        "expire_spent": "expired_spent",
    }.get(event)
    if target is None:
        raise IllegalTransition(f"unknown event {event!r}")
    if target == "reconciled":
        vocabulary = OUTCOMES_BY_KIND.get(action_kind)
        if vocabulary is None:
            raise IllegalTransition(f"unknown action_kind {action_kind!r}")
        if outcome not in vocabulary:
            raise IllegalTransition(
                f"{action_kind} reconcile requires an outcome in {vocabulary}, "
                f"got {outcome!r}")
    if target not in _TRANSITIONS[state]:
        raise IllegalTransition(f"{state} -> {target} is not legal")
    return target
