# rules/ — credential-attack rule corpus (v1)

One JSON object per file, laid out in pack directories. Validate with
`python -m babayaga.rulecheck engine/rules` (exit 2 on any refusal,
exit 0 when clean). `rules.retired/` starts when the first rule is
retired; retirement is a move, never a delete (the internal design notes).

## The B10 inversion

The throttle IS the safety case in a credential-attack engine: **a rule
without explicit throttle flags is a refusal, not a default**.
`babayaga.rulecheck` enforces this at corpus load; there is no quiet
cadence.

## Language

**Rule**:
A closed-shape JSON object binding one credential-attack shape to its
safety limits. Rules carry no credential material (the internal design notes);
principals and pairs come from the ROE and the pair list.

**Pack**:
The rule's intent family, from the closed set `spray` (password-outer
across principals, the shape `budget.plan_slice` emits), `stuff` (replay
of already-known pairs, one shot each), `brute` (multi-password pressure
on a narrow principal set).
_Avoid_: category, type, kind

**Match**:
The conditions under which a rule applies. v1 is exactly one key,
`service`, a hydra module name from the closed vocabulary (`http-get`,
the lab demo path). An unknown service refuses; it is never guessed.

**Throttle**:
The rule's pace discipline, REQUIRED: `instrument_flags` must pin hydra
`-t` (parallel connects, 1–4) and `slice_cadence_seconds` must declare the
minimum spacing between spray slices. The `-e` family (attempt multiplier)
is forbidden, and `-C`/`-K`/`-I`/`-f` are runner-owned (budget.py); a rule
re-declaring them refuses.

**Budget ceiling**:
`budget.per_principal_per_run_max`, int in [1,100] (NIST SP 800-63B-4
anchor, the same ceiling `roe.validate` enforces). The ROE may tighten it
further per engagement, never loosen it.

**Lockout-abort threshold**:
`lockout_abort_after`, the count of `locked` outcomes that halts the run
against the target. Fail closed: v1 rules abort on the first one.

**Refusal rationale**:
`refusal_rationale`, the sentence recorded when this rule's limits force a
refusal. Every refusal path is explained as data, not improvised at the
call site.

## v1 shape (closed at every level; unknown keys refuse)

```json
{
  "id": "R-CRED-SPRAY-001",
  "name": "lab http-get spray, serial slices at 30s cadence",
  "pack": "spray",
  "match": {"service": "http-get"},
  "throttle": {"instrument_flags": ["-t", "1"], "slice_cadence_seconds": 30},
  "budget": {"per_principal_per_run_max": 3},
  "lockout_abort_after": 1,
  "refusal_rationale": "..."
}
```

`id` is `R-CRED-<PACK>-<NNN>` and the pack segment must agree with the
`pack` field. The three spray rules are cadence tiers of one shape
(30s / 300s / reset-window 900s); STUFF-001 is the single-shot pair
replay; BRUTE-001 is the high-risk narrow shape at the slowest cadence.
