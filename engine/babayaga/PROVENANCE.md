# Review-critical safety modules — engine/babayaga/

This registry names the modules that ARE the engine's safety case. They
were authored natively at the v0 seed and are ordinary source in every way
but one: a defect in them is not a bug, it is an authorization- or
hygiene-boundary failure. That is why they are registered, and why the
rule below binds them harder than the rest of the tree.

| Module | Wired | Why it is review-critical |
|---|---|---|
| `scope.py` | **dormant** | The scope-matching library (multi-homed names, out-wins-in, bind_ip). Nothing calls it yet — see the row below for the gate that does run. A wrong match here would mean engaging a target the operator never authorized. |
| `roe.py` | live | `check_target` is the actual target gate: a target the ROE does not cover is refused at the run boundary. A defect here is the one failure the whole gate exists to prevent. |
| `egress.py` | live | The egress policy: declared mode, the launch self-attestation gate, exit-identity freshness. A fail-open here puts the operator's own uplink in target logs. |
| `opsec.py` | **dormant** | WAF detection, canary guard, per-origin cooldowns. A defect here provokes defender detection or escapes rate discipline mid-campaign. |
| `cmd.py` | **dormant** | Renders rule command templates. Owns the never-a-shell and credentials-never-in-argv invariants; a defect here is injection into, or secret leakage through, a spawned command line. The live path builds argv directly (`run.py`) under `budget.check_flags`. |
| `confidence.py` | **dormant** | The log-odds evidence model. A defect would inflate the `valid` verdicts downstream consumers trust. The live verdict producer is `parsers/hydra_stdout.py`. |
| `secret_transport.py` | **dormant** | Credential transports (memfd header files, in-process argv fill). The live pair transport is `executor.py`'s O_TMPFILE path (the internal doctrine). |
| `run.py` | live | The single-slice gated executor: window, egress gate, target gate, budget plan, reserve/dispatch ordering. A reorder here is a spend before a gate. |
| `budget.py` | live | Flag policy and per-principal spend planning; material digests. A defect lets forbidden argv reach the wire or overspend a grant. |
| `executor.py` | live | Anchored-instrument spawn and the O_TMPFILE pair-list transport (the internal doctrine). A defect writes plaintext credential material to disk or spawns off-anchor. |
| `parsers/hydra_stdout.py` | live | The producer of every `valid` verdict; adversarial-output discipline. A defect fabricates evidence the ledger, seal and export all trust. |
| `ledger.py` | live | The state machine, event log and per-row ROE stamps. A defect lets a spend bypass a transition or forges evidence. |
| `seal.py` | live | The attestation manifest and verify gate. A defect launders inconsistent evidence into a "sealed" campaign. |

## The rule

Changing any registered module requires an explicit operator sign-off note
in the commit message — what changed, why the invariant above still holds.
A drive-by edit inside a larger change does not count: if the diff touches
a registered row, the message says so on its own line. Reviewers reject
registered-module diffs without the note, whatever the tests say.

Modules not listed here change under the ordinary gates (make test plus
the adapter suites). Registering a new module is itself a sign-off change.
