# Review-critical safety modules — engine/babayaga/

This registry names the modules that ARE the engine's safety case. They
were authored natively at the v0 seed and are ordinary source in every way
but one: a defect in them is not a bug, it is an authorization- or
hygiene-boundary failure. That is why they are registered, and why the
rule below binds them harder than the rest of the tree.

| Module | Why it is review-critical |
|---|---|
| `scope.py` | Decides what is in and out of scope. A wrong match here means engaging a target the operator never authorized — the one failure the whole gate exists to prevent. |
| `egress.py` | The egress policy: declared mode, the launch self-attestation gate, exit-identity freshness. A fail-open here puts the operator's own uplink in target logs. |
| `opsec.py` | WAF detection, canary guard, per-origin cooldowns. A defect here provokes defender detection or escapes rate discipline mid-campaign. |
| `cmd.py` | Renders rule command templates. Owns the never-a-shell and credentials-never-in-argv invariants; a defect here is injection into, or secret leakage through, a spawned command line. |
| `confidence.py` | The log-odds evidence model. A defect inflates the `valid` verdicts that the budget gate, the seal and the access export downstream all trust. |
| `secret_transport.py` | Credential transports (memfd header files, in-process argv fill). A defect here writes plaintext credential material onto a captured command line or disk. |

## The rule

Changing any registered module requires an explicit operator sign-off note
in the commit message — what changed, why the invariant above still holds.
A drive-by edit inside a larger change does not count: if the diff touches
a registered row, the message says so on its own line. Reviewers reject
registered-module diffs without the note, whatever the tests say.

Modules not listed here change under the ordinary gates (make test plus
the adapter suites). Registering a new module is itself a sign-off change.
