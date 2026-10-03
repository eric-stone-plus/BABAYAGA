# AGENTS.md — BABAYAGA contributor rules

BABAYAGA is a public research and specification repository: an
authorized-only credential-attack engine (ROE-gated engagement mode).
Committed work
must be reproducible from the repository and free of credentials, personal
machine paths, private endpoints, engagement evidence, or host-specific
infrastructure.

Prose — documentation, docstrings, comments, identifiers — is English.
Narrow exceptions are functional data, not prose, and must stay in the
language they carry meaning in:

- Detection signatures that match a localized response, e.g. the WAF
  block-page titles and canary path tokens in `engine/core/opsec.py`.
  Translating them silently disables the detection.
- Instrument output grammar, e.g. the hydra banner and summary shapes
  parsed in `engine/core/parsers/hydra_stdout.py`.

Never encode in a comment: an operator or deployment hostname, a
jurisdiction or network-posture detail, a real target or engagement
observation, an internal incident or round identifier, or a reference to a
document that is not in this tree. Describe the invariant the code
enforces, not the engagement that motivated it.

## The refusal doctrine

The engine's whole point is refusal: without a valid ROE, budget, and
ledger, nothing spends.

- Do not weaken a gate to make a demo pass. A refusal is the product
  working; routing around one is a defect, not a workaround.
- The engine engages only targets the ROE covers (`roe.check_target`
  refuses the rest). The v0 loopback-only flag
  (`engine/core/__init__.py::LAB_ONLY`) is off — engagement mode is
  the doctrine and the ROE is the gate; never bypass it.
- The attempt runner (`babayaga run`) is never a plugin tool. The seat
  plugin exposes the ops-safe surface (doctor / status / roe-check) only.
- The plugin's deny hook is a tripwire, not a boundary — its documented
  bypasses live in `engine/scripts/gates.ts`; never describe
  it as enforcement. The boundary is the engine.
- Lab fixtures carry obviously-synthetic credential material only. Real
  credential material never enters this tree in any form; the ledger and
  the logs carry digests, never plaintext.

## Contribution rules

- Instruments are cited, never vendored, linked, or relicensed
  (INSTRUMENTS.md, NOTICE): the engine drives external binaries through
  argv and consumes their output streams.
- The review-critical safety modules listed in
  `engine/core/PROVENANCE.md` are the engine's safety case. Changing one
  requires an explicit operator sign-off note in the commit message — what
  changed, and why the module's registered invariant still holds.
- A rule without explicit throttle flags is a corpus defect, not a default
  cadence (`engine/rules/README.md`); `core.rulecheck` refuses it.
- One contributor identity. Every commit carries the repository owner's
  GitHub-linked Git identity as both author and committer. Do not commit
  under an agent, bot or tool identity, and do not add co-author or
  generated-with trailers: the history records the work, not which
  assistant held the pen.
