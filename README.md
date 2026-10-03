# BABAYAGA

Authorized-only credential-attack engine, driven as an opencode plugin.
Engagement mode: the engine engages only what the ROE covers, enforced
in code (`roe.check_target` refuses the rest; the v0 loopback-only flag
`engine/core/__init__.py::LAB_ONLY` is off since 2026-10-03).
An independent research project — the thesis stands alone in GATE.md.

## Quickstart

```sh
cd engine
make install       # uv venv + editable install (babayaga CLI)
babayaga doctor    # environment gates; fails closed while hydra is unanchored
babayaga run --lab # the gated demo: ROE -> budget -> ledger -> hydra -> seal
```

The demo drives THC-Hydra against the loopback fixture in `engine/lab/`
(synthetic material only). An anchored hydra build is required — the session
PATH is never a resolver; `babayaga doctor` reports the anchor state and the
accepted version range lives in `engine/scripts/hydra.json`.

The QA gates (`make test`, `make plugin-check`)
run from the full source tree; their suites are not part of this export and
SKIP here (see `engine/PUBLISHED_FROM`).

The seat plugin (`engine/scripts/babayaga.ts`) is a thin
control plane over the CLI: register it with opencode as a plugin (copy or
link it into opencode's plugin directory). It exposes doctor / status /
roe-check plus a tripwire deny on raw hydra-class credential-attack
invocation (the C-instrument class; other instruments are out of the
tripwire's scope by design); the attempt runner is never a plugin tool.

## Repo map

- `GATE.md` — identity: the question BABAYAGA asks
- `CATEGORY.md` — product-category survey and positioning
- `RESEARCH.md` — technical research single source
- `HOSTS.md` — the seat plugin surface
- `INSTRUMENTS.md` — upstream instrument citation/provenance map
- `EVOLUTION.md` — self-evolution doctrine
- `AGENTS.md` — contributor rules
- `engine/core/` — engine core (roe/budget/ledger/run/executor/seal/parsers) + `PROVENANCE.md` (review-critical safety modules)
- `engine/rules/` — rule corpus (throttle flags REQUIRED); `rulecheck.py` validates
- `engine/scripts/` — the seat plugin (thin control plane) + instrument manifests (flat `*.json`) + `publish.py` (the export gate, never shipped)
- `engine/lab/` — loopback fixtures for the demo path (`run --lab`)

## Warning

This engine's whole point is refusal: without a valid ROE, budget, and
ledger, nothing spends. Do not weaken a gate to make a demo pass.
