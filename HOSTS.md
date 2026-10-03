# HOSTS.md — the seat plugin surface

| Seat | Surface | Path | Status |
|---|---|---|---|
| opencode | `babayaga` control plane | `engine/scripts/babayaga.ts` | shipped v0; live seat acceptance 2026-10-02 (host 0.0.0-main-202610011151, throwaway `OPENCODE_CONFIG_DIR` seat): 5 tools registered and fired against the real CLI with payload parity to direct `babayaga` calls, tripwire blocked `hydra`/`/usr/bin/hydra`/`hydra;id` shapes while `echo hi` ran; two live-host contract defects found and fixed (`c90afb7`: `ToolResult.output` envelope, JSON-Schema args); opt-in real-CLI plugin tier (`BABAYAGA_IT=1`) now covers doctor/status/roe-check and refusal in an isolated `BABAYAGA_HOME`; runtime seams live in `babayaga-runtime.ts`, so the registration module exports only the plugin factory and no longer triggers `getLegacyPlugins` factory-probe noise. Restructured 2026-10-04: the engine is a pure plugin — the host/ adapter layer is gone, the plugin ships flat in `engine/scripts/` |

Update trigger: the plugin lands, changes scope, or drops.

The plugin is a thin control plane: every tool shells out to the gated
`babayaga` CLI, and gate semantics are never re-implemented in TypeScript.
Registration is a host-side move — copy or link the plugin into opencode's
plugin directory; the attempt runner is never exposed as a plugin tool.

The engine is a pure-plugin product (2026-10-04): the multi-seat `host/`
adapter layer is gone. The openclaw seat shipped as a spike and was removed
with it. Its transport — the framed stdio boundary in `engine/core/adapter.py`,
protocol babayaga/1 — stays as the engine's host protocol: `babayaga adapter
--request '<json>'` is one frame in, one frame out (ops-safe read set, with
run/amend refused at the protocol layer). The removal is recorded in the
status cell above and in git history.

## Seat facts

Per-host facts (egress lanes, instrument homes, anchored builds) are
measured at engagement setup and stay with the operator's own notes —
this inventory is host-independent by design.
