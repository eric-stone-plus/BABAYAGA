# HOSTS.md — adapter inventory

| Seat | Adapter | Path | Status |
|---|---|---|---|
| opencode | `babayaga` control plane | `engine/host/opencode/babayaga.ts` | shipped v0; live seat acceptance 2026-10-02 (host 0.0.0-main-202610011151, throwaway `OPENCODE_CONFIG_DIR` seat): 5 tools registered and fired against the real CLI with payload parity to direct `babayaga` calls, tripwire blocked `hydra`/`/usr/bin/hydra`/`hydra;id` shapes while `echo hi` ran; two live-host contract defects found and fixed (`c90afb7`: `ToolResult.output` envelope, JSON-Schema args); opt-in real-CLI plugin tier (`BABAYAGA_IT=1`) now covers doctor/status/roe-check and refusal in an isolated `BABAYAGA_HOME`; runtime seams live in `babayaga-runtime.ts`, so the registration module exports only the plugin factory and no longer triggers `getLegacyPlugins` factory-probe noise |
| openclaw | `babayaga` control plane | `engine/host/openclaw/index.ts` | shipped spike |

Update trigger: an adapter lands, changes scope, or drops.

The adapter is a thin control plane: every tool shells out to the gated
`babayaga` CLI, and gate semantics are never re-implemented in TypeScript.
Registration is a host-side move — copy or link the adapter into opencode's
plugin directory; the attempt runner is never exposed as a plugin tool.

The stdio adapter boundary (`engine/babayaga/adapter.py`, protocol babayaga/1)
landed 2026-10-01 and is the openclaw seat's transport: its tools shell out to
`babayaga adapter --request '<json>'` (one frame in, one frame out; ops: the
ops-safe read set, with run/amend refused at the protocol layer), instead of
the opencode seat's argv subcommands. The openclaw spike adds two
honestly-labeled gate layers — a trusted tool policy
(`contracts.trustedToolPolicies`, id `raw-instrument-deny`) and the ordinary
`before_tool_call` tripwire — both tripwires, never boundaries. Runtime
acceptance: `openclaw plugins validate` green against host 2026.9.7 (3dd806e),
the bun suite (48 pass/0 fail with the `BABAYAGA_IT=1` real-CLI tier), and a
live Gateway session exercised 2026-10-01 in isolated /tmp state — link
install, five-tool catalog with the optional split, real CLI payloads through
`tools.invoke` (including refusal-as-data on a bad ROE path), the exec
tripwire live-fired in a mock-provider-driven agent turn (`hydra …` blocked
with the gate's blockReason, `echo hi` executed), and a reload/disable/enable
cycle; details in `engine/host/openclaw/README.md` (Gaps). The SDK is
experimental — compat pinned to `>=2026.9.7`.

## Seat facts

Per-host facts (egress lanes, instrument homes, anchored builds) are
measured at engagement setup and stay with the operator's own notes —
this inventory is host-independent by design.
