# HOSTS.md — adapter inventory

| Seat | Adapter | Path | Status |
|---|---|---|---|
| opencode | `babayaga` control plane | `engine/host/opencode/babayaga.ts` | shipped v0 |
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
acceptance is limited to what was actually validated: `openclaw plugins
validate` green against host 2026.9.7 (f81d71f) plus the bun suite; no live
Gateway session was exercised. The SDK is experimental — compat pinned to
`>=2026.9.7`.
