# BABAYAGA — OpenClaw host adapter (v0 spike)

Thin control plane for the authorized-only credential-attack engine. Every
tool shells out per call to the framed stdio adapter —
`babayaga adapter --request '<json>'` (babayaga/1; `engine/babayaga/adapter.py`)
— and gate semantics are never re-implemented in TypeScript. Same doctrine as
the opencode seat (`engine/host/opencode/`); the frame contract replaces the
opencode seat's argv subcommands.

## Tool surface

| Tool | Adapter operation | Default surface |
|---|---|---|
| `babayaga_doctor` | `doctor` | yes |
| `babayaga_status` | `status` | yes |
| `babayaga_roe_check` | `roe-check` (`options.roe_path`) | optional |
| `babayaga_seal_verify` | `seal-verify` (`options.target`) | optional |
| `babayaga_export_access` | `export-access` (`options.campaign`) | optional |

The optional three are marked `toolMetadata.<tool>.optional: true` in the
manifest (and registered with `{ optional: true }`), so the default
model-facing surface is just doctor/status until the operator allowlists the
rest. `run` (the attempt runner) and `amend` (the operator-attestation act)
are never tools; the adapter refuses them fail-closed at the protocol layer
(`operation_refused`).

Exit mapping (Boundary A: 0 ok / 2 refusal / 1 failure; 15 s spawn timeout →
SIGKILL, 1 MiB output cap):

- adapter exit 2, or an in-frame `operation_refused` → a normal tool result
  whose `details.status` is `"denied"`, with the refusal payload preserved.
  **Refusal is data** — it is never thrown. (OpenClaw's outcome grading treats
  a `denied` status as a failed call, which is intended: the model is told the
  gate refused.)
- exit 0 with an ok frame → the frame's `result` payload as the tool value
  (JSON text to the model, original value in `details`).
- anything else (exit 1/3/124/130, timeout, spawn/parse failure) → throw,
  i.e. a tool-call error.

## Gates (two layers, honestly labeled)

Both layers run the same word-form check (`gates.ts`) over the `command` of
`exec` tool calls and deny raw `hydra|medusa|ncrack|patator` invocation:

- **(a) trusted tool policy** — `api.registerTrustedToolPolicy`, id
  `raw-instrument-deny`, declared in `contracts.trustedToolPolicies`. This is
  the host-trusted pre-tool tier: it runs before ordinary hooks and the host
  fails closed if it throws. Still a word-match gate.
- **(b) `before_tool_call` tripwire** — the ordinary hook, matching the
  opencode seat's `tool.execute.before` deny.

**Tripwire, not a boundary.** Neither layer catches variable indirection
(`h="hy";$h$d`), base64/eval obfuscation, or scripts whose *content* holds the
call (see `DOCUMENTED_BYPASSES` in `gates.ts`). The boundary is the engine:
ROE-or-refuse, budget-or-refuse, ledger-or-refuse, and `doctor` fails closed
while the instrument resolves on the session PATH.

## Standing doctrine

- **The plugin never starts work by being loaded.** Registration only declares
  tools and gates; no spawn happens until a tool is invoked.
  `activation.onStartup: true` means the *code* loads at Gateway startup, not
  that anything runs.
- **The runner is operator-side only.** `babayaga run` executes from the
  operator's shell, never through any host seat.
- Lab-only v0: the engine engages loopback fixtures only (`LAB_ONLY`).

## Configuration

One optional config key, `babayaga_bin` (validated by the manifest's strict
`configSchema`). Resolution order per the internal design notes: `BABAYAGA_BIN` env >
`plugins.entries.babayaga.config.babayaga_bin` > `babayaga` on PATH.

```json
{
  "plugins": {
    "entries": {
      "babayaga": { "enabled": true, "config": { "babayaga_bin": "/usr/local/bin/babayaga" } }
    }
  }
}
```

## Install

From a checkout of this repo (source entry, no build step):

```bash
openclaw plugins install --link /path/to/babayaga/engine/host/openclaw --force
openclaw plugins enable babayaga --accept-capabilities
```

`--link` creates a managed install record loaded from the source directory;
`--force` acknowledges installing from a local source, and enabling records
consent to the declared capabilities (the trusted tool policy). The unmanaged
alternative is a bare load path in `openclaw.json`:

```json5
{ plugins: { load: { paths: ["/path/to/babayaga/engine/host/openclaw/index.ts"] } } }
```

Note the difference: `plugins.load.paths` entries cannot persist capability
acceptance, so the trusted-policy consent prompt reappears; the managed
`--link` install is the recommended shape.

## Reload

After editing plugin code or the manifest:

```bash
openclaw plugins reload babayaga
```

Reload refreshes the backend plugin in place (hybrid mode is the default) and
reports the applied Gateway generation; changed declared capabilities may
require re-review before it proceeds. `plugins.load.paths` discoveries use the
same reload action. Reload does not reinstall dependencies — this package has
none.

## Compatibility

The Plugin SDK is experimental; this package is pinned to the host it was
verified against: `openclaw.compat.pluginApi: ">=2026.9.7"`,
`minGatewayVersion: "2026.9.7"` (checkout HEAD f81d71f). Shapes verified
against that checkout: `defineToolPlugin` + metadata symbol
(`src/plugin-sdk/tool-plugin.ts`), `api.registerTool` / `registerTrustedToolPolicy` /
`on` (`src/plugins/plugin-api.types.ts`), trusted-policy decision shape
(`src/plugins/host-hooks.ts`, `src/plugins/trusted-tool-policy.ts`), hook
matcher semantics (`src/plugins/tool-hook-matcher.ts`), manifest loader
requirements (`src/plugins/manifest.ts`).

**Zero runtime dependencies, zero `node_modules`** (standing rule). Parameter
and config schemas are hand-written JSON Schema: typebox 1.3.x schemas are
plain JSON Schema objects and the host compiles them structurally
(`typebox/compile`), so the SDK's `TSchema` contract is satisfied without a
runtime typebox import (type-only import, stripped at load). Verified against
typebox 1.3.34 in the pinned checkout.

## Tests and validation

From `engine/`: `make plugin-check-openclaw` (bun test). The suite uses a stub
`babayaga` adapter (bash, canned babayaga/1 frames + Boundary A exit codes)
and covers: exit-contract translation including refusal-as-data, the five-tool
surface and optional split, trusted-policy deny on `hydra …` exec argvs,
tripwire behavior, and documented-bypass acceptance. Registration tests drive
the real entry with a faithful miniature of the SDK's tool-plugin module
(same `Symbol.for` metadata key), and a manifest test cross-checks
`contracts.tools` / `trustedToolPolicies` / `toolMetadata` against the
registered surface.

When an `openclaw` binary is on PATH, the suite additionally runs the real
`openclaw plugins validate --root . --entry ./index.ts` (offline). Passing
means: the manifest loads under the host's manifest loader, the entry exposes
tool-plugin authoring metadata, generated manifest fields are not stale, and
`contracts.tools` matches the declared tool names. Last run: **pass**
(`Plugin babayaga is valid.`, host 2026.9.7, f81d71f).

Gaps: `@openclaw/plugin-inspector` is not installed on this machine (not run).
Runtime acceptance beyond authoring-time validation — a live Gateway session
with the plugin enabled and tools invoked — has **not** been exercised; the
spike's acceptance is `plugins validate` plus the bun suite.
