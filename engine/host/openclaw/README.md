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
  a `denied` status as a failed call: `isToolResultError` lists `denied` among
  the failure statuses and fails the call unless `ok`/`success` is explicitly
  `true` (`src/agents/tool-result-error.ts:91-130`), applied to every
  normally-returned result at `src/agents/harness/tool-invocation.ts:87`.
  Intended here: the model is told the gate refused.)
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
openclaw plugins install --link /path/to/babayaga/engine/host/openclaw --force --accept-capabilities
```

`--link` creates a managed install record loaded from the source directory;
`--force` acknowledges installing from a local source. Measured on host
2026.9.7 (3dd806e), 2026-10-01: install **refuses** without
`--accept-capabilities` ("Plugin "babayaga" requires capability consent. The
plugin was not installed.") — the consent flag belongs on the install command;
with it, the plugin lands enabled, no separate `plugins enable` pass needed.
The unmanaged alternative is a bare load path in `openclaw.json`:

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
`minGatewayVersion: "2026.9.7"` (checkout HEAD 3dd806e). Shapes verified
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

`integration.test.ts` is the optional real-CLI tier (the Wave-4 gap note in
the internal design notes): skipped unless `BABAYAGA_IT=1` AND a real CLI resolves
(`BABAYAGA_BIN` env, else `babayaga` on PATH — the the internal doctrine resolution); opting in
without a resolvable CLI fails loudly. Opted in, its six tests drive the real
engine through the framed adapter end to end — doctor / status / roe-check ok
payloads, a roe-check refusal as `denied` data (never thrown), and `run` /
`amend` refused at the protocol layer (`operation_refused`) — against a tmp
`BABAYAGA_HOME` and the shipped loopback ROE example
(`engine/babayaga/defaults/roe.example.json`; LAB_ONLY holds, no credential
material). Run it with `BABAYAGA_IT=1 make plugin-check-openclaw`. Last
opt-in run: **pass** (48 pass / 0 fail suite-wide, real `babayaga` 0.0.1,
2026-10-01).

When an `openclaw` binary is on PATH, the suite additionally runs the real
`openclaw plugins validate --root . --entry ./index.ts` (offline). Passing
means: the manifest loads under the host's manifest loader, the entry exposes
tool-plugin authoring metadata, generated manifest fields are not stale, and
`contracts.tools` matches the declared tool names. Last run: **pass**
(`Plugin babayaga is valid.`, host 2026.9.7 (3dd806e), 2026-10-01).

Host-hook conformance is exercised by `tests/verify-hook-contract.mjs`. It
copies this adapter (or a supplied comparison adapter) into a private temporary
workspace, loads the real SDK test runtime from an OpenClaw checkout, and runs
eight semantic cases: exact block reason, terminal ordering, `exec` matcher
scope, no invented approval on allow, approval payload/parameter snapshots,
veto precedence, trusted-policy-before-hook ordering with zero tool execution,
and one allowed wrapped-tool execution. Both adapters pass **8/8** on the
2026.9.7 checkout (2026-10-02). The optional ninth case runs the pinned
`@openclaw/plugin-inspector@0.3.26` retained callback probe for both allow and
deny; it passes **9/9** for each adapter. Inspector synthetic output is a
callback shape check only: it does not execute tools, contact a provider, or
prove host terminal/approval semantics. Inspector 0.3.26 also does not map
this genuine hook evidence into its `before-tool-call-probe` runtime coverage
counter, so that P1 remains an honest reporting limitation rather than a
product gap.

Run the host conformance tier with an isolated shell (the command does not
read the operator shell profile):

```bash
bash --noprofile --norc -c \
  'node tests/verify-hook-contract.mjs /path/to/openclaw'
bash --noprofile --norc -c \
  'node tests/verify-hook-contract.mjs /path/to/openclaw /path/to/other/engine/host/openclaw /path/to/@openclaw/plugin-inspector'
```

Static inspector `check --plugin-root <adapter> --openclaw <checkout>` also
passed for both adapters with zero breakages, warnings, or compatibility
gaps. The inspector's separate `inspector-gap` class remains: the hook P1
above and the TypeScript source-entrypoint P2 (plus the comparison adapter's dependency-install
P2). These describe inspector coverage limits; they are not silently erased
from the acceptance result.

The runner owns its temporary directory, process group, and child deadline;
it does not touch Gateway state, the user shell profile, or engine campaign
data. The optional inspector path is pinned to 0.3.26 and is intentionally
kept outside the plugin package's runtime dependencies.

Live-Gateway acceptance: **exercised 2026-10-01** against host 2026.9.7
(3dd806e), in a throwaway isolated state (`OPENCLAW_STATE_DIR` /
`OPENCLAW_CONFIG_PATH` under /tmp, non-default port, tmp `BABAYAGA_HOME`):

- `plugins install --link --force --accept-capabilities` into the isolated
  config; Gateway startup logged the plugin loaded (19 plugins, `babayaga`
  among them).
- `tools.catalog` (operator RPC) lists all five tools with the declared
  optional split (`optional: true` on roe_check/seal_verify/export_access).
- `tools.invoke` RPC drove `babayaga_doctor` / `babayaga_status` /
  `babayaga_roe_check` against the real CLI: ok payloads (doctor `status:
  "ok"`, `lab_only: true`; roe-check `valid: true` with the canonical digest
  of `engine/babayaga/defaults/roe.example.json`), and a nonexistent ROE path
  returned `details.status: "denied"` (exit 2) as data — never thrown. The
  operator RPC grants a requested plugin tool by name
  (`gatewayRequestedTools`, src/gateway/tools-invoke-shared.ts:258), so the
  optional allowlist gate is asserted at catalog/metadata + suite level, not
  through this path.
- Tripwire live-fired through real agent turns (a scripted loopback
  OpenAI-compatible provider driving the embedded runtime — no production
  model involved): `exec hydra -l x -p y 127.0.0.1 ssh` was blocked, the tool
  result carrying the plugin's `blockReason` verbatim; `exec echo hi` ran and
  returned `hi`. The host runs trusted policies before ordinary hooks and
  treats a trusted block as terminal
  (src/agents/agent-tools.before-tool-call.policy.ts:250-297), so the layer
  that fired is (a) `raw-instrument-deny`; both layers emit the same
  `gateEvent()` text.
- `plugins reload babayaga` applied in place (generation increments);
  disable/enable cycled the tool surface (invocations `not_found` while
  disabled, real payloads again after enable).
- The session's first doctor call exposed a spike defect — `runBounded` used
  `Bun.spawn`, which does not exist under the Node-hosted Gateway — fixed by
  moving the spawn to `node:child_process` (works under both runtimes); gates
  green after the fix (`make plugin-check-openclaw` 48 pass/0 fail with
  `BABAYAGA_IT=1`; `make test` 286 pass).

Follow-up live acceptance on **2026-10-02**, host checkout `98aa688c634`:

- A real `xiaomi-token-plan/mimo-v2.6-pro` turn in session
  `agent:main:real-gap` selected `babayaga_doctor` with empty arguments. Its
  persisted transcript pairs the model tool call with an `isError: false`
  result (`details.status: "ok"`, `lab_only: true`, all six checks passing)
  and a subsequent normal model completion. Gateway state/config were
  isolated; this read-only doctor call used the existing engine home.
- With both engines installed, `tools.effective` reported
  `checked: "live-session"` for both real-model sessions. The default surface
  contained this engine's doctor/status and the other engine's status/seal_verify. Explicit
  `tools.alsoAllow` added all six optional tools, yielding all ten. This checks
  the model-facing optional split without invoking any operation tool.

These close the earlier real-model, optional-surface, and inspector execution
gaps for the tested host/model. They do not claim compatibility with every
provider or turn the word-match tripwires into engine safety boundaries.
