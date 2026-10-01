/**
 * BABAYAGA openclaw plugin entry — thin control plane (v0 spike).
 *
 * Doctrine (the internal design notes, mirrored from engine/host/opencode/babayaga.ts):
 *   - every tool SHELS OUT to the gated `babayaga` CLI — here through the
 *     babayaga/1 framed adapter (`babayaga adapter --request '<json>'`);
 *     gate semantics are never re-implemented in TS;
 *   - ops-safe read surface only: doctor, status, roe-check, seal-verify,
 *     export-access; the attempt runner (`babayaga run`) and the operator-
 *     attestation act (`babayaga amend`) are NEVER plugin tools — the adapter
 *     itself refuses them fail-closed at the protocol layer;
 *   - two honestly-labeled gate layers (gates.ts header): a trusted pre-tool
 *     policy plus an ordinary before_tool_call tripwire — tripwires, not
 *     boundaries;
 *   - the plugin never starts work by being loaded: registration only
 *     declares tools and gates; nothing spawns until a tool is invoked.
 *
 * Entry shape: defineToolPlugin owns the five tool registrations and the
 * static authoring metadata `openclaw plugins build/validate` reads; the
 * exported entry reuses that register() and adds the two gate layers,
 * carrying the tool-plugin metadata symbol over so the authoring commands
 * still recognize the entry. Verified against OpenClaw 2026.9.7 (f81d71f):
 * src/plugin-sdk/tool-plugin.ts (defineToolPlugin, metadata symbol),
 * src/plugins/plugin-api.types.ts (registerTool / registerTrustedToolPolicy /
 * on), src/plugins/tool-hook-matcher.ts (canonical tool-id matcher).
 */

import { defineToolPlugin, toolPluginMetadataSymbol } from "openclaw/plugin-sdk/tool-plugin";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type { TSchema } from "typebox";

import { buildTrustedPolicy, EXEC_TOOL_MATCHER, tripwireBeforeToolCall } from "./gates.ts";
import { buildTools } from "./tools.ts";

// Hand-written JSON Schema (see tools.ts header: no runtime typebox import).
const configSchema = {
  type: "object",
  properties: {
    babayaga_bin: {
      type: "string",
      description:
        "Path to the gated `babayaga` CLI. Precedence: BABAYAGA_BIN env > " +
        "this config key > `babayaga` on PATH (the internal design notes).",
    },
  },
  additionalProperties: false,
} as TSchema;

const toolEntry = defineToolPlugin({
  id: "babayaga",
  name: "BABAYAGA",
  description:
    "Authorized-only credential-attack engine (lab-only v0): ops-safe read " +
    "surface over the babayaga/1 adapter. The attempt runner is operator-side " +
    "only and is never exposed as a tool.",
  activation: { onStartup: true },
  configSchema,
  tools: (tool) => buildTools().map((definition) => tool(definition)),
});

const entry = {
  ...toolEntry,
  register(api: OpenClawPluginApi) {
    toolEntry.register(api);
    // Gate layer (a): trusted pre-tool policy. Installed-plugin policy ids
    // must be declared in contracts.trustedToolPolicies (see manifest).
    api.registerTrustedToolPolicy(buildTrustedPolicy());
    // Gate layer (b): the ordinary before_tool_call tripwire.
    api.on("before_tool_call", tripwireBeforeToolCall, { matcher: [...EXEC_TOOL_MATCHER] });
  },
};

// Preserve the static authoring metadata across the register() wrap so
// `openclaw plugins build` / `plugins validate` still see a tool-plugin entry.
Object.defineProperty(entry, toolPluginMetadataSymbol, {
  value: toolEntry[toolPluginMetadataSymbol],
  enumerable: false,
});

export default entry;
