/**
 * BABAYAGA opencode plugin — thin control plane (v0).
 *
 * Doctrine (adjudicated in CATEGORY.md):
 *   - every tool SHELS OUT to the gated `babayaga` CLI; execution stays in
 *     the OS layer; the plugin never re-implements gate semantics;
 *   - ops-safe, read-only-ish surface only: doctor, status, roe-check,
 *     seal-verify, export-access; the attempt runner is NEVER a plugin tool;
 *   - args are JSON-Schema fragments ({type, description}) => the host's
 *     legacyJsonSchema makes every key required and applies NO runtime
 *     validation (Schema.Unknown) — validate inside execute. Bare strings
 *     as arg values are SILENTLY DROPPED from the model-facing schema
 *     (measured 2026-10-02: the model saw no roe_path parameter) — never
 *     use them;
 *   - execute() must satisfy the host ToolResult contract: an `output: string`
 *     field is REQUIRED (registry.ts fromPlugin feeds it to truncate.output,
 *     which calls text.split — a missing `output` kills every call with
 *     "undefined is not an object (evaluating 'c.split')", measured
 *     2026-10-02). envelope() keeps the structured outcome alongside for
 *     tests and programmatic consumers;
 *   - type-only imports are stripped by Bun: no package.json, no node_modules;
 *   - plugins load at opencode startup only — restart after edits.
 *
 * Verified against opencode 0.0.0-main-202609280832; Hooks-shape corrected
 * 2026-10-01 (`tool` singular key; before-hook args arrive on the mutable
 * output parameter) — the earlier revision silently registered nothing.
 * ToolResult/args contract corrected 2026-10-02 against
 * 0.0.0-main-202610011151 (live seat acceptance): tools registered and
 * fired but every execute() died in truncate.output (no `output` string)
 * and arg keys never reached the model (bare-string arg values dropped).
 */

import type { Plugin } from "@opencode-ai/plugin";

import { checkCommand } from "./gates.ts";

import { buildTools } from "./babayaga-runtime.ts";

export default function babayaga(): Plugin {
  return {
    // Hooks key is `tool` (singular) — `tools` never registers. Verified
    // 2026-10-01 against the host's Hooks interface (packages/plugin/src/index.ts).
    tool: buildTools(),
    // The host calls (input, output); the mutable args live on OUTPUT.
    "tool.execute.before": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { args?: { command?: unknown } },
    ) => {
      if (input.tool !== "bash") return;
      const command = String(output.args?.command ?? "");
      const verdict = checkCommand(command);
      if (verdict.deny) {
        throw new Error(`[babayaga] ${verdict.reason}`);
      }
    },
  };
}
