/**
 * BABAYAGA opencode plugin — thin control plane (v0).
 *
 * Doctrine (adjudicated in CATEGORY.md):
 *   - every tool SHELS OUT to the gated `babayaga` CLI; execution stays in
 *     the OS layer; the plugin never re-implements gate semantics;
 *   - ops-safe, read-only-ish surface only: doctor, status, roe-check,
 *     seal-verify, export-access; the attempt runner is NEVER a plugin tool;
 *   - plain-object args => every key required, no runtime validation by the
 *     host — validate inside execute;
 *   - type-only imports are stripped by Bun: no package.json, no node_modules;
 *   - plugins load at opencode startup only — restart after edits.
 *
 * Verified against opencode 0.0.0-main-202609280832; Hooks-shape corrected
 * 2026-10-01 (`tool` singular key; before-hook args arrive on the mutable
 * output parameter) — the earlier revision silently registered nothing.
 */

import type { Plugin } from "@opencode-ai/plugin";

import { checkCommand } from "./gates.ts";

const BABAYAGA_BIN = process.env.BABAYAGA_BIN ?? "babayaga";
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_OUTPUT_BYTES = 1 << 20; // pipe guard: 1 MiB

export interface BoundedResult {
  stdout: string;
  stderr: string;
  code: number;
  timedOut: boolean;
}

/** Bounded one-shot CLI spawn: timeout -> SIGKILL, capped output capture. */
export async function runBounded(
  bin: string,
  args: string[],
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
  env: Record<string, string> = {},
): Promise<BoundedResult> {
  const proc = Bun.spawn([bin, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ...env },
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill(9);
  }, timeoutMs);
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;
  clearTimeout(timer);
  return {
    stdout: stdout.length > MAX_OUTPUT_BYTES ? stdout.slice(0, MAX_OUTPUT_BYTES) : stdout,
    stderr: stderr.length > MAX_OUTPUT_BYTES ? stderr.slice(0, MAX_OUTPUT_BYTES) : stderr,
    code,
    timedOut,
  };
}

function parseJson(text: string): Record<string, unknown> | null {
  try {
    const first = text.indexOf("{");
    const last = text.lastIndexOf("}");
    if (first === -1 || last <= first) return null;
    return JSON.parse(text.slice(first, last + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export interface CliOutcome {
  engineExit: number; // translated engine contract: 0 ok / 2 refusal / 1 failure
  payload: Record<string, unknown> | null;
  raw: string;
  timedOut: boolean;
}

/** Run a babayaga CLI subcommand and translate its exit contract. */
export async function callEngine(args: string[], bin = BABAYAGA_BIN): Promise<CliOutcome> {
  let res: BoundedResult;
  try {
    res = await runBounded(bin, [...args, "--json"]);
  } catch (err) {
    return {
      engineExit: 1,
      payload: null,
      raw: `spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      timedOut: false,
    };
  }
  if (res.timedOut) {
    return { engineExit: 1, payload: null, raw: "engine call timed out (SIGKILL)", timedOut: true };
  }
  // Boundary A exit contract: 0 ok / 2 refusal / else failure.
  const engineExit = res.code === 0 ? 0 : res.code === 2 ? 2 : 1;
  return { engineExit, payload: parseJson(res.stdout), raw: res.stdout.trim(), timedOut: false };
}

/** Tool set, exported for tests. The runner is deliberately absent. */
export function buildTools(bin = BABAYAGA_BIN) {
  return {
    babayaga_doctor: {
      description:
        "Run `babayaga doctor` — engine health, lab-only guard state, tools " +
        "anchoring (fails while the instrument resolves on the session PATH).",
      args: {} as Record<string, never>, // plain-object args: no optional keys
      async execute() {
        const out = await callEngine(["doctor"], bin);
        return {
          ok: out.engineExit === 0,
          engineExit: out.engineExit,
          ...(out.payload ?? { raw: out.raw || "(no output)" }),
        };
      },
    },
    babayaga_status: {
      description:
        "Run `babayaga status` — campaign homes, attempt ledger counts, " +
        "fold==materialized verification state.",
      args: {} as Record<string, never>,
      async execute() {
        const out = await callEngine(["status"], bin);
        return {
          ok: out.engineExit === 0,
          engineExit: out.engineExit,
          ...(out.payload ?? { raw: out.raw || "(no output)" }),
        };
      },
    },
    babayaga_seal_verify: {
      description:
        "Run `babayaga seal <target> --verify` — recompute the campaign seal " +
        "and compare against the manifest (refusal on drift or never-sealed).",
      args: { target: "campaign name under BABAYAGA_HOME, campaign dir, or campaign.db path" },
      async execute(input: { target: string }) {
        if (typeof input.target !== "string" || input.target.length === 0) {
          return { ok: false, error: "target is required (validate inside execute)" };
        }
        const out = await callEngine(["seal", input.target, "--verify"], bin);
        return {
          ok: out.engineExit === 0,
          engineExit: out.engineExit,
          ...(out.payload ?? { raw: out.raw || "(no output)" }),
        };
      },
    },
    babayaga_export_access: {
      description:
        "Run `babayaga export-access <campaign>` — sealed, digest-only access " +
        "records in the access/grants_access ingest shape (the B16 bridge). " +
        "Credential hygiene: digests only, never plaintext.",
      args: { campaign: "campaign name under BABAYAGA_HOME, campaign dir, or campaign.db path" },
      async execute(input: { campaign: string }) {
        if (typeof input.campaign !== "string" || input.campaign.length === 0) {
          return { ok: false, error: "campaign is required (validate inside execute)" };
        }
        const out = await callEngine(["export-access", input.campaign], bin);
        return {
          ok: out.engineExit === 0,
          engineExit: out.engineExit,
          ...(out.payload ?? { raw: out.raw || "(no output)" }),
        };
      },
    },
    babayaga_roe_check: {
      description:
        "Validate a ROE file and print its canonical digest (fail-closed: " +
        "malformed or non-conforming ROE -> refusal).",
      args: { roe_path: "absolute or repo-relative path to the ROE JSON file" },
      async execute(input: { roe_path: string }) {
        if (typeof input.roe_path !== "string" || input.roe_path.length === 0) {
          return { ok: false, error: "roe_path is required (validate inside execute)" };
        }
        const out = await callEngine(["roe-check", input.roe_path], bin);
        return {
          ok: out.engineExit === 0,
          engineExit: out.engineExit,
          ...(out.payload ?? { raw: out.raw || "(no output)" }),
        };
      },
    },
  };
}

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
