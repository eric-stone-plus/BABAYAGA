/**
 * BABAYAGA openclaw tools — thin control plane over the babayaga/1 framed
 * adapter (engine/babayaga/adapter.py). Same doctrine as the opencode seat
 * (engine/host/opencode/babayaga.ts): every tool SHELS OUT to the gated
 * `babayaga` CLI; the plugin never re-implements gate semantics; the surface
 * is the ops-safe read set only (doctor, status, roe-check, seal-verify,
 * export-access); the attempt runner is NEVER a plugin tool.
 *
 * Boundary: one `babayaga adapter --request '<json>'` spawn per tool call —
 * a single request frame in, a single response frame out. The CLI maps the
 * frame's exit granularity onto Boundary A: 0 ok / 2 refusal / 1 failure.
 *
 * Exit mapping (host side):
 *   - process exit 2, or an in-frame `operation_refused`  -> tool result
 *     details.status "denied" (refusal is data; never thrown);
 *   - process exit 0 with an ok frame                     -> the frame's
 *     `result` payload (defineToolPlugin wraps it as JSON text + details);
 *   - anything else (exit 1/3/124/130, timeout, spawn or parse failure)
 *     -> throw, i.e. a tool-call error.
 *
 * Parameter schemas are hand-written JSON Schema: typebox 1.3.x schemas are
 * plain JSON Schema objects (no symbol metadata) and the host compiles them
 * structurally (`typebox/compile`), so no runtime typebox import is needed
 * and this package keeps the zero-node_modules rule. `TSchema` is a
 * type-only import, stripped at load.
 */

import type { TSchema } from "typebox";

const DEFAULT_TIMEOUT_MS = 15_000; // same bound as the opencode seat
const MAX_OUTPUT_BYTES = 1 << 20; // pipe guard: 1 MiB
const PROTOCOL = "babayaga/1";
const MAX_DETAIL_CHARS = 4096;

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

export interface AdapterOutcome {
  processExit: number; // Boundary A: 0 ok / 2 refusal / 1 failure
  frame: Record<string, unknown> | null; // the parsed babayaga/1 response frame
  raw: string;
  stderr: string;
  timedOut: boolean;
}

// Correlation integers, never caller-supplied text (adapter.py parse_request).
let nextRequestId = 1;

/** Parse the single response frame strictly: a non-JSON emission is an engine failure. */
function parseFrame(stdout: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(stdout.trim());
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Dispatch one babayaga/1 request frame through `babayaga adapter --request`. */
export async function callAdapter(
  bin: string,
  operation: string,
  options?: Record<string, string>,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<AdapterOutcome> {
  const frame = {
    protocol: PROTOCOL,
    request_id: nextRequestId++,
    operation,
    ...(options ? { options } : {}),
  };
  let res: BoundedResult;
  try {
    res = await runBounded(bin, ["adapter", "--request", JSON.stringify(frame)], timeoutMs);
  } catch (err) {
    return {
      processExit: 1,
      frame: null,
      raw: `spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      stderr: "",
      timedOut: false,
    };
  }
  return {
    processExit: res.code,
    frame: parseFrame(res.stdout),
    raw: res.stdout.trim(),
    stderr: res.stderr,
    timedOut: res.timedOut,
  };
}

/**
 * Translate an adapter outcome into the tool's return value.
 * Refusal is data; failure throws (AgentTool contract: throw on failure).
 */
export function toToolValue(out: AdapterOutcome): unknown {
  if (out.timedOut) {
    throw new Error("babayaga adapter call timed out (SIGKILL)");
  }
  const frame = out.frame;
  const frameExit = typeof frame?.exit_code === "number" ? frame.exit_code : undefined;
  const frameError = typeof frame?.error === "string" ? frame.error : undefined;
  if (out.processExit === 2 || frameError === "operation_refused") {
    return {
      status: "denied",
      exitCode: frameExit ?? 2,
      ...(frameError ? { error: frameError } : {}),
      ...(frame && "result" in frame ? { result: frame.result } : {}),
      ...(frame === null ? { raw: out.raw.slice(0, MAX_DETAIL_CHARS) } : {}),
    };
  }
  if (out.processExit === 0 && frame?.ok === true && "result" in frame) {
    return frame.result;
  }
  const detail = (out.stderr.trim() || out.raw || "(no output)").slice(0, MAX_DETAIL_CHARS);
  throw new Error(`babayaga adapter call failed (process exit ${out.processExit}): ${detail}`);
}

export interface BabayagaPluginConfig {
  babayaga_bin?: string;
}

/** Config key carrying the engine binary path; env wins per the internal design notes. */
function resolveBin(config: BabayagaPluginConfig | undefined, fixedBin?: string): string {
  if (fixedBin) return fixedBin;
  const envBin = process.env.BABAYAGA_BIN;
  if (envBin) return envBin;
  const configured = config?.babayaga_bin;
  return typeof configured === "string" && configured.length > 0 ? configured : "babayaga";
}

const EMPTY_PARAMS = {
  type: "object",
  properties: {},
  additionalProperties: false,
} as TSchema;

function pathParams(key: string, description: string): TSchema {
  return {
    type: "object",
    properties: { [key]: { type: "string", minLength: 1, description } },
    required: [key],
    additionalProperties: false,
  } as TSchema;
}

function invalid(message: string) {
  // "invalid" is a reserved failure status in the host's outcome grading:
  // returned as data (never thrown), graded as a failed call.
  return { status: "invalid", error: message };
}

/**
 * The five tool definitions, in defineToolPlugin's declaration shape.
 * The attempt runner is deliberately absent. `fixedBin` exists for tests.
 */
export function buildTools(fixedBin?: string) {
  const binFor = (config: BabayagaPluginConfig | undefined) => resolveBin(config, fixedBin);
  return [
    {
      name: "babayaga_doctor",
      description:
        "Run `babayaga doctor` through the babayaga/1 adapter — engine health, " +
        "lab-only guard state, tools anchoring (fails while the instrument " +
        "resolves on the session PATH).",
      parameters: EMPTY_PARAMS,
      async execute(_params: Record<string, never>, config?: BabayagaPluginConfig) {
        return toToolValue(await callAdapter(binFor(config), "doctor"));
      },
    },
    {
      name: "babayaga_status",
      description:
        "Run `babayaga status` through the babayaga/1 adapter — campaign homes, " +
        "attempt ledger counts, fold==materialized verification state.",
      parameters: EMPTY_PARAMS,
      async execute(_params: Record<string, never>, config?: BabayagaPluginConfig) {
        return toToolValue(await callAdapter(binFor(config), "status"));
      },
    },
    {
      name: "babayaga_roe_check",
      description:
        "Validate a ROE file and return its canonical digest through the " +
        "babayaga/1 adapter (fail-closed: malformed or non-conforming ROE -> " +
        "a denial result, not an error).",
      parameters: pathParams("roe_path", "absolute or repo-relative path to the ROE JSON file"),
      optional: true,
      async execute(params: { roe_path?: unknown }, config?: BabayagaPluginConfig) {
        // Plain-object params arrive unvalidated on some paths: validate inside execute.
        if (typeof params?.roe_path !== "string" || params.roe_path.length === 0) {
          return invalid("roe_path is required (validate inside execute)");
        }
        return toToolValue(
          await callAdapter(binFor(config), "roe-check", { roe_path: params.roe_path }),
        );
      },
    },
    {
      name: "babayaga_seal_verify",
      description:
        "Recompute a campaign seal and compare against the manifest " +
        "(`babayaga seal <target> --verify` through the babayaga/1 adapter; " +
        "denial on drift or never-sealed).",
      parameters: pathParams(
        "target",
        "campaign name under BABAYAGA_HOME, campaign dir, or campaign.db path",
      ),
      optional: true,
      async execute(params: { target?: unknown }, config?: BabayagaPluginConfig) {
        if (typeof params?.target !== "string" || params.target.length === 0) {
          return invalid("target is required (validate inside execute)");
        }
        return toToolValue(
          await callAdapter(binFor(config), "seal-verify", { target: params.target }),
        );
      },
    },
    {
      name: "babayaga_export_access",
      description:
        "Export sealed, digest-only access records in the " +
        "access/grants_access ingest shape (the B16 bridge) through the babayaga/1 " +
        "adapter. Credential hygiene: digests only, never plaintext.",
      parameters: pathParams(
        "campaign",
        "campaign name under BABAYAGA_HOME, campaign dir, or campaign.db path",
      ),
      optional: true,
      async execute(params: { campaign?: unknown }, config?: BabayagaPluginConfig) {
        if (typeof params?.campaign !== "string" || params.campaign.length === 0) {
          return invalid("campaign is required (validate inside execute)");
        }
        return toToolValue(
          await callAdapter(binFor(config), "export-access", { campaign: params.campaign }),
        );
      },
    },
  ];
}
