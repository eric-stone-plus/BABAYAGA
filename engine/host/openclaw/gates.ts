/**
 * BABAYAGA seat gates — the deny tripwire for raw instrument invocation.
 *
 * HONESTY CONTRACT (measured 2026-09-28 on the opencode seat, ported verbatim):
 * this word-match is a TRIPWIRE, not a boundary. It catches accidental/direct
 * invocation shapes and leaves an audit mark; it does NOT catch variable
 * indirection
 * (`h="hy";$h$d`), base64/eval obfuscation, or scripts whose *content* holds
 * the call. The boundary is the engine: budgets bind only the instrumented
 * path, and `babayaga doctor` fails closed while the instrument resolves on
 * the session PATH. Never present either layer as more than it is.
 *
 * Two layers register the same check here, honestly labeled:
 *   (a) buildTrustedPolicy() — a TRUSTED pre-tool policy for
 *       api.registerTrustedToolPolicy (declared in the manifest under
 *       contracts.trustedToolPolicies). The host runs trusted policies before
 *       ordinary hooks and fails closed if evaluation throws. This is the
 *       stronger tier, and it is still only a word-match gate.
 *   (b) tripwireBeforeToolCall() — an ordinary before_tool_call hook: the
 *       documented tripwire, identical in shape to the opencode seat's
 *       `tool.execute.before` deny.
 */

const INSTRUMENTS = ["hydra", "medusa", "ncrack", "patator"] as const;

// Word-form match, tolerant of absolute paths, quotes, and shell punctuation.
// Built to catch: "hydra ...", "/usr/bin/hydra", "hydra;id", "hydra|cat",
// `x=hydra;$x`, `["hydra"]` inside python3 -c strings.
const INSTRUMENT_RE = new RegExp(
  `(?<![A-Za-z0-9_-])(?:[\\w./-]*[/\\s"'\`=;|&($[{]?)(${INSTRUMENTS.join("|")})(?![A-Za-z0-9_-])`,
  "i",
);

export interface GateVerdict {
  deny: boolean;
  reason?: string;
}

export function checkCommand(command: string): GateVerdict {
  const m = INSTRUMENT_RE.exec(command);
  if (m) {
    return {
      deny: true,
      reason:
        `raw instrument invocation denied: '${m[0].trim()}' — credential attacks ` +
        `run through the babayaga engine (the babayaga CLI; the seat exposes ` +
        `babayaga_doctor/status/roe_check/seal_verify/export_access), which ` +
        `enforces ROE, per-principal budgets, and the sealed attempt ledger. ` +
        `(This deny is a tripwire, not a boundary — see gates.ts header.)`,
    };
  }
  return { deny: false };
}

/** Known-bypass shapes we deliberately do NOT catch — encode the honesty. */
export const DOCUMENTED_BYPASSES: string[] = [
  'h="hy"; d="dra"; eval "$h$d -C x"', // character-level indirection
  "echo aHlkcmE= | base64 -d | sh", // encoded payload
  "bash /tmp/run.sh", // call lives in file content, not argv
];

/** Manifest-declared local id (contracts.trustedToolPolicies). */
export const TRUSTED_POLICY_ID = "raw-instrument-deny";

/** Canonical tool ids both layers watch: the host's shell-exec surface. */
export const EXEC_TOOL_MATCHER = ["exec"] as const;

/** Minimal before_tool_call event shape both layers consume (SDK-typed at registration). */
export interface ToolCallEventLike {
  toolName?: string;
  params?: Record<string, unknown>;
}

export interface BlockDecision {
  block: true;
  blockReason: string;
}

function gateEvent(event: ToolCallEventLike): BlockDecision | undefined {
  const command = event.params?.command;
  if (typeof command !== "string") return undefined;
  const verdict = checkCommand(command);
  if (!verdict.deny) return undefined;
  return { block: true, blockReason: `[babayaga] ${verdict.reason}` };
}

/**
 * Layer (a): trusted pre-tool policy registration value for
 * api.registerTrustedToolPolicy. `block: true` is terminal; returning
 * undefined is no decision. Verified against PluginTrustedToolPolicyRegistration
 * (openclaw src/plugins/host-hooks.ts) at 2026.9.7 / f81d71f.
 */
export function buildTrustedPolicy() {
  return {
    id: TRUSTED_POLICY_ID,
    description:
      "Deny raw credential-instrument invocation (hydra/medusa/ncrack/patator) " +
      "in exec calls; credential attacks run through the gated babayaga engine. " +
      "Tripwire, not a boundary — see gates.ts header.",
    matcher: [...EXEC_TOOL_MATCHER],
    evaluate(event: ToolCallEventLike): BlockDecision | undefined {
      return gateEvent(event);
    },
  };
}

/**
 * Layer (b): the ordinary before_tool_call tripwire, registered with
 * api.on("before_tool_call", ..., { matcher: ["exec"] }).
 */
export function tripwireBeforeToolCall(event: ToolCallEventLike): BlockDecision | undefined {
  return gateEvent(event);
}
