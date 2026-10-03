/**
 * BABAYAGA seat gates — the deny tripwire for raw instrument invocation.
 *
 * HONESTY CONTRACT (measured 2026-09-28): this word-match is a TRIPWIRE,
 * not a boundary. It catches accidental/direct invocation shapes and leaves
 * an audit mark; it does NOT catch variable indirection (`h="hy";$h$d`),
 * base64/eval obfuscation, or scripts whose *content* holds the call.
 * The boundary is the engine: budgets bind only the instrumented path, and
 * `babayaga doctor` fails closed while the instrument resolves on the
 * session PATH. Never present this hook as more than it is.
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
        `babayaga_doctor/status/roe_check), which enforces ROE, per-principal ` +
        `budgets, and the sealed attempt ledger. ` +
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
