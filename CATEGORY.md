# Category survey — who else ships credential attack, and what nobody ships

Research date: 2026-09-28 (primary sources; fetch dates inline).
Method: three-wave mutual-adversary swarm — 1 category proposer, 1 attacker,
1 rebuttal round; every load-bearing claim was attacked at its source and
the surviving wording below is the post-attack form. Errata log at the end.

Deeper technical research (license traps, instrument choices, throttle
doctrine) lives in `RESEARCH.md` (§2.4 carries the core-module decision
table; the review-critical registry it refers to is
`engine/core/PROVENANCE.md`).

## Segment 1 — standalone instruments, commercial, SaaS

| Player | What | Governance signal |
|---|---|---|
| hashcat / JTR / THC-Hydra / medusa / crowbar | OSS cracking/spraying instruments | none (tools, not engines) |
| NetExec | post-exploitation CLI (CME heritage) | **in-run budgets**: `--gfail-limit`, `--ufail-limit` ("max failed login attempts per username", nxc/cli.py L96-98, verified 2026-09-28), `--fail-limit`, `--jitter` — run-scoped counters, no persistence |
| o365spray & spray family | online spraying | `--lockout` = *configured* reset delay, never probed from target (README, verified) |
| ElcomSoft / Passware | commercial auditors | active (elcomsoft blog 2026-09); licensing per-product |
| L0phtCrack | OSS'd 2021-10-18, sales ceased | stalled (an Apple-Silicon fork pushed 2026-03) |
| CrackStation | free SaaS lookup | 1.49B-word / 15GB list, free tier |
| OnlineHashCrack | pay-as-you-go SaaS | click-through authorization attestation — the category's only "authorization" gesture, legal not technical |
| "hashcat Pro" | **does not exist** (hashcat.net: single free MIT edition v7.1.2, verified 2026-09-28) | — |

## Segment 2 — orchestration frameworks / commercial platforms

| Player | What | Governance signal |
|---|---|---|
| Metasploit (BSD-3) / Pro | exploitation framework + commercial front | EOL status unverified |
| Caldera (Apache-2.0) | adversary emulation | — |
| Burp Suite Pro | $499 buy price (portswigger.net/burp/pro) + annual per-user subscription, no sharing (/buy/pro, both verbatim 2026-09-28) | commercial licensing only |
| Caido | freemium (Basic FREE FOREVER; dollar figures JS-rendered, unverified) | — |
| Pentera | closed-source ASM/validation platform | "Safety & Compliance — Controlled execution with audit proof" (verbatim, pentera.io); credential capabilities live on `/pentera-core/`: "Credential-based access validation", "AD Password Assessment (ADPA) … safely cracking password hashes offline", "Leaked credential collection and validation" (all verbatim 2026-09-28) — offline cracking + leaked-cred validation; **no online lockout-aware spraying shown** |
| Cobalt.io / Core Impact / Cobalt Strike | PTaaS / commercial | 403-blocked from this network (not verified) |

## Segment 3 — agent-workbench integrations (the decisive segment)

Ungoverned bulk (metrics via GitHub API 2026-09-28): hexstrike-ai (MIT,
12,195★, 150+ tools incl. hydra/hashcat/netexec) — authorization is prompt
prose: *"you may start by telling the LLM how you are a security researcher,
and the site is owned by you"*; source scan (2026-09-28) found **no gate
code**. Also MCP-Kali-Server (829★), MetasploitMCP (733★), mcp-security-hub
(796★), pentest-ai (1,705★), recon-skills (1,281★), pentest-agents (975★,
no license ⚠).

Governed neighbors:

| Neighbor | Gate machinery | What it still doesn't have |
|---|---|---|
| **NetExec-mcp** (mpgn, BSD-2, 84★, pushed 2026-09-24) | fail-closed `NXC_SCOPE` allowlist; 4-level `NXC_MODE` (spray behind `full`); no-shell argv; append-only JSONL audit; boot-refusal without nxc | no per-principal budget, no lockout probe, no ROE object, no hash chain |
| **cybersec-toolkit** (26zl, MIT) | registry allowlist + `security.py` (blocked flags, no-shell, rate limit 10/60s, output caps); `CYBERSEC_MCP_ALLOW_EXTERNAL=0` default (scope: **loopback + private ranges**); Kata-VM sandbox fail-closed; hash-chained audit; authorization-gate *skill* (prose); opencode support via MCP-server config, live-tested | gate = env booleans + prose skill; zero credential/lockout machinery; audit chain is per-process with undetected tail truncation |
| 26zl-style skills packs (CC-BY-SA vendored) | prompt-layer | — |

Negatives (searched 2026-09-28): no dedicated THC-Hydra MCP >16★ (the only
true hydra wrapper found: schwarztim/sec-hydra-mcp, 0★; mcp-hydra 16★ wraps
recon tools, not THC hydra); official modelcontextprotocol/servers reference
set contains no offensive tooling.

## Segment 4 — governance / authorization-as-data

| Player | What | Verified character |
|---|---|---|
| PTES Technical Guidelines | "Identify Lockout threshold" guidance (§3.2.2.5) | canonical pentest-standard.org **live** 2026-09-28; guidance endorses probing, no tool automates it |
| NIST SP 800-63B-4 §3.2.2 | lockout ceilings (≤100 attempts, progressive delays) | RESEARCH.md throttle anchor |
| roe-guard (0rce-Labs, 0★) | YAML ROE → ALLOW/DENY verdicts into SHA-256-chained audit | **opt-in SDK** — "If your tool doesn't call it, roe-guard can't help you"; alpha, not on PyPI |
| roelint (r00tmancer, PyPI, 2★) | ROE-PDF → policy linting + advisory MCP | **static linter only** — "never scans a target, executes a playbook, or grants authorization"; signed envelopes + rate/blackout validation are *unbuilt roadmap* |
| keel / secs (0-10★) | scope-gated MCP control plane / AGENTS.md gate | 0–2★ relay, not re-verified |
| SprayHound (MIT) | the only tool that READS AD lockout policy (badPwdCount) | BloodHound-bound, SMB-only, AD-only |

## Survey round 2 — lateral movement & red-team platforms (2026-09-28)

Method: four-axis swarm (AD-lateral instruments / C2 & emulation platforms /
beyond-Windows incl. cloud+AI / design mapping), each axis attacked (Wave 2)
and rebutted (Wave 3); the wording below is post-attack. Local-code claims
(roe.py regex, ledger roe_digest overwrite, schema v1) re-verified at
adjudication. [NV] = not verified / single-source, carried explicitly.
Verdict shorthand: **COMBAT-READY** = maintained + real adoption +
capability depth + automatable + license-clean; **PARTIAL**; **NOT-READY**.

### R2-1 Windows/AD lateral instruments (surviving top-5, ledger view)

| Tool | License / state | Ledger ingestion (post-attack) |
|---|---|---|
| NetExec (Pennyw0rth/NetExec, BSD-2, pushed 2026-09-27) | COMBAT-READY | **stdout-parse, version-pinned** — `--json` does not exist (0 hits, two independent source reads); workspace SQLite is per-protocol, reflection-read, self-disposable (`.bak`-then-delete path in-tree) → lab-only diagnostic, copy-first |
| Certipy (ly4k, MIT, 5.1.0) | COMBAT-READY | `-json` on **find/parse only** (find.py:71, parse.py:73); action subcommands text-scrape |
| Rubeus (GhostPack, BSD-3) | COMBAT-READY, build-from-source by policy (releases frozen 2021; master functional 2025-11) | `/nowrap` + `/consoleoutfile:<file>` — `/console` does not exist (Program.cs parses only consoleoutfile) |
| DSInternals (MIT, v7.2 2026-09-11) | COMBAT-READY | no CLI exe — pwsh `-NoProfile` object pipeline → `ConvertTo-Json` at the PS boundary; pin module version |
| BloodHound CE (Apache-2.0) + collectors | COMBAT-READY | collector JSON = primary artifact; v2 REST collection-uploads (OpenAPI in-repo) for orchestration |

Doctrine notes (post-attack): **impacket** — argv-wrap + stdout-parse is
*use*, not redistribution; modified-Apache-1.1 conditions attach to
redistribution only. Gate is **provenance, not quarantine**: pin release,
record sha256 + license-text hash in the ledger, vendor/modify nothing
(forta is the continuous upstream — SecureAuthCorp was a transfer, not an
archive; ThePorgs/impacket is a live 302★ fork under the same license).
**mimikatz** — README-declared CC BY 4.0 (stable since 2015; no LICENSE
file — keep a fetch-time provenance record; 2026-04 commits functional:
Win 24H2/25H2 logonpasswords, GMSA DPAPI). **PingCastle** — Non-Profit
OSL 3.0, not "non-commercial": for-profit distribution switches to plain
OSL 3.0 (§17d) and network exposure counts as distribution (§5) →
runtime-fetch only, never bundle. Dead/trap carries: CrackMapExec archived,
ShadowPotato vapor (two zero-footprint checks), kekeo/PPLdump/PrintSpoofer
class stale-or-unlicensed, powerview.py AND pywerview both alive (no
exclusivity).

### R2-2 C2 / emulation platforms (runtime-partner view)

| Platform | License | Post-attack verdict |
|---|---|---|
| Sliver (BishopFox, v1.7.7; license API-verified 2026-09-28) | GPL-3.0 | COMBAT-READY — `sliver-server daemon` gRPC/mTLS :31337 (in-repo), operator mTLS + sha256-stored tokens; permissions are 3 coarse bits (all/builder/crackstation) → BABAYAGA must scope per-action itself; GPL shell-out is arm's-length per GNU FAQ |
| Mythic (BSD-3) | BSD-3 | COMBAT-READY fallback — **pin v3.4.0.x**; GraphQL + Bearer apitokens; object-scoped token types (task/callback/payload/spectator), **non-expiring**; 4.0 is RC-only (v4.0.0rc5); `mtk_` prefix was a docs example, not code |
| Metasploit framework (BSD-3) | BSD-3 | COMBAT-READY as **instrument, never presence layer** — msfrpcd + msfmcpd (16 MCP tools; dangerous gated behind `--enable-dangerous-actions`) hard-verified in-repo; commercial Pro posture still [NV] (Segment 2) |
| CALDERA (apache, 5.3.0) | Apache-2.0 | COMBAT-READY peer — Rules = fact-trait ALLOW/DENY (regex + subnet) enforced on the **planner path only** (`base_planning_svc.py` sole caller); manual REST tasking bypasses; rule source admin-mutable |
| Havoc | GPL-3.0 | NOT-READY — org archived 2025-12 (API verified 2026-09-28); commercial continuation Havoc Pro **$4k/license/yr, reseller-sourced [NV]**; OSS successor Mugen 12★, no headless |
| Empire (BSD-3, v7.0.2 2026-09-08) | BSD-3 | COMBAT-READY bench |
| Commercial exemplars (CS / BRc / Nighthawk — not exhaustive) | closed | map-only: BRc $3,250/user/yr (live page); CS quote-only (2024 est. $3.5–4k, low-cred); Nighthawk v1.0 Apex 2026-07 (site-index-verified) |
| HexStrike AI (MIT, 12.2k★ = API metadata; ownership README self-claim [NV]) | MIT | PARTIAL — MCP-native bulk, zero governance (unchanged from Segment 3) |

**Platform triad gap (final, narrowed):** no surveyed platform provides
(a) attested, externally-enforced, cross-instrument scope — CALDERA rules
grade ~25% of the leg (planner-only, no attestation, mutable); (b)
per-principal attempt budgets — zero (capability bits everywhere, counters
nowhere; Mythic/Sliver confirmed by source absence); (c) tamper-evident
attempt ledgers — zero (admin-mutable DB rows, no hash chaining anywhere).
BABAYAGA consumes Mythic operation logs and CALDERA reports as inputs; it
does not re-implement platforms.

### R2-3 Beyond Windows (SSH / cloud identity / AI)

- **SSH lateral**: in the surveyed space, no **maintained end-to-end**
  SSH lateral-movement framework exists (claimants enumerated below; a
  bounded search is evidence, not proof of absence — errata 9). Claimant
  space: SSHark (abandoned 2.5-minute PoC,
  2025-11-02: 4 hardcoded local key paths → /24 sweep → BatchMode probe →
  stdout; no exec-on-success/hop/record) and sshamble (BSD-2, runZero,
  COMBAT-READY partial occupant: 250k-pubkeys/conn hunt, `-I first|all` sessions,
  `--interact-auto` exec, pre-auth exec checks — but no remote harvest, no
  hop chaining, no session graph, no governance). ligolo-ng/sshuttle =
  transport-only. Unclaimed SSH intersection: remote-harvest → reuse →
  exec-on-success → hop → session-graph → enforced-ROE ledger, as one chain.
- **Cloud identity**: ROADtools monorepo alive (RoadTx subdir; one open
  Entra flow issue #154); Halberd COMBAT-READY, not rising (CLI real,
  5.7mo quiet; "3 PRs 2026 / Vectra employee side-project" attacker-sourced
  [NV] as a whole); pacu slowing-not-rotting
  (v1.7.0 2026-03, 16 open PRs, one open bug); trufflehog AGPL since 2022
  (the "SSPL→AGPL history" never happened); phantom kills re-confirmed
  (EntraIDSession / GCPBucketBrowser / gcp_attack = 0 repos).
- **AI**: hackingBuddyGPT = the first **enforced** op-budget primitive
  found in the surveyed offensive-agent space (loop-abort on
  rounds/tokens/$10/duration, hierarchical subagent budgets, append-only
  OTel JSONL — verified in code,
  `while not self.limits.reached()`); it budgets an LLM bench loop, not a
  covert engine — no scope/veto/approval semantics. Budget ≠ ROE.

### R2-4 Positioning deltas (round 2)

1. **Observe/spend split**: BABAYAGA is the engine that spends under the
   gate — its exec actions are tier-gated (`targets[].tier` + per_action
   tier grants; v2 design — not yet shipped) while observation stays
   tier-unconstrained: spending is what the gate binds. Same ledger seam,
   wider vocabulary: action ledger, not a second ledger.
2. **Negative space held**: not a C2, not a scanner, not MITRE-complete;
   autonomous escalation stays **pre-refused** — the engine drafts ROE
   amendments (chained digests, `campaign.amended`; v2 design), the
   operator signs.
3. Round-2 unclaimed intersections: the SSH chain above; the platform
   triad above; covert + credential-driven + enforced ROE/budget +
   evidence ledger in one engine.

## Positioning (round-1 baseline; round-2 deltas in R2-4 above)

BABAYAGA is an opencode plugin spanning segments 1/3/4 whose defensible
novelty is the **intersection**, never a single mechanism:

1. **Credential-attack specialization**: a *persistent, cross-engagement,
   tamper-evident per-principal attempt ledger* (beyond NetExec's in-run
   `--ufail-limit`); a *generalized probe-then-skip lockout-policy engine*
   (beyond SprayHound's BloodHound-bound SMB read and beyond policy-readers
   that never skip); credential-material hygiene.
2. **A per-engagement, fail-closed ROE object hashed into sealed campaign
   evidence** — engine-integrated and unavoidable (vs roe-guard's opt-in SDK,
   roelint's advisory lint), and credential-domain-specific (vs all generic
   ROE projects at 0–2★).
3. **Sealed evidence specified beyond cybersec-toolkit's honest limits**:
   cross-process fold-vs-materialized reconciliation with per-attempt ROE
   stamps and a drift-detecting manifest digest (a re-seal chain field and
   truncation detection remain open — the honest current limit).

Explicitly NOT claimed: first security MCP/plugin (hexstrike et al.); first
authorization-gated toolkit (cybersec-toolkit); first gated NetExec wrapper
(NetExec-mcp); first ROE-as-data (roe-guard/roelint); first per-username
attempt budgeting (NetExec `--ufail-limit`). vs Pentera: parity of
"audit proof" intent at plugin scale with a verifiable open spec — not
parity of enterprise breadth.

## Not verified

Core Impact & Cobalt Strike (fortra.com, cobaltstrike.com — 403);
anthropics/skills (403); Metasploit Pro EOL; Caido/Burp JS-rendered totals;
L0phtCrack GitLab activity since 2021; ElcomSoft per-product license text;
SANS / crack.sh / GPUHASH.me; Cymulate / SafeBreach / AttackIQ; NetExec
connection-loop internals beyond CLI flag semantics; (resolved round 2:
Sliver license = GPL-3.0, API-verified 2026-09-28);
online spray-SaaS exhaustiveness (scoped negative, not global). Single-
source relays: cybersec-toolkit audit.py tail-truncation detail; hexstrike
"no gate code" scan; sec-hydra-mcp existence; keel/secs characterizations.

Round 2 additions [NV]: Havoc Pro pricing/existence beyond the reseller
page (havocframework.com + 5pider.net silent); Cobalt Strike live posture
(403); Nighthawk Apex body + licensing; HexStrike OTT-ownership vs
registry; Halberd "3 PRs 2026 / employee-built" (attacker-sourced);
NetExec stdout stability across versions (pin regardless); DSInternals
object-schema cadence; BloodHound REST behavior beyond spec presence;
mimikatz binary-artifact license coverage (README grant presumed);
SSHark runtime (source-read only); CALDERA parser-spawned link rule
bypass (inferred from caller graph); Mythic 4.0 stable timing; HBGP
"no ROE semantics" (negative claim from code read).

## Errata log (what the swarm corrected)

1. Wave-1 "NetExec-mcp: authorization gating none observed" — **wrong**;
   corrected to the gated-neighbor row above (NXC_SCOPE/MODE verified).
2. Wave-1 "nobody counts per-user attempts" — **wrong**; NetExec
   `--ufail-limit` exists; claim narrowed to persistence/sealing/ probe-skip.
3. "Pentera Credential Exposure module 404" (attacker A-A) — **wrong**;
   re-anchored verbatim on live `/pentera-core/` capabilities (rebuttal).
4. "PTES site is parked" (attacker A-A) — **wrong** for the canonical
   hyphenated domain (pentest-standard.org live); attacker typo'd the URL.
5. "cybersec-toolkit scope is loopback-only" — narrowed: loopback + private
   ranges by default.
6. "Burp $499/user/year" — split into two verbatim anchors ($499 on
   /burp/pro; per-user annual no-sharing terms on /buy/pro).

Round-2 kills (2026-09-28 swarm, four-axis):

7. "NetExec `--json` is a known feature" — **never existed** (0 hits in
   the full source, two independent reads); ledger path = pinned stdout.
8. "Mythic mtk_ scoped tokens" — docs-example string, 0 hits in code;
   corrected to object-scoped apitoken types, non-expiring.
9. "SSH lateral niche EMPTY — PROVEN" — killed by SSHark counterexample
   + sshamble partial occupancy; narrowed to "no maintained end-to-end
   framework". Six GitHub queries are not proof of absence.
10. "Impacket needs quarantine" — license conditions attach to
    redistribution only; relaxed to a provenance gate (pin + hash + never
    vendor/modify/redistribute).
11. "mimikatz has no license" — README-declared CC BY 4.0 since 2015.
12. "trufflehog moved SSPL→AGPL" — license added once (2022), AGPL
    verbatim; no such history exists.
13. "Cobalt Strike $5.9k/user/yr 2023" — dead-as-cited; official pages
    quote-only.
14. "Havoc has no canonical successor" — commercial Havoc Pro continues
    the line (reseller-sourced); "no *open-source* successor with headless
    API" survives.
15. CALDERA rules coverage grade 40% → **~25%**: planner-path only,
    manual REST tasking bypasses, rule source mutable.
16. "Rubeus `/console`" — does not exist; `/nowrap` + `/consoleoutfile:`.
17. PingCastle "custom non-commercial" — actually Non-Profit OSL 3.0
    (licensor-side clause; copyleft + external-deployment on distribution).
18. Design kills recorded for the v2 build: "zero new methods"
    (signature break + axis collision + no migration path), hop_depth
    column (unobservable fabrication), `detected` as reconcile outcome
    (moral hazard + wrong layer), `INSERT OR REPLACE` roe_digest
    (evidence-integrity hole), clockskew workaround (rootless shares the
    host clock — non-problem).
