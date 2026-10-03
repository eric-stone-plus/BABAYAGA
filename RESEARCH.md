# RESEARCH.md — The Spending Engine: External Survey and Adoption Roadmap

- Research dates: 2026-09-28 (main survey), 2026-10-03 (NSA-org /
  Ghidra adjacency round, §1.5), and 2026-10-03 again (phase-2
  mission re-evaluation, §1.6). External data (repository metrics,
  licenses, versions, standards text) is as of the fetch date stamped
  on the claim; every drifting figure carries its own fetch date.
- Source: a goal-mode adversarial research swarm — four parallel survey
  axes (engine internals / credential-attack tooling / attack-framework
  governance / runtime and protocol libraries), then a second round in
  which two attacker subagents tried to kill every load-bearing claim.
  The research was read-only: it changed no upstream files and cloned
  nothing outside temporary scratch.
- Round 2 (2026-10-03): adjacency survey of Ghidra
  (NationalSecurityAgency/ghidra) and the full NationalSecurityAgency
  GitHub organization (89 repositories at fetch date), to decide
  whether any of it belongs in the spending engine. Primary-source
  pass (GitHub REST API, releases page, verbatim
  LICENSE/README/GettingStarted reads) followed by one adversarial
  killer pass; killed claims and corrections are recorded in §5, the
  acceptance note in §6.
- Material scope: **lawful public sources only**. Upstream tools are
  surveyed where they publish; nothing leaked or unlicensed is fetched,
  read, or adopted. An engine whose premise is authorized-only operation
  with sealable evidence cannot adopt a technique that cannot prove its
  provenance.
- Working assumptions of this survey (not yet decisions): an independent
  public repository; original files AGPL-3.0-or-later; instruments cited,
  never vendored; English prose.
- Acceptance: see the stamp at the bottom.

## 0. One-line conclusion

**Nobody ships the gate.** Across twelve surveyed attack frameworks and
every surveyed credential tool, not one enforces a machine-readable
authorization object, and exactly one tool (SprayHound) reads the
target's actual lockout policy before guessing. The instruments —
hydra, hashcat, NetExec, kerbrute — are mature, permissively citable,
and already JSON-checkpointed; what is missing is the gate layer
itself: fail-closed scope, ROE-as-data, event-sourced state, seals,
and a **lockout-policy throttle** whose default ceilings are derived
from a published standard (NIST SP 800-63B-4 §3.2.2). BABAYAGA is that
layer over unchanged external instruments. Almost everything else this
survey found is a pattern to cite, not a component to build.

Reconnaissance doctrine deliberately terminates at the door: valid
credentials are reported and never spent. But a credential never spent
is a claim, not a proof — and the spending side is where authorization
matters most, because a guess is an irreversible act against a target.
BABAYAGA is the engine for that side: it spends, under its own
authorization gate, and exports what it proves in an
`access`/`grants_access` vocabulary a reconnaissance engine can ingest.

The 2026-10-03 adjacency round (§1.5) looked where offensive
capability concentrates naturally — the NSA's public portfolio,
Ghidra above all — and found the same shape: a reverse-engineering
framework and defender tooling, archived test-PKI and key-custody
utilities, and not one tool that spends a credential. The negative
finding survives a second, unrelated corpus. (Under the phase-2
operator identity of §1.6 the framework itself is in scope as the RE
instrument — the negative finding is about *spend*, and stays true.)

## 1. Fusion verdicts for the instrument layer

All instruments below are driven as external binaries through the
executor seam, never vendored. Licenses were read from the LICENSE
files in-repo, not from README badges.

### 1.1 Network credential testing

| Tool | Upstream | License (read from file) | Activity at 2026-09-28 | Verdict |
|---|---|---|---|---|
| THC-Hydra | vanhauser-thc/thc-hydra | **AGPL-3.0**, stock text (diffed against SPDX canonical; zero THC additions). README carries a non-binding author's wish ("do not use in military or secret service organizations") that is prose, not a license term | pushed 2026-07-30, v9.7 (2026-05-03), ~12.3k★ | **Adopt as primary C instrument.** Fork-per-host model (`hydra_head{pid, sp[2]}` in hydra.c), `-t` per-target (default 16, MAXTASKS 64) / `-T` overall, `-W`/`-c` pacing, `-D XofY` wordlist segmentation, `hydra.restore` checkpoint, and the best output contract of the field: `-b jsonv1` with a documented versioned schema |
| Medusa | jmk-foofus/medusa | **GPL-2.0** (+OpenSSL exemption in source header) | pushed 2025-05-14; slow but alive | **Pattern only.** Runtime-`dlopen` `.mod` modules (add a service without touching core — the closest existing analog to BABAYAGA's plugin seam), per-host pthread pools, and the only measured **adaptive backpressure** (`addMissedCredSet()`: on service-side thread death, decrement the host's thread count and re-queue the orphaned credentials). Resume exists (`-Z` resume map) — an earlier "no resume" reading was killed in round 2 |
| Ncrack | nmap/ncrack | **GPL-2.0 + Nmap Special Exception**, and the exception is the strongest license trap found: COPYING declares a derivative any application *"designed specifically to execute Covered Software and parse the results (as opposed to typical shell or execution-menu apps)"* | pushed 2024-04-14; dormant-ish | **Not adopted as an instrument** (see §4). **Adopt the vocabulary:** `-T0..-T5` timing templates, per-service `cl/CL` connection floors/ceilings, `at` auth-tries-per-connection, `cd` delay, `--stealthy-linear` — the right interface shape for BABAYAGA's throttle, even though ncrack itself is left out. Its `-oX` is unimplemented per its own man page |
| Patator | lanjelot/patator | **GPL-2.0** | pushed 2025-05-20, v1.1.0 | **Pattern only.** Payload sets as cartesian products (`FILE0`, `COMBO00`, `RANGE`) with `--start/--stop` offsets and a `--resume r1,r2,…` position tuple (verified: a plain tuple, not XML); the `-x ignore:mesg='…'` **failure-semantics classifier** is the result-classification pattern BABAYAGA needs. Note: workers are `multiprocessing.Process`, not threads, despite the `--threads` flag name |

### 1.2 Offline cracking

| Tool | Upstream | License | Activity | Verdict |
|---|---|---|---|---|
| Hashcat | hashcat/hashcat | **MIT** — `docs/license.txt` (no root LICENSE file; GitHub reports null — badges lie) | pushed 2026-09-28; v7.1.2 (2025-08-23); ~27k★ | **Adopt as the offline orchestrator target.** `--status-json`, `--machine-readable`, `--session/--restore/--restore-file-path/--restore-position`, `--outfile-check-*`, `--potfile-path`; `--brain-server`/`-z` for cross-instance dedup (default port 6863). PRINCE is **not** in core — it lives in hashcat/princeprocessor and pipes via stdin |
| John the Ripper (jumbo) | openwall/john (bleeding-jumbo) | **GPL-2.0+** with OpenSSL/unRAR exceptions and per-file BSD islands (file-by-file analysis required) | commits 2026-09-28 (rolling) | **Adopt as second instrument + pattern.** `--session/--restore/--status/--catch-up`, `--fork=N`, **`--node=MIN[-MAX]/TOTAL`** built-in keyspace split, `--rules-stack`, PRINCE integrated (`--prince`). Pattern value: node splitting and rules stacking; orchestration surface weaker than hashcat's JSON |

### 1.3 Spray and post-validation

| Tool | Upstream | License | Activity | Verdict |
|---|---|---|---|---|
| NetExec | Pennyw0rth/NetExec | **BSD-2-Clause** | pushed 2026-09-27; v1.5.1 (2026-02-23) | **Adopt as instrument.** Successor of CrackMapExec; protocols smb/ssh/ldap/ftp/wmi/winrm/rdp/vnc/mssql; `--jitter`, `--continue-on-success`, `--no-bruteforce` (1:1 pairing); `--sam/--lsa/--dpapi` harvesting; **per-protocol workspace DBs at `~/.nxc/workspaces`** — the durable credential store pattern to mirror. No `--pw-spray` flag exists (killed); no `--json` flag (measured) |
| kerbrute | ropnop/kerbrute | **Apache-2.0** (not MIT — round 1 guessed wrong) | functionally frozen since 2024; last release 2019 | **Adopt as instrument.** `userenum/bruteuser/bruteforce/passwordspray`; honest README: pre-auth failures avoid classic 4625 events **but still count toward lockout**; `--safe` aborts all threads on a locked account. Its threat-model honesty is itself the pattern |
| SprayHound | Hackndo/sprayhound | **MIT** | commits 2026-06-14 | **Adopt as instrument + adopt its core idea.** With any valid domain account it reads the lockout policy and per-user `badPwdCount`, **skips users too close to the threshold** (`-t/--threshold`, `--unsafe` to override) — the only policy-aware tool found in the entire survey |
| o365spray | 0xZDH/o365spray | MIT | pushed 2024-11-06 | Adopt as instrument; `--count/--lockout/--sleep/--jitter` lockout-timer semantics |
| MSOLSpray | dafthack/MSOLSpray | MIT | pushed 2024-03-19 | Adopt as instrument; Azure AD **error-code → action mapping** (locked/MFA/disabled/tenant) |

### 1.4 Candidate generation and corpora — the licensing minefield

| Item | Upstream | License | Verdict |
|---|---|---|---|
| CeWL | digininja/CeWL | **dual CC-BY-SA-2.0 / GPL-3+ declared in the source header; no LICENSE file** | Instrument (site-derived wordlists, metadata usernames) |
| username-anarchy | urbanadventurer/username-anarchy | MIT | Instrument (username format engine, plugin formats) |
| SecLists | danielmiessler/SecLists | **MIT (root file)** but no per-file provenance manifest; rockyou-lineage contents inherit rockyou.txt's permanently murky status (breach corpus, never licensed) | **External user-supplied data, never vendored or redistributed** by BABAYAGA |
| OneRuleToRuleThemAll | NotSoSecure/password_cracking_rules | MIT **file**, composite content ("Rules taken from other ruleset will follow respective license" — README) | Shape only; never redistribute |
| ns-rules (dive lineage) | NSAKEY/nsa-rules | **Fair License** (round 1 said "no license" — killed in round 2; it is permissive) | Usable rules; the *original* dive.rule's author remains unattributed anywhere reachable — do not cite |
| Hob0Rules | praetorian-inc/Hob0Rules | **no LICENSE file** → all-rights-reserved; also ships rockyou.txt.gz | Not redistributable; reference only |
| Hashtopolis | hashtopolis/server | **GPL-3.0** (round 1 guessed AGPL — corrected) | **Pattern only**: server/agent/chunk delegation for distributed hashcat is the farm design; no code |

### 1.5 Reverse-engineering adjacency — Ghidra and the NSA org (2026-10-03)

Question put to the survey: does anything in
NationalSecurityAgency/ghidra, or in the wider NationalSecurityAgency
org (89 repositories at fetch date), belong in a credential-spending
engine? **No.** Ghidra is a software reverse engineering framework —
disassembly, assembly, decompilation, graphing, and scripting (README
verbatim) — with no credential-guessing, spraying, or cracking surface
of any kind: it never sends a guess anywhere. Its GhidraServer tree
does ship login modules (password-file, JAAS, Kerberos, PKI, SSH), but
those are verifier-side authentication for the collaboration server —
a login is enforced, never guessed. The org's credential-adjacent
projects are archived test-PKI and key-custody tools. Nothing here
spends.

| Item | Upstream | License (read from file) | Activity at 2026-10-03 | Verdict |
|---|---|---|---|---|
| Ghidra | NationalSecurityAgency/ghidra | **Apache-2.0** at the root (LICENSE read verbatim) — but the tree is **not uniformly Apache**: a top-level `GPL/` directory ships GNU-derived components (DemanglerGnu, GnuDisassembler — "leverage the binutils disassembler capabilities", README verbatim) and `GPL/licenses/` holds GPL-2, GPL-2+Classpath, GPL-3, GPL-3-linking-permitted, LGPL-2.1 (incl. an LGPL-2.1 icon-set text), LGPL-3.0, and Public-Domain texts. GitHub's badge says Apache-2.0; the distribution is mixed — same badge-vs-tree shape as hashcat's null LICENSE (§1.2) | pushed 2026-09-30; v12.1.4 (2026-09-21, `Ghidra_12.1.4_build`, release SHA-256 published on the release page); ~80.3k★ | **Not adopted as instrument or dependency** (§4). Two contact surfaces recorded: (a) headless batch mode — README verbatim "can be run in both user-interactive and automated modes", entry point `<GhidraInstallDir>/support/analyzeHeadless` per GettingStarted.md — so Ghidra is *drivable* through the executor seam like any external binary; that surface is kept for the authoring-time trigger below, never for the runtime loop; (b) the license composition is a standing caution: citation and argv only, and the tree must never be bundled or redistributed with ours |
| ghidra-data | NationalSecurityAgency/ghidra-data | Apache-2.0 ("governed by the same licensing … as Ghidra", README verbatim) | pushed 2026-09-04; 218★ | Not adopted. FID databases and data-type archives for the SRE workflow — data, not instruments |
| ghidra-volatility, ghidra-frida, ghidra-lisa, ghidra-extensions | same org | `NOASSERTION`/none (GitHub API `license.spdx_id`) | pushed 2025-03 → 2026-01 | **Not adopted.** Trace/analysis extensions (README verbatim): Volatility-based analysis of QEMU targets via Ghidra traceRMI; Frida-based analysis via traceRMI; abstract-interpretation/taint extension (LiSA); a low-support extension dump ("CAVEAT EMPTOR"). ghidra-volatility (a Volatility *command bridge* — hashdump-class recovery lives in Volatility's own plugins), ghidra-frida (live-process memory, registers, stacks), and ghidra-lisa (taint queries) can all touch credential *material* — and that is always harvesting: the reconnaissance side of the door, handed over under §2.4's sealed-export contract (BABAYAGA then cracks via hashcat), not a spending capability |
| MADCert (archived) | same org | **MIT** (LICENSE.md read from file; GitHub's classifier reports `NOASSERTION` — its "The MIT License" heading defeats the detector, a badge-lie instance) | archived; pushed 2025-02-03 | Not adopted. Test-PKI factory (root/intermediate CAs, user and server certs) — a plausible fixture generator for the B14 lab, but archived; the lab builds its own fixtures rather than take a dependency on a dead repo (permissive license, so the refusal is maintenance, not redistribution) |
| kmyth, pelz (archived) | same org | Apache-2.0 each | archived 2024 | Not adopted. Key-material custody — kmyth: TPM seal/unseal + KMIP utilities; pelz: KMIP-backed key wrap/unwrap service on SGX, plus an Accumulo crypto plugin. No PKCS#11 surface in either (attacker-checked); none of it guesses a credential |
| lemongraph | same org | `NOASSERTION` | pushed 2026-04-30; ~1.2k★ | Not adopted. "Log-based transactional graph engine" is the nearest architectural cousin to the event-sourced attempt ledger + `access`/`grants_access` export (§2.4, B3) — take it as confirmation of the shape, no code; the ledger schema is already adjudicated |
| seabee | same org | `NOASSERTION` | pushed 2026-09-30 | Not adopted. eBPF policy hardening against privileged attackers — host defense on the other side of the gate question |
| Remainder of the org (78 repos) | same org | Apache-2.0 / BSD-2 / BSD-3 / GPL-2.0 / Other, per repo | mostly 2019–2026 | **Out of scope.** The datawave/timely/Accumulo big-data stack (~40 repos), qgis-* ×13, and one-offs (emissary, skills-*, Foundation formal-crypto specs, TraceAnalysis, openflame, dnf-model-counting, qonduit, call-stack-profiler, lemongrenade, XORSATFilter, enigma-simulator, PACE/PACE-python, SIMP, maat, DCP, accumulo-python3, rank-based-linkage, fractalrabbit) — query stacks, GIS plugins, trajectory simulation, attestation, file copy, an Enigma teaching notebook; none of it spends a credential (the kill scan's nearest miss was datawave-authorization-service, a JWT *verifier* endpoint). Recorded so the org is not re-scanned piecemeal |

**Deferred with trigger (recorded so it is not re-proposed):** Ghidra
as an *authoring-time* adjunct, never a runtime instrument. If an
engagement needs an instrument module for an auth scheme that cannot
be built from documented protocol behavior — an undocumented custom
hash or wire format in a client or server binary — headless scriptable
analysis is the standard way to recover the scheme's shape before
writing the module. That work happens outside the engine, sees no
credentials, and lands as a module like any other (§1 preamble:
external binary, its own repo and license). Until such an engagement
exists, Ghidra is not installed, not cited as a dependency, and
appeared in no manifest at survey time (§1.6 later re-judges the
adoption and the tree state).

### 1.6 Mission re-evaluation — the phase-2 identity (2026-10-03)

Operator redesign (2026-10-03): BABAYAGA is the **phase-2 operator** of a
pentest — reverse engineering, lateral movement, credential spending —
where phase-1 reconnaissance stands. §1.5 answered the *spend-only*
question ("does anything here spend a credential?"); its facts stand, its
adoption verdicts are mission-scoped and are re-judged here against the
phase-2 mission (RE / lateral / spend / candidate-generation / lab
fixtures). Primary-source re-check same day; root license probes
(LICENSE, LICENSE.md, LICENSE.txt) were initially read as a provenance
check and are not one — the adversarial pass below replaced them with
recursive tree search (errata at the end of this section).

| Item | §1.5 verdict | §1.6 verdict (phase-2) | Reason |
|---|---|---|---|
| ghidra | Not adopted | **ADOPT as the RE instrument** (FLIP) | The RE framework, first-class under the phase-2 mission: `analyzeHeadless` drives through the executor seam like any external binary (§1.5's own deferred note generalized to the mission). License caution UNCHANGED and becomes a manifest note: Apache-2.0 root over a `GPL/` GNU-derived subtree (DemanglerGnu/GnuDisassembler, binutils lineage) — citation + argv only, never bundled, never vendored |
| ghidra-data | Not adopted ("data, not instruments") | **ADOPT as the RE data pack** (FLIP) | FID databases + type archives are the decompiler's fuel — companion data in the nuclei-templates shape: mirrored, loaded at RE time, never a code dependency. Apache-2.0 (LICENSE read from file, 2026-10-03) |
| ghidra-frida | Not adopted | **ADOPT as the dynamic-RE extension** (FLIP) | The code deliverable — the `ghidrafrida` Python package at `src/main/py/` — is **Apache-2.0** (`src/main/py/LICENSE` + pyproject.toml classifier, in-tree since 2024-04-25); provenance is provable and the §1.5 exclusion dies. Frida-based tracing via traceRMI is core dynamic RE. Runtime dep on Frida itself is unvendored (argv/extension, never a code dependency). Scope caveat: the non-py trivia (build.gradle, Module.manifest) carries no headers (unverifiable U1) |
| ghidra-lisa | Not adopted | Not adopted (stands, reason sharpened) | Taint / abstract-interpretation queries are RE value, but a recursive tree search (94 paths) finds **zero** license/copying/notice files anywhere — including for the bundled third-party LiSA library (U4). The §1 provenance doctrine applies here and only here among the three satellites |
| ghidra-volatility | Not adopted | Not adopted — copyleft trap (reason replaced) | Two **VSL-1.0** texts license the Volatility side (`VOLATILITY_LICENSE.txt`, `src/main/py/LICENSE.txt`; the API's `NOASSERTION` is a *detected* file, not absence). VSL "Additions" explicitly reaches "any software designed to execute the software and parse its results, such as a wrapper" — a **copyleft obligation over the bridge**, in the mysqlclient-contamination shape §2.3 already refused. Not a provenance void; a worse one. Re-evaluate trigger: license interpretation settles (U2) or upstream relicenses |
| ghidra-extensions | Not adopted | Not adopted (stands) | CAVEAT EMPTOR dump, no license |
| MADCert | Not adopted (archived) | Stands, with a lab note | The phase-2 lab (B14) now needs AD/PKI fixtures and MADCert is a plausible factory, but it is archived — the lab still builds its own fixtures rather than depend on a dead repo |
| kmyth, pelz, lemongraph, seabee, PACE | Not adopted | Stands | Key custody / ledger cousin / host defense / Accumulo at-rest crypto — none is RE, lateral, or spend |
| TraceAnalysis | Not named (lost in the one-off list) | **ADOPT as the dynamic-trace RE suite** (FLIP) | Execution-trace generation/analysis: `ghidra-lifter`, the `ghidra-tracemadness` Ghidra module, dynamic-dataflow plugins (`pointsto`, `fntrack`, `cbranch`, `fpmodels`, `syscalls`), and five tracer backends (QEMU-user / Unicorn / PIN / PANDA / icicle). Dual **Apache-2.0/MIT** (`LICENSE-APACHE` + `LICENSE-MIT`) — the org's best-licensed RE candidate after ghidra core. Per-component pinning lands in manifests when first driven |
| Remainder of the org (77 repos) | Out of scope | Stands | Re-screened name-by-name in the adversarial pass: nothing else is RE, lateral, or spend; the nearest remains datawave-authorization-service, a JWT *verifier* (verifier-side — enforced, never guessed). Opaque-named repos (XORSATFilter, dnf-model-counting, rank-based-linkage, fractalrabbit, qonduit) were judged on descriptions only (U3) |

§0's negative finding ("nothing in the NSA org spends a credential")
stands as a fact. What changed is the adoption criterion: a phase-2
operator looks for RE and lateral capability as well as spend.

**Killed during the §1.6 adversarial pass (2026-10-03, recorded not
dropped):** (1) "ghidra-frida has no LICENSE" — false: `src/main/py/LICENSE`
is Apache-2.0, in-tree 17 months; the root-only probe was the wrong
depth and the verdict flipped to adopt. (2) "ghidra-volatility has no
LICENSE" — false: VSL-1.0 texts exist; the real risk is the VSL
"Additions" copyleft over wrappers, so the exclusion stands on a
different (worse) ground. (3) "root probes consistent with
NOASSERTION" — false: three of four APIs report `null`, and the one
`NOASSERTION` is a detected VSL file; root-only filename probing can
never support a no-license conclusion. (4) "nothing in the remainder is
RE-class" — false: TraceAnalysis is a dual-Apache/MIT execution-trace
RE suite with a Ghidra module inside it. Survived intact: ghidra +
ghidra-data adoptions (analyzeHeadless verified from
analyzeHeadlessREADME.md), ghidra-lisa's no-license-anywhere finding,
the README characterizations of all three satellites, and the 89/78/77
arithmetic.

## 2. Patterns

### 2.1 Instrument-layer engineering (what the last 20 years got right)

- **Rate vocabulary already exists in three dialects** — ncrack's named
  templates `-T0..-T5`, Metasploit's integer map
  (`BRUTEFORCE_SPEED` 0→300 s, 1→15 s, 2→1 s, 3→0.5 s, 4→0.1 s, 5→0;
  `userpass_interval`, `lib/msf/core/auxiliary/auth_brute.rb:750`,
  verified verbatim), and per-flag pacing (hydra `-W/-c`, patator
  `--rate-limit`, ffuf `-rate` + `-p 0.1-2.0` random-range jitter,
  NetExec `--jitter 2-5`). BABAYAGA adopts the *named-level* dialect:
  auditability in the ROE beats freeform sleeps.
- **No surveyed tool implements a token bucket** — fixed delay plus
  concurrency caps is the state of the art; golang.org/x/time/rate
  (BSD-3) is the permissive reference algorithm if one is ever needed.
- **Checkpoints are session files** — hydra `hydra.restore` (5-minute
  writes, platform-locked binary struct, hardened open), hashcat
  `.restore` + `--restore-position`, john `NAME.rec` + `--catch-up`,
  medusa `-Z` map, patator position tuples. Distribution is segments
  (hydra `-D XofY`) or nodes (john `--node`) or brain dedup (hashcat).
- **Failure semantics as data** — patator's `-x ignore/retry/reset`
  conditions and MSOLSpray's error-code table are the two existing
  shapes of "classify the refusal before the next guess".
- **Option vocabulary is settled** — MSF's `auth_brute` mixin
  (`USERPASS_FILE`, `STOP_ON_SUCCESS`, `PASSWORD_SPRAY`,
  `TRANSITION_DELAY`, `ABORT_ON_LOCKOUT` in smb_login) is a
  battle-tested surface BABAYAGA's rule schema can reuse wholesale;
  `BATCHMODE` no longer exists upstream (do not cite it).
- **The normalized credential model is solved** — Metasploit's
  `metasploit-credential` gem: `public/private/realm → core → login`
  with `status` + `last_attempted_at` per (core, service), Private
  subclassed by type (password, ntlm_hash, ssh_key, krb_enc_key …).
  Take the shape (BSD-3), not the code.

### 2.2 Governance and standards — the negative finding that justifies the project

**Machine-readable authorization gating: zero hits in twelve trees.**
Round 2 ran full recursive filename scans (GitHub trees,
`truncated=false`) over metasploit-framework (14,977 files), caldera
+mitre/stockpile (390/351), atomic-red-team (1,376), Infection Monkey
(3,148), routersploit (1,216), Nettacker (867), axiom (200), osmedeus
(1,197), DomainPasswordSpray (3), NetExec (297), king-phisher (356):
no ROE/authorization/scope/kill-switch object exists upstream. Every
regex hit was a false positive (API-client whitelists, linter configs,
exploit names). Workspaces (MSF) and scan-target lists (Monkey) are
data partitioning and input, not authorization. Scope caveat: filename
+ targeted content checks, not full-content grep. **A fail-closed ROE
gate remains structurally novel in this space**; B1 adopts SP 800-115
Appendix B fields as an executable object — relocated, not re-researched.

**Lockout hygiene: one policy reader in the field.** SprayHound alone
reads the target's policy; kerbrute/MSF react post-hoc
(`--safe`/`ABORT_ON_LOCKOUT`); hydra/medusa/hashcat/john have nothing
beyond raw `-t`. A generalized **lockout-policy engine** (per-principal
attempt ledger + policy probe + skip/abort) is unclaimed territory.

**Standards anchors (all verified at source):**

- **NIST SP 800-63B-4 §3.2.2 "Rate Limiting (Throttling)"** (final
  2025-07-31; supersedes 800-63-3 — round 1's §5.2.2 citation was
  killed as stale): the verifier SHALL limit consecutive failed
  attempts on a single account to **no more than 100** (explicitly an
  upper bound; agencies MAY go lower) and MAY use progressive delay
  "**e.g., 30 seconds up to an hour**". These are the defender's
  contract numbers; BABAYAGA's default throttle ceilings are derived
  from them (well below 100, progressive).
- **MITRE ATT&CK T1110** sub-techniques verified (content v19.2):
  .001 Password Guessing, .002 Password Cracking, .003 Password
  Spraying, .004 Credential Stuffing — the closed action vocabulary for
  BABAYAGA's rule classes. Terms of Use permit redistribution with
  MITRE's copyright designation and license reproduced. Machine-
  readable source: mitre-attack/attack-stix-data versioned bundles.
- **NIST SP 800-115** §6.5 + Appendix B (ROE template) — the B1 gate's
  field vocabulary; adopted, not re-derived.

### 2.3 Runtime and protocol libraries — the stdlib verdict

Measured runtimes of the references: hydra/medusa/ncrack are C/C++
(processes/pthreads/nsock), patator is multiprocessing Python,
NetExec is ThreadPoolExecutor Python (default parallelism in the
hundreds; two rounds read different defaults — 100 vs 256 — the number
is version-drifted and non-load-bearing), ffuf is goroutines. **No
maintained asyncio-native multi-protocol engine exists on PyPI**
(negative finding, relevance-page-1 scope).

Protocol library matrix (license-first; single-source rows marked in
§5): SSH — paramiko **LGPL-2.1**, asyncssh **EPL-2.0 OR GPL-2.0+**
(dual), libssh2 BSD-3; SMB — impacket **modified Apache-1.1** ("The
Apache Software License, Version 1.1, Modifications by Fortra" — not
Apache-2.0; GitHub itself says NOASSERTION), pysmb **zlib-license**,
smbprotocol MIT, go-smb2 BSD-2; WinRM — pywinrm MIT; Kerberos — pykrb5
MIT, gokrb5 Apache-2.0; LDAP — ldap3 **LGPL-3.0, stale since 2021**,
go-ldap MIT; MySQL — PyMySQL MIT (mysqlclient is **GPL-2.0+** — a dep
would contaminate); PostgreSQL — psycopg2 LGPL+exceptions; Oracle —
oracledb UPL-1.0 OR Apache-2.0; Mongo — pymongo Apache-2.0; Redis —
redis-py MIT; RDP — **no maintained pure-Python client** (negative
finding; FreeRDP itself is Apache-2.0 as a binary).

**Verdict: BABAYAGA stays stdlib-only.** Python's stdlib covers
HTTP/1.1+TLS, raw sockets, and the mail protocols; every other protocol
rides an external binary through the executor seam. A native-protocol
engine would import LGPL/EPL/Apache-1.1 dependencies into an AGPL
distribution for throughput the instrument layer already delivers.
Deferred with trigger: an optional `[native]` extra bundling only
permissive stacks (smbprotocol/pywinrm/PyMySQL) if a stdlib-only seam
ever proves insufficient — recorded so it is not re-litigated.

### 2.4 Core module decisions (the safety seam)

Adjudicated per module at the 2026-09-28 seed. The round-1 "adopt an
external engine package as a dependency" idea was **killed**: no
surveyed engine package offers a library-API stability promise, and a
dependency would import another project's doctrine drift into the
safety case. Every core module is native authorship (NOTICE); the
safety-critical ones are registered in `engine/babayaga/PROVENANCE.md`
and change only with an operator sign-off note.

| Module | Decision | Rationale |
|---|---|---|
| `scope.py` | Native, review-critical | Label-boundary matching, out-of-scope precedence, ∀-IP discovery rule, `bind_ip` pinning, redirect/SAN checks — 100% target-agnostic; a defect here is a *safety* defect, not a bug |
| `opsec.py` | Native, review-critical | WAF sensing, canary guards, per-origin CooldownBoard with snapshot/restore — extended per-principal for lockout counters |
| `egress.py`, `cmd.py`, `executor.py`, `secret_transport.py` | Native, review-critical | The secret-never-in-argv contract (cmd.py SECRET_KEYS, `@env:` diversion; executor env guard) is the engine's most important hygiene seam; file-argument transports ride the memfd `/proc/self/fd/N` pattern |
| `ledger.py` + `schema.py` | Native, own schema | Event+row-in-one-transaction, flock single-writer, CAS state changes; attempt ledgers are high-write-rate state, so the schema is event-sourced attempts rather than entity snapshots. The export speaks the reserved `access` kind + `grants_access`/`escalates_to` edge vocabulary |
| `confidence.py` | Native, review-critical | The priors `kerbrute: 0.85`, `hydra: 0.90` and the `credential_usable` hard-evidence signal were seeded for exactly this engine |
| `state_machine.py`, `rulecheck.py` | Native | Pure transition tables + forbidden-actor + derived drift-audited registries; the attempt lifecycle is flat (`queued→running→result{valid\|invalid\|locked\|error}`); the checker makes throttle flags *required* on every rule (the B10 inversion) |
| `seal.py` | Native | Seal = db content digests + integrity triple + census + provenance, one JSON file; re-seal re-attests (no chain field yet — the exported manifest digest anchors out-of-band); gated on fold == materialized rows |
| Dispatch gate ordering | Native | The ACT ordering canary → cooldown → scope → recheck → render → dedup is load-bearing: every cheaper gate runs before every dearer one, and scope is re-checked after cooldowns |
| Sealed reconnaissance exports | **Consume** | A sealed-export manifest is the handoff contract: BABAYAGA ingests sealed credential/asset findings as campaign inputs, spending what observe-only doctrine reports but never uses |

## 3. Adoption roadmap: B1–B15

Ordering: gates and seams first, instruments second, corpora and farms
last. ★ = top five by cost/benefit (B1, B2, B4, B3, B9).

| # | Adoption | Source | Cost / benefit |
|---|---|---|---|
| **B1** ★ | **ROE-as-data launch gate** — SP 800-115 Appendix B fields as an executable object, extended with BABAYAGA-specific fields: per-target attempt budgets, lockout thresholds, `authorized_hours`, denied areas; produced case-init style; hashed into the seal manifest; fail-closed | SP 800-115 App.B + reverse-skill pattern | Medium / **highest** — the project's reason to exist (§2.2's zero-gating finding) |
| **B2** ★ | **Lockout-policy engine** — per-(principal, origin) attempt ledger; default ceilings derived from SP 800-63B-4 §3.2.2 (far below the 100 upper bound; progressive delays toward the 30 s–1 h shape); SprayHound's policy-probe + skip; kerbrute `--safe` / MSF `ABORT_ON_LOCKOUT` semantics generalized to every module | §2.2 anchors | Medium / **very high** — unclaimed territory |
| **B3** ★ | **Credential entities + attempt ledger** — the export speaks the reserved `access` kind and `grants_access`/`escalates_to` edges; MSF public/private/realm/core/login vocabulary as shape; outcomes (not per-guess) are events; ingest sealed reconnaissance findings as inputs | metasploit-credential (BSD-3, shape) + the access/grants_access vocabulary (§2.4) | Medium / **very high** |
| **B4** ★ | **Instrument layer** — parsers + rules for hydra (`-b jsonv1`), hashcat (`--status-json`, potfile), NetExec (workspace DB ingest), kerbrute, patator (hits CSV/XML), SprayHound/o365spray/MSOLSpray; secret-transport extension for file arguments (memfd `@fd:` lists); the two pre-seeded confidence priors gain producers | §1 + the executor seam | Medium / **very high** |
| **B5** | **Throttle vocabulary** — named levels (ncrack `-T` / MSF 0–5 dialects), ffuf-style random-range jitter, per-origin in-flight caps, per-protocol `at/cd/CL` ceilings; a rule without throttle flags is a corpus defect (the M15 inversion) | §2.1 | Small / high |
| **B6** | **Candidate provenance** — every wordlist/rule file carries a provenance manifest (origin, license, hash); SecLists is a user-supplied path, never vendored; redistribution matrix from §1.4 (Fair-License ns-rules usable; Hob0Rules and rockyou never) | §1.4 | Small / high |
| **B7** | **Checkpointing** — per-campaign session restore files (hydra/hashcat pattern), position-only restore, segment/node distribution hooks (hydra `-D`, john `--node`) left as future seams | §2.1 | Small / medium |
| **B8** | **OPSEC inheritance** — WAF-sensing gate on spray rules, canary guards, one-UA-per-engagement, `cmd_stealth` variants; CooldownBoard extended per-principal | opsec.py (§2.4) | Small / high |
| **B9** ★ | **Credential-material hygiene** — masked `***` representations in every event/digest/seal; values only via env-name indirection + memfd transports; plaintext passwords never in argv, logs, or artifacts; the credential store is the only plaintext surface and is access-guarded | cmd/executor/secret_transport (§2.4) | Medium / **very high** — the inverted doctrine demands it |
| **B10** | **Corpus checker re-instantiation** — AST-derived producer/consumer model, `--strict` CI gate, derived outcome-class registry with drift audit (valid-credential / sprayed / locked / cracked …) | the corpus-checker pattern (§2.4) | 1–2 days / high |
| **B11** | **ATT&CK T1110.001–.004 as the action-class vocabulary**, pinned to a STIX release, MITRE attribution line reproduced per ToU | §2.2 | Small / medium |
| **B12** | **Budget gate** — wall-clock + total-attempts + USD caps per campaign; over-cap fails closed and seals | the B1 fail-closed gate doctrine | Small / high |
| **B13** | **Re-adjudication from sealed evidence** — a replay command recomputes campaign outcomes from the event log without re-running tools; a "valid" credential promoted only on hard evidence (`credential_usable`), never tool self-report | confidence.py + the replay-verdict pattern | Days / high |
| **B14** | **Replay fixtures / lab targets** — a local lab (ssh/ftp/http-form/smb containers) so the engine and its gates are exercised end-to-end with zero real targets; fixtures generated from sealed evidence | the digital-twin lab pattern | Small / high |
| **B15** | **Crack farm** (deferred) — hashcat brain for multi-instance dedup now; Hashtopolis-pattern task/agent/chunk delegation only if a farm is ever justified; triggers recorded | hashcat + Hashtopolis (pattern only, GPL) | Deferred |

## 4. Explicitly not adopted (recorded to prevent re-proposal)

| Item | Reason |
|---|---|
| **ncrack as a driven instrument** | The Nmap Special Exception *declares* derivative any app "designed specifically to execute Covered Software and parse the results"; a dedicated ncrack parser sits exactly in that reading, and its `-oX` is unimplemented anyway. The generic multi-tool posture (hydra primary) stays inside the carve-out. Its `-T` vocabulary is still adopted — vocabulary is not combination |
| Vendoring AGPL/GPL code (hydra, medusa, patator, Hashtopolis, Infection Monkey, GoLismero, Legion) | Patterns and ideas only; instruments keep their repos and licenses |
| Native protocol stacks as dependencies (paramiko, asyncssh, impacket, ldap3, …) | §2.3 verdict: stdlib-only engine + external binaries; the license spread (LGPL-2.1 / EPL-2.0 / modified-Apache-1.1 / GPL-2.0) makes any bundle a permanent audit surface for zero instrument-layer gain |
| asyncio engine rewrite | No measured precedent in the field; the orchestrator is IO-light and instruments do the concurrent work |
| `rockyou.txt` and Hob0Rules redistribution | No license / all-rights-reserved; breach-corpus provenance can never be stated in a manifest |
| Metasploit as a driven instrument | Its option vocabulary and credential model are adopted as patterns (BSD-3, citable); driving msfconsole as a subprocess buys nothing over the dedicated instruments |
| RDP native support | No maintained pure client library (measured); if ever needed, FreeRDP (Apache-2.0) rides the executor like any binary |
| Go/Rust core rewrite | The orchestrator is IO-bound and the heavy tools are already native — a rewrite buys throughput the instrument layer already delivers |
| LLM-driven attempt planning | Unguided LLM agency benchmarks bound this class (12–18%); BABAYAGA's scheduler is deterministic — an LLM may propose wordlist hypotheses but never transitions attempts (forbidden-actor pattern) |
| Ghidra as an instrument or dependency | It reverse-engineers binaries; it never guesses a credential (§1.5 — its GhidraServer login modules are verifier-side authentication). The one legitimate contact surface — headless analysis while *authoring* a module against an undocumented auth scheme — is authoring-time work that sees no credentials and ships as a normal external-binary module. The `GPL/` GNU-derived tree inside an Apache-2.0 root also rules out any bundling: citation and argv only, like every instrument |
| NSA-org projects (ghidra-* satellites, MADCert, kmyth, pelz, lemongraph, seabee, PACE) | None spend credentials (§1.5): the satellites extend the SRE workflow (memory-forensics and taint surfaces are harvesting = recon side of the door); MADCert/kmyth/pelz are archived cert/key custody; lemongraph is at most an architectural cousin of the ledger; seabee is host defense; PACE is Accumulo at-rest crypto |

## 5. Credibility statement

**Consulted directly (primary sources, 2026-09-28):** LICENSE files of
every tool in §1 (raw.githubusercontent.com); hydra.c, medusa.c,
patator.py, netexec cli.py/paths.py/database.py, kerbrute README,
SprayHound README, hashcat src/usage.c, john src/options.c,
ncrack docs/ncrack.usage.txt + COPYING; Metasploit auth_brute.rb /
ssh_login.rb / metasploit-credential models / creds.rb; caldera +
mitre/stockpile ability and object files; Atomic Red Team T1110.* YAMLs
and validate-atomics workflow; Infection Monkey
propagation_credentials_repository.py (develop); attack.mitre.org
T1110 pages + Terms of Use; csrc.nist.gov SP 800-115 and SP 800-63-4
pages; **pages.nist.gov/800-63-4/sp800-63b.html §3.2.2 text re-read
verbatim by the adjudicator**; **impacket LICENSE re-read verbatim by
the adjudicator** (modified Apache-1.1 confirmed).

**Single-source (measured by one axis, not independently re-verified):**
the §2.3 library-license rows other than impacket (paramiko,
asyncssh, pysmb, smbprotocol, pywinrm, pykrb5, gokrb5, ldap3, PyMySQL,
mysqlclient, psycopg2, oracledb, pymongo, redis-py, go-smb2, FreeRDP);
hydra `-D`/MAXTASKS/restore-internals; medusa dlopen/.mod and
`addMissedCredSet`; patator ≥3.13 requirement; ncrack
`--connection-limit` unimplemented; Hashtopolis architecture beyond
its license; CeWL/o365spray/MSOLSpray behavior beyond license.

**Killed or corrected during the adversarial round (2026-09-28):**
"Medusa has no resume" (false: `-Z` map); "patator is threaded" (false:
multiprocessing); "nsa-rules is unlicensed" (false: Fair License);
"SP 800-63-3 §5.2.2" as citation (stale: superseded by 800-63B-4
§3.2.2, numbers survive); "stealthsploit/OneRuleToRuleThemAll" as
canonical (404; canonical is NotSoSecure/password_cracking_rules);
NetExec default-thread count (conflicting readings, dropped); "adopt
an external engine package as a dependency" (killed: native
authorship, §2.4).

**Not verified (must not be cited as fact):** the original dive.rule's
author; SecLists per-file provenance beyond sampling (no manifest
exists); hashcat potfile line format (wiki page absent); Go module
version numbers (proxy.golang.org unreachable); AWS jitter doctrine;
`EllicLion/CredMaster`, `GoMapEnum/GoMapEnum`, `Secure-Shell/Firework`
(all 404 at research time); `t3l3machus/pswd-spray` (repo
unreachable); the "no token bucket anywhere" claim beyond the six
tools measured.

**Round 2 (2026-10-03), Ghidra + NSA-org adjacency (§1.5):** ghidra
LICENSE read verbatim from raw.githubusercontent.com (Apache-2.0
confirmed); `GPL/` and `GPL/licenses/` directory inventories and
per-repo metadata (license.spdx_id, archived, pushed_at, stars) via
the GitHub REST API; GnuDisassembler README, root README,
GhidraDocs/GettingStarted.md, MADCert LICENSE.md, and the five
ghidra-* satellite READMEs read verbatim; the org repository list
(3 pages, 89 repos) and the releases page read directly. One
adversarial pass followed (dedicated killer subagent; full-tree
scans, satellite source reads, and a counterexample hunt over all 89
repos). **Killed and corrected in that pass:** "no authentication
surface of any kind" (false — GhidraServer ships verifier-side login
modules; corrected to the guess/verifier distinction); "MADCert is
not redistribution-licensed" (false — LICENSE.md is MIT; the
`NOASSERTION` classifier is a heading misdetect); "kmyth/pelz are
PKCS#11" (false — KMIP/TPM/SGX key custody, zero PKCS surfaces);
"ghidra-volatility and ghidra-lisa are the only material-touching
pieces" (false — ghidra-frida traces live-process memory, and
ghidra-volatility is a command bridge rather than a hash-recovery
tool). **Survived intact:** the Apache-2.0 root + `GPL/` mixed-tree
finding; analyzeHeadless documentation; and the core scope verdict —
nothing in the org spends a credential (kill scan across all 89).
Must not be cited as fact without re-fetch: star counts and
`pushed_at` (drift daily).

## 6. Acceptance stamp

- **One adversarial round passed (2026-09-28).** Every load-bearing
  claim was attacked by dedicated verifier subagents against primary
  sources: five priority license/fact claims survived intact (hydra
  AGPL-3.0 stock; ncrack special-exception wording; hashcat MIT +
  `--status-json` + PRINCE-not-in-core; NetExec BSD-2 + flag set;
  SprayHound policy-aware skipping); the standards pair survived with
  one citation correction (800-63-4); the zero-gating negative finding
  survived a dedicated counterexample hunt across twelve trees.
- **The adjudicator personally re-read** the two most load-bearing
  external texts (SP 800-63B-4 §3.2.2; impacket LICENSE) before
  acceptance.
- **Errata applied:** the six killed/corrected items of §5 are recorded
  above rather than silently dropped.
- **Data timestamps:** all upstream snapshots 2026-09-28.
- **Round 2 (2026-10-03) accepted after one adversarial pass:** a
  dedicated killer attacked §1.5 against primary sources plus an
  89-repo counterexample hunt; the scope verdict ("nothing in the NSA
  org spends") and the license-composition finding survived, four
  fact/wording claims were killed and corrected (errata in §5).
  Round 1's stamp above stands unchanged.
