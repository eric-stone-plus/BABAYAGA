# Instruments

BABAYAGA names the composition; it does not merge instrument source trees.
Every instrument is driven as an external binary through argv (RESEARCH.md §1
preamble), keeps its own repository, license, and release cycle, and is cited
— never vendored, linked, or copied (NOTICE). A complete engine is this
citation graph plus the gate ([GATE.md](GATE.md)), not a vendor directory.

All survey facts below come from the 2026-09-28 research round
([RESEARCH.md](RESEARCH.md)); drifting figures carry that date, and the
per-claim primary sources and credibility statement are RESEARCH.md §5.
Nothing here was re-surveyed.

## Driven instruments

One instrument is wired at v0. Its adapter manifest lives at
`engine/host/manifests/hydra.json` (loader/validator:
`engine/babayaga/manifests.py`) and pins the version range doctor checks.

| Instrument | Role | Repo | License | Boundary |
|---|---|---|---|---|
| THC-Hydra | network credential testing — the primary C instrument (RESEARCH.md §1.1) | [vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) | AGPL-3.0, stock text (diffed against SPDX canonical; zero THC additions) | runtime argv only |

Contract facts, all measured on the anchored **v9.8dev** build
(2026-09-28; `engine/babayaga/budget.py`, `engine/babayaga/cli.py`):

- Budget binding: explicit `user:pass` pairs via `-C` only; `-e nsr` is
  forbidden (measured 3x attempt multiplier); `-K -I -f` required
  (`budget.py::REQUIRED_FLAGS`/`FORBIDDEN_FLAGS`).
- Output contract: the stderr summary stream is the primary parse source;
  `-b jsonv1` is opportunistic because the anchored build has a measured
  `-o` EINVAL defect (`cli.py::probe_hydra_output`).
- Pacing and distribution vocabulary: `-t`/`-T` concurrency, `-W`/`-c`
  pacing, `-D XofY` wordlist segmentation, `hydra.restore` checkpoints
  (RESEARCH.md §1.1, §2.1).
- Ports: arbitrary via `-s` / `service://…:PORT` — the manifest's
  `requires_standard_ports` is `false`, which is what lets the lab fixture
  serve http-get on loopback:8080 (`engine/lab/`).
- Upstream state at survey time: v9.7 (2026-05-03) was the latest tagged
  release; the anchor is the 9.8 development tree, pinned as the range
  `[9.8dev, 9.9)` so the eventual 9.8 release stays in range.
- The README's author's wish ("do not use in military or secret service
  organizations…") is prose, not a license term (RESEARCH.md §1.1).

## Adopted, not yet driven (the B4 instrument layer)

Verdicts and licenses from RESEARCH.md §1 — licenses were read from the
LICENSE files in-repo, not from README badges.

| Instrument | Repo | License | Planned role |
|---|---|---|---|
| hashcat | [hashcat/hashcat](https://github.com/hashcat/hashcat) | MIT (`docs/license.txt`; no root LICENSE — badges lie) | offline orchestrator target: `--status-json`, `--session/--restore*`, potfile, `--brain-server` dedup (§1.2) |
| John the Ripper (jumbo) | [openwall/john](https://github.com/openwall/john) | GPL-2.0+ with OpenSSL/unRAR exceptions and per-file BSD islands | second offline instrument; `--node=MIN[-MAX]/TOTAL` keyspace split, `--rules-stack` (§1.2) |
| NetExec | [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) | BSD-2-Clause | spray + post-validation; per-protocol workspace DBs are the credential-store pattern to mirror (§1.3) |
| kerbrute | [ropnop/kerbrute](https://github.com/ropnop/kerbrute) | Apache-2.0 (a round-1 "MIT" guess was killed) | userenum/brute/spray; `--safe` abort-on-lock; its honest lockout threat model is itself the pattern (§1.3) |
| SprayHound | [Hackndo/sprayhound](https://github.com/Hackndo/sprayhound) | MIT | policy-aware spray: reads the target's lockout policy and per-user `badPwdCount`, skips near-threshold users — the only policy reader in the surveyed field (§1.3) |
| o365spray | [0xZDH/o365spray](https://github.com/0xZDH/o365spray) | MIT | cloud spray; `--count/--lockout/--sleep/--jitter` lockout-timer semantics (§1.3) |
| MSOLSpray | [dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray) | MIT | Azure AD error-code → action mapping (§1.3) |
| CeWL | [digininja/CeWL](https://github.com/digininja/CeWL) | dual CC-BY-SA-2.0 / GPL-3+ (source header; no LICENSE file) | site-derived wordlists, metadata usernames (§1.4) |
| username-anarchy | [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy) | MIT | username format engine (§1.4) |

## Patterns, not instruments

| Source (license) | What BABAYAGA adopts |
|---|---|
| medusa ([jmk-foofus/medusa](https://github.com/jmk-foofus/medusa), GPL-2.0) | runtime-`dlopen` `.mod` plugin seam — the closest existing analog to BABAYAGA's plugin seam; the field's only measured adaptive backpressure (`addMissedCredSet`); `-Z` resume map (§1.1) |
| patator ([lanjelot/patator](https://github.com/lanjelot/patator), GPL-2.0) | the `-x ignore/retry/reset` failure-semantics classifier; cartesian payload sets with `--start/--stop` and position-tuple `--resume` (§1.1) |
| ncrack ([nmap/ncrack](https://github.com/nmap/ncrack), GPL-2.0 + Nmap Special Exception) | the `-T0..-T5` / `cl/CL` / `at` / `cd` throttle vocabulary — vocabulary only, the instrument itself is out (below) |
| Metasploit ([rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework), BSD-3) | the `auth_brute` option vocabulary (`STOP_ON_SUCCESS`, `PASSWORD_SPRAY`, `TRANSITION_DELAY`, `ABORT_ON_LOCKOUT`) and the metasploit-credential `public/private/realm → core → login` shape (§2.1); take the shape, not the code |
| Hashtopolis ([hashtopolis/server](https://github.com/hashtopolis/server), GPL-3.0) | server/agent/chunk delegation as the crack-farm pattern (deferred, B15); no code (§1.4) |

## Explicitly not adopted

RESEARCH.md §4, recorded to prevent re-proposal. The two license traps first:

- **ncrack as a driven instrument** — the Nmap Special Exception declares
  derivative any application *"designed specifically to execute Covered
  Software and parse the results"*; a dedicated ncrack parser sits exactly in
  that reading, and its `-oX` is unimplemented anyway. The generic
  multi-tool posture (hydra primary) stays inside the carve-out; vocabulary
  is not combination.
- **impacket, and with it every native protocol stack** — impacket's LICENSE
  is *"The Apache Software License, Version 1.1, Modifications by Fortra"*,
  a modified Apache-1.1, not Apache-2.0 (GitHub itself reports NOASSERTION;
  the adjudicator re-read it verbatim). The whole §2.3 matrix (paramiko
  LGPL-2.1, asyncssh EPL-2.0 OR GPL-2.0+, ldap3 LGPL-3.0, mysqlclient
  GPL-2.0+) is the same trap shape: BABAYAGA stays stdlib-only and every
  non-stdlib protocol rides an external binary through the executor.

Also not adopted (§4): vendoring any AGPL/GPL instrument source;
redistributing `rockyou.txt` or Hob0Rules (no license / all-rights-reserved —
breach-corpus provenance can never be stated in a manifest); Metasploit as a
driven instrument; native RDP (no maintained pure-Python client — measured);
an asyncio engine rewrite; Go/Rust core rewrites; LLM-driven attempt
planning (an LLM may propose wordlist hypotheses but never transitions
attempts).

## Corpora are not instruments

Candidate material follows its own provenance rule (B6: every wordlist/rule
file carries a provenance manifest — origin, license, hash). Per §1.4:
SecLists is external user-supplied data, never vendored or redistributed
(MIT root file, but no per-file provenance manifest; rockyou-lineage
contents inherit rockyou.txt's permanently murky status). ns-rules (Fair
License) is usable; OneRuleToRuleThemAll is shape only (composite content
follows each source ruleset's license); Hob0Rules is reference only.

## Version matrix

Versions actually pinned or shipped together at v0. Survey-time upstream
release figures for the adopted-but-undriven rows live in RESEARCH.md §1.

| Component | Version | Source of truth | Status |
|---|---|---|---|
| THC-Hydra (anchored build) | 9.8dev, accepted range `[9.8dev, 9.9)` | `engine/host/manifests/hydra.json`; probe `hydra -h` banner | driven (lab only) |
| BABAYAGA engine | 0.0.1 | `engine/pyproject.toml`, `babayaga/__init__.py` | engine package |
| Review-critical safety modules (scope/cmd/egress/secret_transport/confidence/opsec) | engine 0.0.1 | `engine/babayaga/PROVENANCE.md` registry | native; change requires an operator sign-off note |

## License boundary

Citation is not combination; see [NOTICE](NOTICE). THC-Hydra stays AGPL-3.0
on its own repository: BABAYAGA invokes it as an independent program via its
CLI and consumes its stdout/stderr streams; nothing is vendored, linked, or
copied, and this repository does not relicense it. Every engine module is
original BABAYAGA work — the review-critical safety modules registered in
`PROVENANCE.md` are native authorship, not upstream citations. Nothing in
this document is a legal reading; the survey's credibility statement and
errata are RESEARCH.md §5.
