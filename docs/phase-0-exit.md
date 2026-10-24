# Phase 0 exit report

Owner: A1. Date: 2026-10-23. Status: **closed.** Owner accepted on 2026-10-24 by authorizing Phase 1 (see "Owner sign-off"). Revised 2026-10-23 20:40Z to add A6's Windows runs, F-012 and F-013. Items marked *open at close* are listed in "Carried into Phase 1".

This report closes Phase 0 (Establish evidence and challenge assumptions). It follows the milestone format in `CLAUDE.md` §9. It records what was delivered, where it is on `main`, what was independently checked, and what was decided. Nothing in Phase 0 was tested on hardware. No result is better than `documented-untested` or `simulated`, because no lab device or capture exists (owner, 2026-10-23).

## Milestone

**Phase 0: Establish evidence and challenge assumptions.** The objective was to find the architecture-critical risks, choose a plausible architecture and a first implementation scenario, define the contracts the first slice needs, set objective acceptance criteria, and mark unsupported assumptions. No product code was to be written.

## Implemented (deliverables on `main`)

All Phase 0 work is merged to `main`: PRs #1 to #6 at 18:55Z, with the owner's approval, follow-ups #7 to #10 at 19:05Z, review-record close-outs #11 to #14 at 19:08Z to 19:09Z, A5's Windows results (#16) at 19:22Z, and A6's Windows check H-14 with its findings (#17, #20 to #23) by 20:35Z.

| Brief | Deliverable required by the brief | Where it is on `main` | Done |
| --- | --- | --- | --- |
| **P0-A1** Architecture | System boundary; alternatives with a provisional choice; dependency map; five risks; slice scenario; required contracts; unsupported assumptions; exit-gate decision | `docs/architecture.md`; ADR-0002 to ADR-0007 in `docs/decisions/`; `docs/agent-handoffs.md` (briefs, handoffs, rulings) | Yes |
| **P0-A2** Device feasibility | (1) ranked candidate families; (2) capability matrix; (3) draft command register with classification sources; (4) SSH feasibility; (5) device safety risks; (6) native SER format | `docs/phase0/A2-device-feasibility.md` §2, §5, §6, §7, §15; `docs/device-capabilities.md`; `docs/phase0/A2-command-register-draft.json`; `docs/phase0/A2-sel751-firmware-allowlist.json`; `docs/phase0/A2-sel-portfolio.md` (SEL by device class, ADR-0006); fixtures in `tests/fixtures/ied/` | Yes |
| **P0-A3** Security feasibility | (1) threat model v0 with trust boundaries and attack paths, each with a mitigation and a test; (2) Q1 comparison of proxying, remote workstations and gateways; (3) minimum safe behaviour for the slice; (4) standards anchors, labelled as alignment | `docs/threat-model.md` (TB1 to TB11, AP-1 to AP-27, HR-1 to HR-10); `docs/phase0/A3-security-feasibility.md`; `docs/phase0/A3-review-A5.md`; experiment E1 in `modules/access/experiments/` | Yes |
| **P0-A4** Telemetry feasibility | (1) event schema keeping native bytes and the separate time fields; (2) duplicate handling; (3) Syslog forwarding profile; (4) Zeek, Suricata and library coverage, with sources; (5) Q4 visibility limits | `docs/phase0/A4-event-schema-draft.md`; `docs/phase0/A4-telemetry-feasibility.md`; experiments E-A4-01 to E-A4-03 and schema mapping in `modules/telemetry/experiments/` | Yes |
| **P0-A5** Platform feasibility | (1) runtime comparison against R7 and R8; (2) toolchain and UI stack; (3) persistence recommendation backed by a reproducible crash experiment; (4) site-to-central transport and enrollment outline | `docs/phase0/A5-platform-feasibility.md`; ADR-0002, ADR-0003, ADR-0004; experiments in `platform/experiments/phase0/` (Linux); Windows port and workflow (see "Windows evidence") | Yes (Linux and Windows VM, `simulated`) |
| **P0-A6** Verification | (1) acceptance criteria with numeric or binary pass conditions and named ground truth; (2) R-level matrix for at least R4, R5 and R8; (3) a "no write" proof that does not depend on the adapter's own claims; (4) at least five challenged assumptions; (5) blockers | `docs/verification.md` (V-S1 to V-S20, R/P matrix, C-01 to C-24, H-01 to H-14, B-01 to B-07, F-001 to F-013); recording simulator, register checker and firmware review in `tests/safety/`; experiments E-01 to E-04 in `tests/integration/`; `docs/phase0/A6-cross-review.md`, `docs/phase0/A6-handoff.md` | Yes |

### Windows evidence (ADR-0007)

The owner confirmed on 2026-10-23 that site nodes run Windows. All earlier storage and durability evidence ran on Linux, so A5 ported the experiments to Windows and ran them (W-1) on a GitHub Actions runner: GitHub Actions run 40006949610, Windows Server 2025 on a virtual NTFS disk, results in `platform/experiments/phase0/results/windows-*.txt` and A5 findings §13 (PR #16). Evidence class `simulated`: it is a hosted VM, not site hardware and not the IoT LTSC edition. Every Linux result reproduced:

- **Crash durability:** 400 of 400 kill runs, with no acknowledged event lost.
- **Storage-full restart recovery:** passes only with `auto_vacuum=INCREMENTAL`.
- **Plain TCP Syslog:** loses events without any error, up to 3,568 of about 3,700 per run against a slow collector.
- **Acknowledged transport:** no loss.
- **Write amplification:** matches the Linux figures.

New finding: committing each event on its own at `synchronous=FULL` reaches only 92 events per second on this disk. Batches of 100 reach 676 per second. So group commit is required for throughput as well as SSD wear (ADR-0007 item 5).

A6 checked the run independently (F-011, PR #17). The result files match the job log on all 98 lines. A6 does not count it as the H-14 software half: it used A5's harness, had no flush trace, ran elevated, and ran on Windows Server 2025. A6 also notes that a start-up flush-latency measurement must never be read as proof of a healthy disk, because a cache that acknowledges flushes early looks fast exactly when commits are not durable.

### A6's independent Windows check (H-14 software half: F-012, F-013)

A1 authorized this as Phase 0 close-out, because it closes C-22, which was raised in Phase 0. A6 used its own scripts (`tests/integration/h14/`, workflow `a6-windows-h14`), ran them as a temporary non-admin account, and traced file I/O with ETW. Both runs were on Windows Server 2025, a GitHub-hosted VM, using Python's SQLite rather than the product driver. Evidence class `simulated`.

- **Flush ordering (runs 40015873447 and 40018011417): pass, twice.** At `synchronous=FULL`, all 300 acknowledgements followed a WAL flush issued by the writer. `NORMAL` left 280 of 300 unflushed, and `OFF` issued no flushes at all. Both positive controls showed up and no trace events were lost. This is the precondition for power-loss durability. Whether the disk honours the flush is still H-11.
- **Full-disk recovery (run 40018011417): a new failure mode on NTFS.** The test filled the store, killed the writer, then opened the store in a fresh process at full disk, before releasing the reserve file. The first time, the opens worked. The second time, every open failed with `disk I/O error`, read-only opens included. Recovery's own first statement failed too, so it never released the reserve. The file sizes fit SQLite's `-shm` rebuild running out of space: after the failed open the `-shm` was 0 bytes and only 28,672 bytes were free, less than the 32 KiB it needs. That cause is inferred from the sizes, not observed. The `INCREMENTAL` scenarios and R-A5-5 did not run because of a harness limitation (WinError 32 at setup).

**Reconciling F-013 with A5's W-1.** A1 compared the two harnesses (`platform/experiments/phase0/restart.go` against `tests/integration/h14/recovery_rounds.py`). They do not conflict. They test different startup orders:

- **A5's restart recovery (`startupRecovery`) deletes the reserve file before its first open of the store.** That is the order ADR-0004 item 8 specifies. With that order, W-1's restart case recovered on every round with the product's Go driver: 3 of 3 with `INCREMENTAL` and 3 of 3 with `NONE`, where `NONE` failed only on capacity.
- **A6's harness opens the store at full disk first, by design.** It tests E-03's Linux claim that a crashed full store can still be read before any space is freed. On NTFS that claim held once and then failed.

So on Windows the reserve-first order in ADR-0004 item 8 is load-bearing, not just tidy. Any open of a full store before the reserve is released risks leaving the store unopenable until space is freed outside SQLite. That includes a recovery step that reads first, a UI or support tool, or another process. Whether releasing the reserve then clears the condition is likely but untested.

A6 tried to disprove this reading and could not. W-1 case 3 never opens the store at full disk, so it neither confirms nor contradicts F-013. A6 named two residual gaps, and both are carried into Phase 1:

- **Unchecked delete.** `restart.go` ignores the error from deleting the reserve. If the delete fails, the store is opened at full disk with no signal.
- **No reserve left to release.** ADR-0004 item 8 says a node whose reserve cannot be re-created alarms and does not collect. The next startup then has no reserve to release, which is exactly F-013's condition. V-S9's "readable with the disk still full" clause has no answer for that case yet.

Consequences:

- **C-22:** for the site node, E-03's read-at-full result is contradicted, not only unverified.
- **V-S9:** the criterion is unchanged. "Readable after a restart at full disk" can be met on Windows only through the reserve-first order. A5's run shows that order working, but it ran elevated under A5's own harness. No independent check of it exists yet.

Still open:
- An independent check of the reserve-first order, `INCREMENTAL`, and R-A5-5 on NTFS as a non-admin account (H-14 part 2; the harness setup needs fixing first).
- The product binary as the thing under test.
- A Windows 10/11 LTSC client edition.
- H-11 (power cut on each hardware model).

## Independently verified

These were checked by someone other than the author. Every result here is `simulated` or `documented-untested`.

- **A1 re-runs:** A3's E1 (14/14 over 3 runs), A4's E-A4-02 framing (0 forged messages with the profile, 10/10 cases) and E-A4-03 RELP queue loss (Direct queues: 0 lost), A5's E-A5-1, E-A5-3 and E-A5-5 cross-build, and A6's E-01 (5/5) and simulator self-test (8/8). All reproduced.
- **A6 cross-reviews** of A2, A3, A4 and A5 are in `docs/phase0/A6-cross-review.md`. Each found real defects, and each was fixed and re-checked:
  - L1 to L7 were not independent layers.
  - Termination was confused with revocation.
  - The SER key merged legitimate repeated rows.
  - The alignment key included the row number.
  - NORMAL sync was taken as durability evidence.
  - Pruning deadlocked behind a target that never confirms.
- **Other cross-reviews:** A2 reviewed A3 for IED compatibility (`A3-security-feasibility.md` §8.3) and A4's parser. A3 reviewed A5 (`A3-review-A5.md`) and A2 (`A3-review-A2.md`).
- **Register:** A2's register passes A6's independent 135-line deny corpus, with nothing classified read-only, and its read-only set equals A6's allow corpus.
- **Firmware allowlist:** A6 checked A2's SEL-751 firmware allowlist independently against the 84 firmware rows in Appendix A. All 7 restart fixes appear on exactly the rows A2 lists (`tests/safety/firmware_review/`).
- **Merged tree:** on `main` after the merge, 67 tests pass. The 5 environment-gated tests also pass when given the SEL-751 manual text, the register and the allowlist (5 passed, 141 subtests).

## Exit-gate items

| Exit-gate item (`CLAUDE.md` §6) | Met by |
| --- | --- |
| Five architecture-critical risks identified | `docs/architecture.md` "Five architecture-critical risks": read-only is not guaranteed by the device; the platform as a path into IEDs; no primary device evidence; delivery guarantees weaker than assumed; event fidelity across vendors and over time |
| Plausible initial architecture | ADR-0002 (modular monolith with an isolated collector process), ADR-0003 (Go; Python only for verification), ADR-0004 (SQLite store and delivery semantics), ADR-0007 (Windows site node) |
| Initial implementation scenario selected | ADR-0005: SEL-751 `ID` and `SER` over Telnet, labelled insecure, against documentation and a simulator only |
| Required contracts defined | C1 to C8 in `docs/architecture.md`, with owners and reviewers |
| Objective acceptance criteria | V-S1 to V-S20 and the R/P matrix in `docs/verification.md` |
| Unsupported assumptions marked | `docs/architecture.md` "Unsupported assumptions" |
| Phase 0 branches merged to one tree | PRs #1 to #14, #16, #17 and #19 to #23 merged to `main` (#15 and #18 are this report) |

Gate decision: **passed with conditions** (A1, 2026-10-23). Three conditions are Phase 1 deliverables by design, not Phase 0 gaps. They must close before Phase 2 code starts:

- B-02: the C3 register is approved with citations read from the manual.
- B-04: the C7 credential design is accepted by A3 and reviewed by A6.
- B-03: C5 and C6 are approved, including the rule that only RELP over TLS may be a `required` target.

## Owner decisions and accepted risks

| Date (2026-10-23) | Decision | Recorded in |
| --- | --- | --- |
| Morning | No lab device; the first slice uses documents and a simulator only | ADR-0005, `docs/architecture.md` |
| Morning | Telnet allowed for the slice, labelled insecure; residual risks accepted (cleartext Level 1 password, no cryptographic device identity) | ADR-0005 |
| Afternoon | All OT device classes in scope; SEL first, then other vendors | ADR-0006, `docs/requirements.md` R1.6, R1.7 |
| Afternoon | "Supported" means SEL families whose capabilities meet the requirements; servers and historians are Windows hosts | ADR-0006 |
| 16:41Z | MAXACC: recommend and check. The deployment guide recommends `MAXACC := 1`; the adapter warns, does not refuse, and never changes relay settings | ADR-0005 |
| 17:07Z | Windows host events by host push: no Windows credentials, no agent, alert on a silent host | ADR-0006 |
| 17:21Z | Answers on site hardware and OS, WAN (outage is a fault, N-1), central access (central HMI may reach relays; platform central never does), any Syslog collector, zenon HMI, SEL-3350 replacing SEL-3530 | `docs/requirements.md` "Owner answers", ADR-0004, ADR-0007 |
| 18:47Z | **Accepted risk:** plain Windows 10 Pro allowed on platform nodes, labelled "OS out of support"; the installer warns, does not refuse | ADR-0007 item 9 |
| 18:47Z | **Accepted risk:** newer SEL-751 firmware branches (R400 to R402, R500, R501) are treated as containing the earlier communications-restart fixes. Allowlist entries are classed `inferred (owner-accepted)` | ADR-0005 |
| 18:53Z | Dedicated platform machine at each site, never shared with zenon; hardware may differ from the SEL-3355-2 | ADR-0007 item 1 |
| 18:52Z | Phase 0 branches merged; repository made public; default branch set to `main` | This report |

These A1 safety rulings also bind the slice. All are recorded in ADR-0004 and ADR-0005:

- **Firmware gate:** collection only from allowlisted firmware. The firmware ID must be known before the first connection, and `ID` must confirm it before `ACC`.
- **Language:** no collection unless `LANG := ENGLISH`, with a Level 0 language probe.
- **Failed password:** the adapter closes the connection without sending `QUI`.
- **Forwarding:** only RELP over TLS may be a `required` target. Plain RELP, RFC 5425, TCP and UDP are best-effort; TCP and UDP are labelled insecure.

## Failed or incomplete

- **Windows durability evidence:** W-1 (A5) and H-14's flush check (A6) passed on a Windows VM (`simulated`). H-14's full-disk recovery part found a new failure mode and did not complete its `INCREMENTAL` and R-A5-5 scenarios (F-013). The hardware power-cut test H-11 remains (see "Windows evidence").
- **Device classification:** a full classification of every supplied SEL family in the `docs/architecture.md` device table is not done. Phase 0 asked only for the slice family and the RTAC contrast. The table marks the remaining rows "classification pending". This is planned SEL-family work, not a Phase 0 gap.
- **Review records:** A2, A4 and A6 corrected their stale "pending" reviewer lines (PRs #11 to #13). A3's cross-review of A2 (security-sensitive behaviour), which had not been recorded, is now in `docs/phase0/A3-review-A2.md` (PR #14): accepted for Phase 0 with three changes for the Phase 1 register contract (C-A2-1 to C-A2-3, below).

## Unverified assumptions

Everything that depends on hardware: H-01 to H-14 in `docs/verification.md`. This includes:

- the real Level 0 `QUIT` reply and the `SHO P 1` output (H-13);
- Spanish-port behaviour (H-12);
- relay load from polling (H-05);
- power-cut durability on each hardware model (H-11);
- the Windows edition a real site image reports (H-14).

Also unverified: whether the firmware a relay reports is honest, and the IEC 62351 and IEC 62443 mappings, which were made from secondary knowledge.

## Open risks

- The five architecture-critical risks in `docs/architecture.md`.
- Owner-accepted risks: Telnet cleartext, firmware fix inheritance, and Windows 10 Pro.
- RTAC and SEL-3620 limits: the RTAC can lock out accounts and delete logs (D20, D21), and the SEL-3620 proxy is not a command allowlist (A3 HR-4).
- **Full store on NTFS (F-013):** opening a full store before its reserve is released can leave it unopenable, read-only opens included, until space is freed outside SQLite. Recovery must release the reserve before the store is first opened, and nothing else may open the store first. This is evidence-backed on a Windows Server VM only.
- Stock IDS engines cannot decode IEC 61850 or IEC 104 (A4); GOOSE rules failed 8 of 8 adversarial cases. Both are inputs to Phase 4.

## Carried into Phase 1 (on hold until the owner says go)

1. Contracts C1 to C8, closing B-02, B-03, B-04 and B-05.
2. Inputs already agreed for the C2 brief:
   - posture warnings and refusal reasons;
   - the language-probe reply grammar;
   - the storage-durability and OS-support labels;
   - the standing condition and migration date for nodes on an unsupported OS.
3. The rest of H-14 and ADR-0007 moving from proposed to accepted. H-14 still needs:
   - an independent NTFS run of the reserve-first startup order, `INCREMENTAL` and R-A5-5, as a non-admin account;
   - the product binary as the thing under test;
   - an LTSC client edition.
   The C2/storage contract must state three things (ADR-0004 item 8, F-013):
   - startup releases the reserve before the store is first opened, and a failed release is an error, not a silent continue;
   - no other process opens the store before recovery completes;
   - what startup does when there is no reserve to release.
4. Classification of the remaining SEL families in the device table.
5. A3's register changes for C3 (`A3-review-A2.md`):
   - C-A2-1: `ACC` and `QUI` move to a non-invocable session-control class.
   - C-A2-2: the firmware allowlist ships inside the signed register package and fails closed if missing or unsigned.
   - C-A2-3: echo redaction (HR-3) stays mandatory until a capture shows no echo.

## Owner sign-off

Phase 0 is closed when the owner signs below.

- Owner: ALI. Date: 2026-10-24, 11:16Z.
- Decision: **accepted with the open items above.** The owner wrote "Continue phase 1" in the project chat. The owner did not write the requested "Phase 0 accepted". A1 records the instruction to start Phase 1 as acceptance of this report, with its open items carried into Phase 1 as listed. If the owner meant something narrower, this line is corrected and Phase 1 pauses.
