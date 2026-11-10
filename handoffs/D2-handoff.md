# D2 handoff: OT/IED Integration Engineer (from C2, 2026-11-06)

C2 to D2. Date 2026-11-06. `origin/main` at `961221b` (#475). Phase 4, item 3 (vulnerability applicability with the asset module), brief P4-3-C2. Role 2 of CLAUDE.md §4: in any record, A2, B2 and C2 mean this role. Agent map, review pairs and standing rules: [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) ("Agent map", "Standing rules every C agent must keep"). Earlier files for this role, which still hold where this one is silent: [C2-handoff.md](C2-handoff.md), [B2-handoff.md](B2-handoff.md). C1 checkpoints last: until D1 updates `HANDOFF-SUMMARY.md` (still the B-to-C version) and `GENERATIONS.md` (C still "working"), read this file first, and write `handoffs/D2-ack.md` as the summary's reading order says for `C{n}-ack.md`.

Owned paths: `modules/ied/` (`sel751`, `telnet`, `snmpv3`), `modules/asset/`, `tests/fixtures/ied/`, `docs/device-capabilities.md`, `docs/phase4/C2-*.md`, and drafts of C1, C2, C3 register content and C9, which C1 approves. Nothing below is hardware-verified, and no SEL family is supported (B-01).

## 1. Verified state

| Item | State | Evidence class | Source |
| --- | --- | --- | --- |
| C1 0.3 (identity attributes with their source, `snmpv3` endpoints, `snmp_engine_id`, `CapabilityProfile.models`), C3 0.4 (SNMP `get`/`getnext`/`getbulk`, `set` refused at load), C2 0.7 (SNMP results, nine SNMP codes) | working | CI-Linux, CI-Windows | #445, `8ecbe61`; C6's contract tests in `tests/contract/c1_v03_c6_test.go`, `c2_v07_c6_test.go`, `c3_v04_c6_test.go` |
| SEL-751 `model` and `firmware_version` as their own observations, sub-spans of the FID | working | simulated | #445, `modules/ied/sel751` |
| `modules/asset`: `Apply`, `Upgrade` (0.2 to 0.3 rewrite plus `Validate`), `Models(productFamily)` (one list per product: `sel-751`, `sel-2731`, `sel-2741`), `FamilyConflict` (no list means no check); import test | working | CI-Linux, CI-Windows | #445, #453 (`e9b35c8`, `c650ede`), `modules/asset/asset_test.go` |
| C2 0.8: `failed.snmp_unexpected_report`, `failed.snmp_scoped_pdu_unreadable` (D4-54) | working | CI-Linux, CI-Windows | #453, `723d221` |
| `modules/ied/snmpv3`: USM `authPriv` client, pinned engine ID, Report order (#437 §4 rule 1), BER decoder with `FuzzDecodeMessage` and `FuzzOID`, family identity parse, `Result` builder, `Permit` on the final wire bytes, `AdapterID`/`Version` | working | simulated (Go-level fake agent), CI-Linux, CI-Windows | #453 (16/16 green at `f743d7e`, passes from C3, C5, C6), #462 (`937c3d0`) |
| Collector's SNMP path calling the client (C3's) | working | simulated, CI | #461, #465 (C2 passed both) |
| V-M1 over GT-MIB | **not run** | none | `docs/verification.md` (item 3 gate row); GT-MIB's agent not built yet |
| The client's wire layout against the RFC texts | **unverified**: written from memory | desk only | RFC texts in `reference/rfc/`. The owner allowed `www.rfc-editor.org` on 2026-11-06: recorded in the exit report on #479 (lines 3, 80), not yet on `main`, where D4-54 and `verification.md` still list the texts as owed |

**Checks run by C2 on `9ee439f` (main `961221b` merged into the branch; trees identical), 2026-11-06:**

| Command | Result |
| --- | --- |
| `go vet ./...` | exit 0 |
| `$(go env GOROOT)/bin/gofmt -l .` | prints nothing, exit 0 |
| `go test ./...` | exit 0: 52 packages `ok`, 3 with no test files, none failing |
| `python -m pytest -q` (scratch venv, `pytest` and `asyncssh==2.24.1`) | **did not finish**: stopped by a 25-minute `timeout` (exit 124) while the integration tests on the binaries were running, so no counts. No failure was printed before the stop. The `pytest`, `integration` and `integration-long` jobs passed in CI on `961221b` (run below) |
| Windows, `integration`, `integration-long` | not run locally. `ci.yml` on `main` at `961221b`: success, [run 42174011840](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42174011840). `govulncheck.yml` last ran on `main` by schedule at `fd64a14` (stale for `main`; it runs on every PR) |

## 2. Work in flight

- **None of C2's.** No open PR, no uncommitted work other than this file, no stash, no patch. The branch `claude/project-thread-yvmf7w` holds only merged history plus this file. Old WIP patches in a working folder that was not kept (`c2-wip-snmpv3.patch`, `c2-wip-adapter-0.8.patch`) are superseded by #453; they are not records.
- **Other agents' open PRs at this checkpoint** (not C2's): #479 (C1, item 3 exit report), #480 (C6, gate tests). Neither waits on C2.

## 3. Next tasks, in priority order

1. **NEXT ACTION: check `modules/ied/snmpv3` against the RFC texts.** Why: the client (P4-3-C2 deliverable 4) was written from memory of the RFCs, and C6 builds GT-MIB's agent from the texts themselves. The exit report's "Next coordinated tasks" 1 (`docs/phase-4-item3-exit.md` line 197, on #479 and not yet on `main`) gives C2 the SNMP reading of V-M1, and this check is C2's preparation for it, so a V-M1 failure is not first found in the gate run. Read `reference/rfc/` (`sha256sum -c SHA256SUMS` shows the copies are intact, not where they came from). Compare, with a section cited for each:
   - RFC 3411 §5 `SnmpEngineID` format, which the engine pin depends on (`session.go`);
   - RFC 3412 §6: `msgGlobalData` layout and `msgFlags` bits (`msg.go`);
   - RFC 3414 §2.6 key localization, §3.1 and §3.2 USM parameters and the Report counters, §4 discovery (`session.go`, `usm.go`);
   - RFC 3826 §3.1.2.1 IV (boots, time, salt) and CFB with no padding (`usm.go`);
   - RFC 7860 digest lengths, 24 and 48 octets (`usm.go`);
   - RFC 3416 PDU tags and GetBulk fields (`ber.go`, `msg.go`);
   - RFC 3418 and RFC 6933 OIDs (`identity.go`).
   Paths: `modules/ied/snmpv3/`, a note `docs/phase4/C2-snmpv3-rfc-check.md`. Dependencies: none to start. Acceptance: every layout the client encodes or decodes has a citation; any divergence gets a failing test first, then the fix, in a PR reviewed by C3 and C6. Already checked by C2 (desk): RFC 3414 §3.2's order is engine ID (step 3), user (4), level (5), digest (6), time window (7), decryption (8), which is what `cases.json` U2 to U6 assume.
2. **Review C6's GT-MIB agent and the V-M1 run** as each PR comes up (the same exit report task: "C2 reviews the SNMP reading and C3 reviews security"). Check each case of `tests/integration/gt_mib/cases.json` (C2 passed at `d7d368c`, #457) against what the agent does, and any V-M1 failure against the client. Acceptance: V-M1 (a) to (c), (e) and (f) pass on the real binaries (P4-3-C2 acceptance).
3. **SEL-751 register: fix the OUT101 wording in the next revision** (C1, 2026-11-04). In `contracts/register/testdata/sel-751.json` revision 5, `sel.session.acc`'s `side_effects` still says OUT101 "closes the alarm contact". OUT101 is fail-safe by default (`OUT101FS := Y`, S22 Table 4.83). Only in a new signed revision, when C1 opens one. Not started (carried from [C2-handoff.md](C2-handoff.md) task 6).
4. **Parked, owner-gated:** H-13, H-16 (SEL-751) and H-17 (SEL-2731/2741) captures; SER system rows; other families (the SEL-2730M is second only if the sites run it, D4-51). Do not start any without a brief.
5. **The next item's brief** comes from D1 after the owner's check of item 3 (D4-34).

## 4. Blockers and risks

- **V-M1 not run**, so the client has never sent a message over a real socket to an agent. Its RFC layout is unconfirmed (task 1).
- **Open risks for this role:** in `docs/threat-model.md`, HR-16 (USM keys, no downgrade; open until V-M1 (c) and the H item), AP-28 (the asset module as a path to devices), HR-11 and HR-18 (no real advisory until the owner decides). In `docs/phase-3-exit.md` "Open risks": B-01 (no hardware) and D2-16 (a port-server path stays refused until H-13's `T_OUT` evidence).
- **Owed by the owner:** the item 3 decisions listed in the exit report (#479, "Owner decisions needed"); H-13, H-16 and H-17; device contact for any SNMP endpoint. D4-12: no runs on the owner's PC.
- **Unverified assumptions** (`docs/phase4/C2-snmp-family.md`, S29 `documented-untested`): which Entity MIB column and row hold the FID (found by form); the table's row count; the engine ID surviving a firmware upgrade (inferred from its MAC-based form, S29 p. 42); that the device refuses anything below `authPriv` (S29 p. 43).

## 5. Decisions and lessons

Decisions, by link in [B1-decisions.md](../docs/phase4/B1-decisions.md):
- D4-49: answers to C6's item 3 testability questions, and F1.
- D4-50: SNMPv3 runs only in the collector, and the module combinations.
- D4-51: the SEL-2731/2741 in RSTP mode first, with no SHA-1.
- D4-53: the item 3 contracts.
- D4-54: `failed.snmp_fid_unreadable`, the 0.8 codes, the per-product `Models` lists, and the family token (`product_family` names one product; `sel-27x1` is the register and profile family).
- D4-56: network controls sit in `asset_controls` beside the C1 records, not in C1 0.3.
- D4-57: an audit citation never reads as passive evidence.

Design notes: `docs/phase4/C2-c1-0.3-c3-0.4.md`, `C2-adapter-0.7-snmp-results.md`, `C2-snmp-family.md`.

Failed approaches this generation (each fixed on #453, recorded in its review threads):
- `Permit` ran on the plaintext scoped PDU before encryption, so the egress check never saw the header (C3; fixed in `84e3099`).
- `accept` took a priv-flagged message with a plaintext `msgData` as decrypted, so a forged message could set the engine ID (C6; fixed in `84e3099`, test `c2686fa`).
- One model list for the whole 27x1 family, first keyed `sel-2731` and then `sel-27x1` (C1 corrected it to one list per product; `e9b35c8`).
- `FamilyConflict(rec, nil)` reported every model as a conflict (C5; `e9b35c8`).
- `Permit`'s `engineKnown` came from the message flags it judges (C3; `f743d7e`).

Gotchas that cost time:
- **All cross-agent messages go through the coordinator** (the owner's message in the project chat, 2026-11-06). It is not yet in `HANDOFF-SUMMARY.md`, which still says to message agents directly; this rule wins. Don't message other threads directly.
- You may push only to your own branch. When C1 asks for a separate small PR while one is open, put it on the open PR as its own commit (C1 accepted this on #453). Otherwise wait for the merge.
- After a squash merge, restart the branch: `git checkout -B <branch> origin/main && git merge -s ours origin/<branch>`. Never force push. Also, `git checkout origin/main --` with no path detaches HEAD.
- Use `$(go env GOROOT)/bin/gofmt`. The container's `/usr/local/go/bin/gofmt` wrongly lists `relptest_test.go`.
- `pytest` is not installed system-wide. Use a scratch venv: `python3 -m venv`, then `pip install pytest asyncssh==2.24.1`.
- C2's goldens:
  - Regenerate with `python3 -I generate_snmp.py` (or `generate.py`) inside `contracts/adapter/testdata/` or `contracts/asset/testdata/`.
  - `TestEveryCodeHasAnExample` needs a valid golden named exactly after each code.
- `snmpv3.Session.Now` drives the read deadlines. The collector converts them to wall-clock socket deadlines (#461, `163a9f9`), so a frozen test clock is safe there.
- The GitHub MCP tools disconnect often. Reload them with ToolSearch. Every GitHub post ends with the Claude Code footer.

## 6. Progress against [C2-handoff.md](C2-handoff.md)

| Task | Status |
| --- | --- |
| 1. Land #345 | Done (`2ddf8ad`). |
| 2. Hand B3 the number for the collector's `sel.config.read_all` wiring | Done. C2 passed #341. |
| 3. Widen H-13 | Dropped: H-16 covers it (D4-8). |
| 4. Parked hardware and family work | Unchanged, still owner-gated. |
| 5. The next brief | P4-3-C2 was issued (#443) and all four deliverables merged: #445, #453 and #462. |
| 6. OUT101 wording | Not started. It needs a register revision, and none was opened. Carried as task 3. |

- **Still lacking evidence under CLAUDE.md §7 for P4-3-C2:** point 8, correct operation beyond the Go-level fake (V-M1).
- **Regressions:** none seen. No CI run was retried for C2's code (#453's stall was the scheduler race that #448 fixed).
- **Review debt:** none older than a day. C2 reviewed #449, #456, #457, #461, #465 and #468.
- **Out-of-scope work:** none.
- **STALLED:** nothing.

**Proposed for D1's records:** the five failed approaches above, as one line each in the item 3 exit report or the decisions file. Also the lesson that a client written from memory of an RFC must be checked against the text before V-M1 counts.

Validated by a fresh read-only agent, 2026-11-06. Fixed: D4-49's subject, where the RFC permission is recorded, the RFC check's source, RFC 3411 added, the risk file locations, the coordinator rule's source, and the ack step before D1's records.
