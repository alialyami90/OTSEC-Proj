# D6 handoff: Independent Verification and OT Safety Engineer

From C6 to D6, 2026-11-06, at `main` `50b1f37` (#480, C6's last code PR, merged as `158a5d0`; then the C2 to C4 checkpoints). Phase 4, item 3 (vulnerability applicability with the asset module), with its exit gate open on V-M1 only. Role 6 of `CLAUDE.md` §4 (A6), with the review rules of §5.6. Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) and its [agent map](HANDOFF-SUMMARY.md#agent-map) first, then this file. The owned paths, the "never" list and the role definition in [B6-handoff.md](B6-handoff.md) are unchanged. [C6-handoff.md](C6-handoff.md) is the previous generation's file. After cutover, write `handoffs/D6-ack.md` as a Markdown-only PR.

**Standing rules (owner):** no contact with any real device; never fabricate evidence; test credentials only; edit only your own paths; the owner's PC stays off limits while D4-12 holds. **From 2026-11-06, every message between agents goes through the coordinator** (Ali, in the project chat). Never discard uncommitted work. Stage files by explicit path only.

## 1. Verified state

Classes: `desk`, `simulated`, `CI-Linux`, `CI-Windows`. Nothing is hardware-verified (B-01).

| Item | State | Class | Source |
| --- | --- | --- | --- |
| V-M2 (all 21 changes) and V-M3 (SEL-751 desk half) | working | simulated, CI-Linux | #420, #394; gate table "Phase 4 first exit gate status" |
| V-M4, the Syslog and SER halves on the real binaries | working | simulated, CI-Linux | #410, #417, #431 (the `gtinj_ser` leg, about 50 min) |
| GT-ADV and V-M7 (128 of 128 cells) on the real binaries | working | simulated, CI-Linux | #441, #457, #467, #469; leg `test_slice_vm7_e2e.py` |
| V-M8, set cases (18 of 18) and paired runs (12 of 12, root, own network namespace) | working | simulated, CI-Linux | #470, #475; legs `vm8_sets` and `vm8_paired` |
| V-S7 (`check.py`) over every V-M7 and V-M8 recording; the SNMP egress deny corpus | working | simulated, desk | #475; `tests/integration/gt_mib/egress/deny_test.go` |
| Contract tests for C1 0.3, C2 0.7, C3 0.4, C5 0.8, C7 0.8, C8 0.11, C11 0.1 and C12 0.1 | working | desk | #445, #446, #450, #475, `tests/contract/` |
| F-025 (D4-57): an audit citation read as passive evidence | fixed and asserted (#476, #477, #480) | desk | `tests/contract/c12_c6_test.go` |
| V-M1 over GT-MIB | **broken: not built**. The agent is half written (WIP patch, §2) | none yet | gate table row V-M1 |
| Item 3 gate table | working, at `961221b` (#480) | desk | `docs/verification.md`, "Phase 4 item 3 exit gate status" |

**Checkpoint commands**, run in the container at `961221b` plus #480's two commits (the same tree as `158a5d0`), Linux, 2026-11-06:

| Command | Exit | Result |
| --- | --- | --- |
| `go vet ./...` | 0 | clean |
| `gofmt -l .` (the toolchain's, `$(go env GOROOT)/bin/gofmt`, over CI's file list) | 0 | printed nothing. The container's `/usr/local/go/bin/gofmt` is an older Go's and flags `modules/telemetry/forward/relptest/relptest_test.go`; that is the tool, not the file (CI's gofmt step passes) |
| `go test ./...` | 0 | 52 packages ok, 3 with no test files, 0 failed |
| `python -m pytest -q` (pytest 9.1.1, asyncssh 2.24.1; without `OTSEC_SLICE_REQUIRED`) | running at commit time | at 49%: 691 passed, 29 skipped, 0 failed. The final count goes on the checkpoint PR. Windows: none run here (GitHub Actions only; #480's `go (windows-latest)` was green) |

## 2. Work in flight

| What | Where | Head | CI | Reviewers | Exact next step |
| --- | --- | --- | --- | --- | --- |
| #480: the D4-57 pair in `c12_c6_test.go`, `in_use_since` across a restart, gate table at `961221b` | merged as `158a5d0` | n/a | green on its head `523ccce` before C1 merged it | C1 | Nothing. The branch was restarted on `main` for the checkpoint PR |
| GT-MIB agent, WIP (BER, USM crypto, message codec, served MIB from S29, the responder and its log) | `/mnt/project-files/c6-wip/2026-11-06-gt-mib-agent-wip.patch` (creates `tests/integration/gt_mib/agent/`) | not committed | none | C2 (SNMP reading), C3 (security) | After the checkpoint PR merges, `git apply` it on the restarted branch, then do NEXT ACTION. `c6-wip/README.md` describes it |
| Extra RFC texts that the eight do not cover: RFC 2578 (the OID roots `mib-2` and `snmpModules`), RFC 3417 (BER rules), RFC 1157 and RFC 1901 (v1 and v2c message layouts) | `/mnt/project-files/c6-wip/rfc-extra/` with `SHA256SUMS` | n/a | n/a | n/a | Tell C1 (through the coordinator) that they are needed, so they join `/mnt/project-files/rfc/` |
| Review of C1's checkpoint PR | pending | n/a | n/a | C6 | Review when C1 posts it |

## 3. Next tasks, in priority order

1. **NEXT ACTION: finish GT-MIB's agent and confirm the case table against the RFC texts (P4-3-C6, V-M1; plan `docs/phase4/C6-gt-mib-plan.md` §1 and §3).**
   - **Paths:**
     - `tests/integration/gt_mib/agent/` (from the patch);
     - `tests/integration/gt_mib/cases.json`, `test_gt_mib_cases.py` and `README.md`;
     - the `egress/deny_test.go` header;
     - `docs/phase4/C6-gt-mib-plan.md`, which still says 680, RFC 4133 and "unconfirmed" and lists H12 as hostile (`plan_ids()` parses it, so keep its case IDs);
     - the "from memory" wording in `docs/verification.md`.
   - **Left to write in the agent** (the patch has the codec, the crypto, the served MIB, the responder and the log):
     - the `_test.go` files named under Acceptance;
     - a `Hook` per case, for the plan's §2 behaviours;
     - a small `cmd` binary taking `-case`, `-listen` and `-log`, for the runner;
     - the hostile corpus at both layers.
   - **The table's `unconfirmed` list:**
     - replace it with `confirmed` entries, each naming its RFC and section;
     - change `test_rfc_items_stay_marked_until_the_texts_are_in` to assert that every RFC-derived OID has a `confirmed` citation;
     - cite the RFC 2578 roots from `c6-wip/rfc-extra/` by SHA-256 until C1 adds them to `/mnt/project-files/rfc/`.
   - **Imports:** the agent imports only the standard library. The plan allowed the contracts test clock, but the agent does not need it, so the import test refuses every `modules/`, `contracts/` and `platform/` package.
   - **What the texts showed** (checked 2026-11-06, `desk`). Write these into the table:
     - **Confirmed:**
       - `entPhysicalSoftwareRev` is column 10 and `entPhysicalDescr` is column 2 (RFC 6933 §4);
       - `sysDescr` is system 1 and `sysName` is system 5 (RFC 3418 §2);
       - the HeaderData and UsmSecurityParameters layouts (RFC 3412 §6, RFC 3414 §2.4);
       - discovery (RFC 3414 §4);
       - the usmStats OIDs (RFC 3414 §5);
       - the 150-second window (RFC 3414 §3.2 step 7a);
       - the order of checks: user, level, MAC, window, decrypt (RFC 3414 §3.2 steps 4 to 8);
       - the PDU tags and BulkPDU (RFC 3416 §3);
       - AES-128-CFB with IV = boots, time, salt and no padding (RFC 3826 §3.1.2.1 and §3.1.3);
       - MACs of 24 and 48 octets (RFC 7860 §4.1);
       - SHA-2 key localization (RFC 7860 §5);
       - the time-window Report is sent at authNoPriv, and other Reports at noAuthNoPriv (RFC 3414 §3.2 step 7a; RFC 3412 §7.1 step 3d).
     - **Fixes:**
       - (a) **H12 is not hostile.** RFC 3417 §8 (1) allows a long-form length with more octets than needed, and its own §8.1 example (`a5 82 00 39`) uses one. The client's decoder accepts it, so move H12 to `positive`. The egress check refusing that form on our own outbound messages stays: it is policy, not RFC.
       - (b) **W4:** RFC 6933 has 18 accessible columns (2 to 19), so the count is 40 × 18 = 720, not 680.
       - (c) The `mib-2` and `snmpModules` roots come from RFC 2578 §2, which is not one of the eight texts.
   - **Acceptance:**
     - the agent imports no `modules/`, `contracts/` or `platform/` package (an import test);
     - it serves exactly S29's 76 lines (`agent/served.json`, pp. 46 to 47);
     - RFC 3414 A.3.2's SHA vector (`maplesyrup`, `66 95 fe bc ...`) passes through the same `PasswordToKey`/`Localize` with SHA-1;
     - a loopback test drives discovery, the time-window round, a get and a walk against the agent.
   - **Dependencies:** none. C2 and C3 review.
2. **The V-M1 runner on the real binaries (P4-3-C6).**
   - **Design:** one node with several SNMP assets, each with its own agent port and engine ID, so that every case runs in one schedule period. Base it on `slicehelper` `-snmp-port` (#466), `nodeconfigtest.AddSEL2731M` and `install-credential`, whose secret is `authKey || privKey[:16]`, localized with the agent's own code.
   - **Acceptance:** every case in `cases.json` (53, plus the hostile corpus at the layers each entry names; H0 and H12 are positive) is checked against the agent log, the collector's transcript, health and the audit chain; M3's key search finds nothing; there is one `integration-long` leg (C1 authorizes the ci.yml line).
   - **Dependencies:** C5 for a node with more than one SNMP entry, if `AddSEL2731M` cannot be called repeatedly; C3 for the install of an `snmpv3` credential through the admin relay.
3. **Gate table:** mark V-M1 met only after task 2 passes in CI. Then tell C1, who finalizes the item 3 exit report (#479, reviewed: four corrections posted).
4. **Small items, carried:**
   - `a6-windows-restart-marker.yml` line 42 says "ci.yml's 12m" (D4-22 made it 20m);
   - assert `_rows(s) == AHEAD` in `test_slice_unknown_restart_e2e.py`;
   - `TestB6HeldLinksDialAndBindNothing` (`tests/security/heldlinks_b6_test.go`) failed for C5 (2026-11-06, `desk`) beside a concurrent slice run: "address already in use" 184 times. The test frees a port and then treats any failure to bind it as the node binding it, so another process taking the freed port as an ephemeral port reads as a product fault. It passes alone. Fix: on a bind failure, tell the node's own listener apart from another process (on Linux, by matching the socket inode in `/proc/net/tcp` against this process's fds), and fail only on the node's.
   - D4-20's eight store cases: no single PR names all eight. V-M2 (#420) covers retention on the binaries. Check each case before calling it done.

## 4. Blockers and risks

- **B-01** (no hardware), **D4-12** (the owner's PC is paused), **H-17** (the SEL-2731/2741 hardware item, prepared only), **F-016** (Windows flush stalls).
- **HR-16** (the engine-ID pin, which V-M1 (c) tests), **HR-17** (whether a v1 or v2c path is ever added; V-M1 (d) covers the refusal only), **HR-18** (who holds the advisory key).

All of these are listed in `docs/verification.md` and `docs/threat-model.md`.

**Owed by the owner:** HR-17 and HR-18. The RFC texts were delivered on 2026-11-06.

**Unverified:**
- every GT-MIB value labelled SYNTHESIZED in the plan §1.1;
- the IANAPhysicalClass and TruthValue numbers the agent serves, since those MIBs are not in the texts;
- which Entity MIB version the SEL-2731/2741 implements (S29 names only `entPhysicalTable`).

## 5. Decisions and lessons

**Decisions:** [B1-decisions.md](../docs/phase4/B1-decisions.md), especially D4-49 to D4-51 (SNMPv3 in the collector, the family), D4-53 to D4-57, D4-12 and D4-22 (Windows budgets).

ADR-0008 orders the collection methods.

**Failed approaches this generation:**
- Filtering kernel router solicitations out of the V-M8 comparison was rejected. They are now stopped at the source with sysctls (18a2e21; recorded in #470).
- Bounding the unknown-sender test by the store's commit was replaced by waiting while the store moves (#447).
- An expected F-025 pair that was excluded silently would have hidden the defect, so it was raised as F-025 instead (`docs/verification.md`).

**Gotchas** (C1 rewrites `HANDOFF-SUMMARY.md` last; until that merges, its PR table and agent map are the B-to-C ones):
- After a squash merge, restart the branch with `git checkout -B <branch> origin/main` followed by `git merge -s ours <old tip>`. Force push is denied.
- One open PR per branch: a Markdown-only checkpoint PR must wait for the open PR to merge.
- `go test` in `tests/contract` imports `platform/node`; alias `contracts/node` as `cnode` there.
- V-M8's paired runs need root and `unshare -n`. This container has no IPv6, but the CI runner does.
- Use `$(go env GOROOT)/bin/gofmt`, not the `gofmt` on PATH (an older Go's, which flags `relptest_test.go` falsely).
- The GitHub MCP tools disconnect at times. Reload them with ToolSearch.

## 6. Progress against C6-handoff.md

- **1, review #346:** done. It merged as `151c17a`.
- **2, land #336:** done as #379 (`0a7d915`, D4-21 cases), which replaced it.
- **3, D4-20 cases:** partial. V-M2 on the binaries (#420) and C9's bound (#398) exist. No record checks all eight cases, so the task is carried as item 4.
- **4, V-M2 and V-M3:** done (#420, #394).
- **5, V-M4:** done (#410, #417, #431).
- **6, C2 0.6 contract tests:** done (#423).
- **7, the Phase 4 status table:** done (#423 for the first gate; #473 and #475 for item 3).
- **8, the syslogreceive Windows failure:** fixed (#447).
- **9, small items:** two are still open (task 4), untouched for one generation, so not STALLED.
- **Out of scope:** none. Every C6 commit is in owned paths.
- **Regressions:** none.
- **Review debt:** none over a day old.
- **Repeated work:** none.

Validation (2026-11-06, a fresh read-only subagent given only CLAUDE.md, the summary, this file and its links): it chose the right next action. Fixed after it: the plan document and the case-table test that confirming the RFC items breaks, the import rule, the RFC 2578 citation, the branch order for the checkpoint and agent PRs, what is left to write in the agent, H0 and H12 as positives, the stale `c6-wip/README.md`, and the §5 reference.
