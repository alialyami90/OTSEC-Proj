# Handoff P3-A6 — A6 — 2026-10-26

The brief is "Task P3-A6" in `docs/agent-handoffs.md`. Every result below is `simulated`, or comes from the GitHub-hosted Windows runner where that is stated. Nothing here ran against a device or on the owner's PC, and nothing is hardware-verified. The Phase 3 status table is in `docs/verification.md`, under "Phase 3 status".

## Completed

- **V-S8 end to end** (`tests/integration/slice/test_slice_evidence_e2e.py`, #172). The oracle is GT-REC's `sent` records, not the product's parser. Two slices: Figure 10.16, and the same report with row 5's time damaged so it does not parse. Every stored capture, record and forwarded message is checked against the bytes the simulator sent.
- **The ADR-0008 criteria**: V-M1 to V-M8 in `docs/verification.md` (#144), written before any of R1.8, R3.6, R3.7, R4.8, R4.9, R6.7 and R9 is implemented. The R4.8 observation period and false-positive measure, and what makes an R9 finding `confirmed`, are fixed there.
- **Independent checks of the Phase 3 PRs.** For each one: my own tests from the rule text, mutants of the code under test, and a PASS or FAIL comment on the PR. The table under Evidence lists them.
- **The tests themselves** are on `main` through #172:
  - contract: C1 path, C2 0.5 settings, C3 context, C4 0.2 leaf, C5 busy-open retry, C6 0.3 `tlsleaf`, C7 admin requests, C8 0.3 quarantine;
  - integration: `storeopen`, `storediscard`, `quarantine`, `syslogreceive`, `sel751datef`, and the busy-open, evidence and Syslog-receive slices;
  - security: `admin_nonce_test.go`, `collector_path_test.go`, `syslog_frame_bounds_test.go`, `nodekey_cng_windows_test.go`;
  - D3-8: the relayed audit record order, checked for every collector request.
- **The simulator's `SHO G` with a `DATE_F` switch** (#166), from the manual, written independently of A2's adapter.
- **Test timing fixes** (#188, open): the interruptions suite's kill point, `waitN`, and two receive tests on slow Windows runners. The test changes are explained in #188. No product change.

## Evidence

Verdicts are on each PR. "Mutants" counts mutants of the code under test that my tests kill; an "equivalent" survivor changes nothing a caller can observe.

| PR | What | Verdict | Mutants |
| --- | --- | --- | --- |
| #145 | C5 0.2 busy-open retry | PASS | 15 of 17. The 2 survivors make a busy open terminal (the 0.1 behaviour, the safe direction); no real open can produce their input |
| #146 | C7 0.4 admin-signed requests | PASS | 24 of 24 |
| #147 | node busy retry, real binaries | PASS on two conditions, both met at e8a03d3 | 6 of 8, then the survivor that lifted a halt was killed by A5's new test; 1 equivalent |
| #149 | C1 0.2 endpoint path | PASS | 10 of 10 |
| #150 | Syslog receive | PASS | 24 of 26 |
| #151 | C5 0.3 Discarder | PASS | 8 of 9; 1 equivalent at store level |
| #153 | collector side of C7 0.4 | **FAIL** (replay after the clock goes forward and back), then PASS at 9167199 with the clock high-water mark | A3's mutation pass on the fix killed 7 of 7 |
| #154 | Syslog listeners, real binaries | PASS | 3 of 3 |
| #155 | C8 0.3 quarantine records | PASS | 16 of 16 |
| #156 | C3 0.2 context, register rev 4 | PASS | 11 of 11 |
| #157 | node key store | PASS on the hosted Windows runner: `TestA6NodeKeyClaims`, D3-7 claims (a) to (c) | — |
| #160 | collector path guard | PASS | 2 of 2 |
| #163 | quarantine export and clear | PASS | 8 of 8 |
| #164 | C2 0.5 settings | PASS | 10 of 11; 1 equivalent |
| #167 | C4 0.2 `tls_leaf_sha256` | PASS | 15 of 15 |
| #169 | listener sizing | PASS on the claim as A1 worded it (HR-11 mitigated in part, within the configured outage) | — |
| #170 | C6 0.3 `tlsleaf` | PASS | 5 of 5 |
| #171 | D3-8 relayed record order | my test in #172 | 5 synthetic, all killed |
| #174 | node size bounds on received frames | PASS | 5 of 5 |
| #175 | SEL-751 C1 path, `DATE_F`, TIDLE | **FAIL** (TIDLE read outside `SHO P 1`), then PASS at 581c38a | 10 of 10 |
| #178 | unknown budget across restarts | PASS, two observations | 5 of 6; the survivor is stricter, not weaker |
| #180 | collector grants its node the two query rights | PASS on the hosted Windows runner (via #185): claims (a) to (d) | — |
| #183 | collection-method rungs | PASS: 12 of 12 cells I checked match their citations | — |

Local runs for #172 and #188 are in their PR bodies. CI is the record of what passed on `main` (D2-13).

## Interfaces

None introduced or changed. The tests use only exported product APIs and the contracts, and my own fixtures: the recording simulator, the scripted SEL-751, the SQLite holder and the receive rig. `slicehelper` gained `-syslog-udp` and `-syslog-tls` (#172).

## Limitations

- **The slice against the installed Windows services has not run** (the first Phase 3 gate item, P3-W1). It waits on #179 (the service mode), #180 (the pipe rights, PASS) and the signed administrator files (#181, a design). Then the owner runs it on the PC.
- **Two test files are written but not on `main`:**
  - `tests/integration/syslogreceive/restart_test.go`, the unknown budget across restarts. It goes in after #178 merges;
  - `tests/security/collectorwire_services_windows_test.go`, the two-service pipe identity. It goes in after #180 merges.
- **#180's Windows run is not verbose**, so the per-probe values are not printed. The test fails on any probe that differs, so the pass covers them.
- **Everything is simulated.** The simulator and the adapter both come from the SEL-751 manual, so agreement between them is not hardware evidence (H-01 to H-15 are still prepared only).
- **The flood test catches a shared rate bucket only by its lag.** A mutant that shares one rate bucket between senders gave a 376 ms lag. Neither the old fixed 2 s bound nor #188's bound catches it.

## Risks

- **#178, observation 1:** a clock stepped forward across a restart gives a full unknown budget, because the received-time count sees nothing in the window. This is HR-11 territory and stays open until the absolute bound (a C5 class and quota), which gates the first device-observed listener.
- **#178, observation 2:** counting by received time can miss about one queue of records at the window's edge. That is small next to the budget, but it is a few KiB per restart.
- **The collector clears its floor about 10 ms after `QUI`**, after the run returns. A kill in that gap leaves the TIDLE + 1 min floor. That fails safe, but `state.go`'s comment says the floor is cleared at `QUI`. A1 has passed this to A3.
- **HR-12** (a spoofed address on a plaintext listener) stays as A3 recorded it.

## Dependencies

- **A1:** merge #188. After #178 and #180 merge, I add the two pending test files in one PR.
- **A5:** #179 ready for my review. Then the owner's PC run (P3-W1), with A6's checks as in the P3-W1 brief.
- **A3:** the `state.go` comment fix. A C8 test case for the target asset-ID pattern is still owed by A3, as A3's handoff records.
- **A4:** none open from A6.

## Files changed

- `tests/contract/`, `tests/integration/`, `tests/security/` (through #172 and #188)
- `tests/safety/recording_simulator/` (`SHO G`, #166)
- `.github/workflows/ci.yml`: the busy-open slice in `integration-long` (#172, A1 authorized)
- `docs/verification.md` (V-M1 to V-M8, V-S8, the Phase 3 status table), this file

## Reviewer(s) and outcome

- A1 merged #144, #166 and #172. #188 is open.
- The verdict comments are the review record for each PR in the Evidence table.
