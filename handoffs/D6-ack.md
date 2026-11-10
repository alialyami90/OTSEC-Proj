# D6 acknowledgement

From D6 (Independent Verification and OT Safety Engineer), 2026-11-06 about 13:00Z, at `main` `a774a97` (#486, the C1-to-D1 checkpoint, merged). I read [CLAUDE.md](../CLAUDE.md), [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), [D6-handoff.md](D6-handoff.md), D4-58 in [B1-decisions.md](../docs/phase4/B1-decisions.md), role 6's WIP note (a working file that was not kept), the open PR list on GitHub, and `nodeconfigtest.AddSEL2731M` (for the runner's design).

## My scope

I am the independent verifier. I try to disprove claims; I do not approve them by default.

- **I own:** `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md`, `.github/workflows/a6-*.yml`, my own `docs/phase4/C6-*.md` and `D6-*.md` files, and this file.
- **I do not touch:** product code (`modules/`, `platform/`, `cmd/`, `contracts/`, `deploy/`, `ui/`), other agents' documents, or `ci.yml` without D1's written authorization. Probes and mutants stay in worktrees and are never committed.
- **How I work:** every test has an oracle that is not the product's code. Every verdict on a PR is PASS or FAIL (CHANGES NEEDED), with its mutants, probes and survivors, and ends with the attribution footer. A critical safety or security failure blocks acceptance. I never approve or merge, and never skip, disable or quarantine a test.
- **Standing rules I keep:** the summary's list, unchanged. No device contact; the simulator and GT-MIB stay on loopback; test credentials only (D2-5, D2-11); nothing on the owner's PC while D4-12 holds; GitHub Actions is the only test path; stage by explicit path; no force push; messages to other agents go through the coordinator (D4-58). Evidence is `desk`, `simulated`, `CI-Linux` or `CI-Windows`; nothing is `hardware-verified` (B-01).

## State as I found it (differences from the handoff files)

| Item | Handoff says | Found | Source |
| --- | --- | --- | --- |
| C1's checkpoint PR | summary step 0: merges on D6's review | merged as `a774a97` before any D6 review | #486, `git log origin/main` |
| Open PRs | only the checkpoint PR | none open | GitHub open PR list, about 12:55Z |
| RFC 2578, 3417, 1157, 1901 | D6-handoff §2: tell C1 so they join `reference/rfc/` | done. All twelve are there, `sha256sum -c SHA256SUMS` passes for all twelve, and the four match role 6's earlier copies byte for byte | D4-58; `reference/rfc/SHA256SUMS` |
| Code since C6's checkpoint run | `158a5d0` | `main` differs from `158a5d0` only in Markdown (10 files: handoffs, CLAUDE.md, README.md, B1-decisions.md), so C6's Go and pytest results still describe the code | `git diff --name-only 158a5d0 origin/main` |
| GT-MIB WIP patch | role 6's WIP patch of 2026-11-06 (not kept) | present; `git apply --check` is clean on `a774a97`; SHA-256 `733f1f48…0cfccd` | desk, this container |
| `AddSEL2731M` called more than once | handoff task 2: may need D5 | it appends, so it can be called repeatedly with distinct ports. Its engine ID (`TestSNMPEngineID`) and credential ref (`cred_lab2731usm`) are constants, and its schedule ID uses `assetID[:8]`. The runner can set a per-asset engine ID and credential ref on the returned `Config` in test code, so D5 may not be needed | `platform/node/nodeconfigtest/nodeconfigtest.go:270-345`, desk |

Checks on `a774a97` (Linux, this container): see the PR description for `go vet`, `gofmt` and `go test` exit codes. `pytest` was not rerun for the ack; C6's run covered the same code.

## My first three actions

1. **Finish GT-MIB's agent (P4-3-C6, V-M1; NEXT ACTION in D6-handoff §3).** Apply the WIP patch, then write the four acceptance tests: the import test (no `modules/`, `contracts/` or `platform/` package), exactly S29's 76 served lines, RFC 3414 A.3.2's `maplesyrup` SHA vector through the same `PasswordToKey`/`Localize`, and a loopback test for discovery, the time-window round, a get and a walk. Then the per-case `Hook`s, the `cmd` binary (`-case`, `-listen`, `-log`) and the hostile corpus at both layers. Every byte rule cites a section of the twelve texts in `reference/rfc/`; nothing is built from memory.
2. **Correct the case table to what the texts confirm, in the same PR.** In `cases.json`, replace `unconfirmed` with `confirmed` entries that each name an RFC and section, and change `test_rfc_items_stay_marked_until_the_texts_are_in` to assert every RFC-derived OID has a `confirmed` citation. Move H12 to `positive` (RFC 3417 §8 (1) and its `a5 82 00 39` example). Set W4 to 720 (RFC 6933, 18 columns times 40). Cite the `mib-2` and `snmpModules` roots to RFC 2578 §2. Fix the same three points in `docs/phase4/C6-gt-mib-plan.md` (keeping its case IDs, which `plan_ids()` parses), the `egress/deny_test.go` header, and the "from memory" wording in `docs/verification.md`. Reviewers: D2 (SNMP reading) and D3 (security), asked through the coordinator.
3. **Build the V-M1 runner on the real binaries.** One node with several SNMP assets, each with its own agent port, engine ID and credential (set in test code on `AddSEL2731M`'s result), so every case runs in one schedule period. V-M1 (a) runs D4-50's three combinations on the real binaries through #463's node start: both off (no SNMP entry, since the loader refuses one without the asset module, and GT-MIB must log zero PDUs), asset alone, and both on (D5 asked this, via the coordinator). Check each case in `cases.json` against the agent log, the collector's transcript, health and the audit chain, and run M3's key search. Add one `integration-long` leg once D1 authorizes the `ci.yml` line. Only after it passes in CI do I mark V-M1 met in the gate table and tell D1.

After those, the handoff's small items (task 4) in order: the `a6-windows-restart-marker.yml` 12m wording, `_rows(s) == AHEAD`, the `TestB6HeldLinksDialAndBindNothing` port-reuse false positive, and the D4-20 eight store cases.

## Questions

1. **#486 (D1).** It merged before D6 reviewed it. Do you want a post-merge review of the C-to-D summary? I read it as closed and found nothing in it that changes my work, other than the RFC item above, which is already done.
2. **Branch order (D1).** One open PR per branch, and this ack holds mine. I read the summary as letting me write the agent and the table now, and push them as a new PR once this ack merges. Is that right, or do you want me to wait for cutover before writing code?
3. **The V-M1 leg in `ci.yml` (D1).** I will need one new `integration-long` leg. Please say whether to propose its line in my PR for you to authorize there, and what time limit you want (I expect it to be well under the 50-minute `gtinj_ser` leg; I will measure it before asking).
4. **The SNMP credential install (D3).** The runner installs one `snmpv3` credential per asset through the admin relay, each `authKey || privKey[:16]` localized to that asset's engine ID. Is there any limit or rule on several `snmpv3` credentials on one collector that I should know before I build on it?

None of these blocks the ack.
