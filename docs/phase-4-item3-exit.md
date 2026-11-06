# Phase 4 item 3 exit report (vulnerability applicability with the asset module)

Owner: C1 (the A1 role). Date: 2026-11-06. Status: **DRAFT. The gate is not yet decided.** It waits on:

- #466, #474, #475, #476 and #477 merging;
- V-M1, which waits on the owner's choice for the RFC texts.

C6's gate table in `docs/verification.md` ("Phase 4 item 3 exit gate status") is the record for each gate item.

This report closes Phase 4 item 3:

- **R9**, vulnerability applicability against a signed offline advisory set;
- **R1.8**, the asset module, with SNMPv3 identity reads through the collector.

These are in ADR-0008's order, and the owner issued them on 2026-11-05 (D4-48). Work stops at the end of the item for the owner's check (D4-34). The report follows the milestone format in `CLAUDE.md` §9 and mirrors `docs/phase-4a-exit.md`.

**Evidence and test path:**

- No device was contacted.
- Every result is `desk` (Go and Python tests on a CI runner or an agent's container) or `simulated` (the real binaries against C6's recording simulator, on loopback).
- No result is `hardware-verified` (B-01).
- Every advisory, set and signing key is a test one.
- The owner's PC was not used (D4-12), so GitHub Actions was the only shared test path.

In older records, A*n* and B*n* mean the role that C*n* now holds (D3-12, D4-28).

## Milestone

**Phase 4 item 3: vulnerability applicability on the simulated SEL-751, with the asset module's SNMPv3 path for the SEL-2731/2741 in RSTP mode.** The objectives come from the item 3 briefs and exit gate in `docs/agent-handoffs.md`:

- **Asset identity.** Record an asset's identity attributes with their source: a device read, or an operator entry recorded in the audit chain (C1 0.3).
- **SNMPv3 identity reads.** Read identity over SNMPv3 `authPriv` only, from the collector, with:
  - collector-held localized keys;
  - a pinned engine ID;
  - named OIDs;
  - an independent egress check that refuses every write form (C3 0.4, C2 0.7 and 0.8, C7 0.8; HR-16, AP-28).
- **The advisory set.** Install a signed offline advisory set with anchors, a version floor and refusals that are recorded and alarmed (C11 0.1, C8 0.11; HR-18, AP-29).
- **Findings.** Match each asset's identity against each advisory, and store an explained finding with:
  - its class;
  - its evidence, by source;
  - its staleness;
  - its revisions (C12 0.1, C5 0.8).

  The finding never probes a device (V-M8).

## Implemented (on `main`)

| Component | Owner | Main PRs | Reviewers |
| --- | --- | --- | --- |
| The SNMPv3 family note (the SEL-2731/2741 in RSTP mode, D4-51). C1 0.3, C3 0.4, C2 0.7 and C2 0.8. The collector's SNMPv3 client in `modules/ied/snmpv3`. Its adapter ID and version | C2 | #439, #445, #453, #462 | C3, C4, C6 |
| C11 `otsec.advisory/0.1`, C7 0.8 and C8 0.11. The SNMP egress check and the advisory signing tool. SNMPv3 credentials in the credential store. The SNMP path through the collector's pipeline. Node ID `audit` reserved (D4-57) | C3 | #437, #446, #449, #456, #461, #465, #477 *(pending)* | C2, C4, C5, C6 |
| C12 `otsec.finding/0.1` and the matcher note. The matcher in `modules/applicability`. A mismatch under an operator identity. Passive evidence never an audit reference (D4-57) | C4 | #440, #451, #459, #476 *(pending)* | C3, C6 |
| The node's side of item 3. C5 0.8. Parts 1 to 3: the switches, the advisory set and the item 3 ceiling; identity records, latest reads and SNMP entries; findings and the evaluation. A node with one SNMP entry. Recorded network controls (D4-56). The per-family register note, and its code in #466 *(pending)*. The certificate-period test fix. `in_use_since` across a restart, in #474 *(pending)* | C5 | #438, #444, #450, #452, #454, #458, #463, #464, #469, #471, #466 *(pending)*, #474 *(pending)* | C3, C4, C6 |
| The item 3 testability check. GT-ADV, the applicability truth table, written before the matcher. The GT-MIB plan and case table. V-M7's checker. V-M7 and V-M8 on the real binaries. The gate table. The contract tests for C7 0.8 and C12 0.1, `check.py` over the V-M7 and V-M8 recordings, and H-17, in #475 *(pending)* | C6 | #436, #441, #447, #457, #467, #470, #473, #475 *(pending)* | C1, and the owners of what each test covers |
| D4-48 to D4-57, the item 3 briefs and exit gate, and the CI legs | C1 | #435, #442, #443, #455, #460, #468, #472, #478 | The affected owners for each ruling |

Contract versions on `main`:

| Contract | Items 1 and 2 exit | Now | What item 3 added |
| --- | --- | --- | --- |
| C1 | `otsec.asset/0.2` | `0.3` | Identity attributes with their source (device read or operator). SNMPv3 endpoints, with `snmp_engine_id`. An optional `CapabilityProfile.models`. |
| C2 | `otsec.adapter/0.6` | `0.8` | SNMP results: `session.snmp`, the engine ID as the first identity item (AP-27), and `observations[].read`. Codes `failed.snmp_fid_unreadable`, `failed.snmp_unexpected_report` and `failed.snmp_scoped_pdu_unreadable`, none of which suspends anything. An authenticated FID mismatch suspends the asset only (D4-54). |
| C3 | `otsec.register/0.3` | `0.4` | SNMP read operations: named OIDs, `GET`, `GETNEXT` and `GETBULK` only, with `set` refused at load. |
| C5 | `otsec.store/0.7` | `0.8` | The four item 3 series. The item 3 ceiling below the configuration floor. `identity.read`'s optional `mismatch` object (D4-55). |
| C7 | `otsec.authz/0.7` | `0.8` | The `snmpv3` credential: localized keys, `authPriv` only, the pinned engine ID, and HMAC-SHA-256/512 with AES-128. |
| C8 | `otsec.audit/0.10` | `0.11` | `advisory.set_installed` and `advisory.set_refused`. |
| C11 | none | `otsec.advisory/0.1` | New. The signed offline advisory set: anchors, test key IDs a release build refuses, the version floor and the load rule's order. |
| C12 | none | `otsec.finding/0.1` | New. A finding: its class, its evidence by source, its staleness and its revisions. D4-57 tightens what it accepts with no version change. |
| C4, C6, C9, C10 | | unchanged | |

The item 3 contracts were approved together under D4-53. Every change bumped the minor, kept a reader for the previous version, and had C6's contract tests before the gate. C7 0.8's and C12 0.1's C6 tests are in #475 *(pending)*.

## Independently verified

C6's gate table in `docs/verification.md` is the record. C6 wrote GT-ADV before the matcher existed (#441) and the GT-MIB case table before the SNMP agent. V-M7's checker has mutants that each fail their cell.

| Check | Result |
| --- | --- |
| **V-M7** (R9) on the real binaries | **Pass**, `simulated` (#467, #469). All 128 GT-ADV cells pass on main, locally and in the `integration-long` leg. Each of the eleven device-read rows runs on its own node and simulator, and D1's node also holds the five operator rows. Operator rows and denied-branch rows are never `confirmed` (F1). A restart changes no finding and no evidence ID. D2's FID mismatch is kept apart and hides no advisory, before and after a restart. The control cells (TEST-ADV-03 × D8 and × D9) pass with a recorded control (D4-56). |
| **V-M8**, set cases | **Pass**, `simulated` (#470), 17 of 17. Ten bad files are each refused with their C11 code, with one `advisory.set_refused` record, the alarm and status's last refusal, and the set in use unchanged. The same bytes again, or a restart, records nothing. Version 3 installs, naming version 2. A set whose key is revoked in the configuration is dropped at start, and no older set replaces it. |
| **V-M8**, paired runs | **Pass**, `simulated` (#470), 9 of 9. The runs are made as root in a network namespace whose only interfaces are `lo` and a TUN device holding both default routes. The A/A pair matches packet for packet, and so does the R9 run against A1. No run has a flow A1 lacks, and nothing is routed off the host. Kernel ICMPv6 router solicitations broke the first run. They were stopped at the source, not filtered in the comparison (C6, 18a2e21). |
| **V-M8**, a release build refuses a test set | **Pass**, `desk`, Go level only. The binaries' runs use the `otsec_testclock` build, the only one that accepts a test set. The refusal is pinned by tests that `go test ./...` runs untagged: `c11_c6_test.go` ("first test set, release build"), `TestAdvisorySetRefusals`, `TestItem3ConfigRefused` and `TestTestKeyIDsAreTheSeeds`. |
| **V-M1** over GT-MIB | **Not run. It waits on the RFC texts** (see Owner decisions needed). The client (#453), the collector's SNMP path (#461), the node's SNMP entry (#463) and GT-MIB's case table (#457) are built and tested at Go level against a fake agent on loopback. (d), the refusal alone, is shown at desk: C1 0.3, C7 0.8 and C3 0.4 refuse v1 and v2c, and the egress deny corpus refuses whole v1 and v2c messages. The gate never counts a GT-MIB built from memory. |
| **V-S7** | **Pass for the corpus and the SEL path.** The egress deny corpus refuses every SNMP write form (`SetRequest`, also hidden as a second scoped PDU inside the encryption; `InformRequest`; `SNMPv2-Trap`; `Report`; `GetResponse`) and whole v1 and v2c messages. The valid messages are allowed first. C3 0.4 refuses `set` at load. `check.py` over the V-M7 and V-M8 recordings against revision 5 is in #475 *(pending)*. |
| **Contract tests** | C1 0.3, C3 0.4 and C2 0.7 (#445). C5 0.8 (#450). C11 0.1 and C8 0.11 (#446). C7 0.8 and C12 0.1 in #475 *(pending)*. |

### Defects found by independent review and tests in item 3

- **No control could be recorded** (C6 on #467). V-M7 needed a recorded network control for TEST-ADV-03 × D8 and × D9, and none existed anywhere: C11 and the matcher note had left it to C1 0.3, which never settled it. Fixed by D4-56 and #469. #467's pin was a tripwire, not a waiver.
- **An audit citation could read as passive evidence** (C6's F-025, desk). With a node named `audit`, `audit:<node>:<seq>` is also a valid passive event ID, which could back `confirmed`. No configuration ever named a node `audit`. Fixed at both ends by D4-57: #476 and #477 *(pending)*.
- **Item 3 evidence could fill the configuration class** (C6's FAIL on #444). Fixed by the item 3 ceiling (D4-54), and by when its crossing ends (D4-55).
- **A false downgrade after a restart** (C5 for part 3). A mismatch FID held only in memory would have turned an `applicable-by-version` finding into a stored `product-not-named`. The FID is now stored (D4-54, D4-55).
- **A bare model name matches nothing** (C2 on #451). `SEL-2731` gives a false `not-applicable`, because the device reports `SEL-2731M`. This is now a rule for whoever authors the set (D4-54).
- **A certificate-period test that could not pass on a slow Windows start** (#469, #466). The third try's release wait was counted from the end of the held checks, so it ended before `NotBefore`. Fixed in #471.
- **The in-use time reset on restart** (C1 on #470). Fixed in #474 *(pending)*.

### Where tests ran

- **CI** is the main test path (D2-13). `ci.yml` now has **eighteen jobs**: Go on Linux and Windows, pytest, `integration`, and fourteen `integration-long` legs. Item 3 added three legs:
  - V-M7 over GT-ADV;
  - V-M8's set cases;
  - V-M8's paired runs, as root in a network namespace of their own.

  `govulncheck` also runs on Linux and Windows targets. The A1 role checked every merge against green checks on the PR's head, and checked the merged result when `main` had moved.
- **The owner's PC** was not used (D4-12).

## Exit-gate items

| Gate item (`docs/agent-handoffs.md`, "Phase 4 item 3 exit gate") | State |
| --- | --- |
| V-M7 passes per cell over GT-ADV on the real binaries, `simulated`, for the SEL-751 path, including the denied-branch rows (F1) | **Met.** |
| V-M8 passes: every set refusal case, and the paired runs | **Met.** A release build's refusal of a test set is shown at Go level only. |
| V-M1 (a) to (c), (e) and (f) pass over GT-MIB, and (d) is shown for the refusal alone | **Not met.** It waits on the RFC texts, and the choice is with the owner. |
| C1 0.3, C3 0.4, C2 0.7, C5 0.8, C7 0.8, C8 0.11, C11 0.1 and C12 0.1 merged, with reviewers' records and C6's contract tests | **Met for six of the eight.** C7 0.8 and C12 0.1 are met once #475 merges. |
| V-S7 still passes, and the egress deny corpus refuses every SNMP write form | **Met for the corpus and the SEL path.** The recordings are met once #475 merges. |
| No real advisory is in any set, and the gate says which owner questions are open | **Met.** The questions are listed below. |
| No safety or security objection open | **None open from C6.** F-025 is closed once #476 and #477 merge. C3: *(to confirm before the gate)*. |

## Owner decisions needed

1. **V-M1 and the RFC texts.** The choice is on the decision card. Either:
   - allow `www.rfc-editor.org` in the environment's network policy;
   - upload RFC 3411, 3412, 3414, 3416, 3418, 3826, 6933 and 7860;
   - or close item 3 with V-M1 open as a condition.
2. **Who publishes the advisory set and holds its signing key** (HR-18). No real advisory is entered until this is answered. C3 recommends an offline Ed25519 key on a dedicated device, with one curator signing and a second person checking each set's citations.
3. **Whether reports show publisher severity scores** (C3, #437 §5).
4. **Whose key may sign a v1 or v2c per-device approval**, if a v1 or v2c path is ever added (HR-17). Item 3 builds none.
5. **Which SEL switches the sites run.** D4-51 picks the SEL-2731/2741 in RSTP mode on the evidence. The SEL-2730M would follow if the sites run it, with its own ruling on SHA-1.
6. **Model naming for set authors.** Models must be named as the device reports them, with the mode letter (`SEL-2731M`). This goes to whoever publishes the set.
7. **Accept item 3** with the conditions in this report, and choose the next item.

## Failed or incomplete

- **V-M1 is not run** (above). The egress corpus's message layout is written from memory of RFC 3412, 3414, 3416 and 3826, so it is unconfirmed until those texts are in the project. A layout error would make the valid messages fail, which the positive cases would catch. No SNMP message has gone over a socket to a real or simulated agent beyond the Go-level fake.
- **The Windows node start can stall for more than 12 s, and nobody yet knows why.** #471 made the certificate-period test survive it: #471's own run had a late try with a 6 s margin that took 12.47 s and recovered. The cause on the hosted Windows runner is not found. The `platform/node` Windows budget warning (743 s against 720 s) stays a warning under D4-44's ruling.
- **Carried from the first exit:** `config.reads_removed` is contract only; V-S7's 24-hour soak, (c) and (d); V-S6, V-S9, V-S15, V-S18 and V-S20.

## Unverified assumptions

Everything in the earlier lists still stands. Item 3 adds:

- **The SEL-2731/2741's SNMPv3 behaviour** (S29, `documented-untested`):
  - `authPriv` only;
  - the engine ID format, inferred to be MAC-based and to survive a firmware upgrade;
  - the OIDs it serves, and the model and FID forms.

  H-17 in #475 *(pending)* is the hardware item.
- **The real FIDs, and each real advisory's conditions.** These wait on H-01 and on a desk check against the publisher.
- **The SNMP wire layout**, from memory of the RFCs (above).

## Architectural decisions

D4-48 to D4-57 are in `docs/phase4/B1-decisions.md`. These matter most for later items:

- **D4-49 and D4-50.** SNMPv3 runs in the collector, never the node. Applicability never probes a device.
- **D4-51.** The first SNMPv3 family is the SEL-2731/2741 in RSTP mode. SHA-1 stays out.
- **D4-53.** The item 3 contracts were approved together. The product match uses the device-read model, never a declared family. A precondition read false outranks every other mitigation.
- **D4-54.** C5 0.8's item 3 ceiling. An authenticated SNMP FID mismatch suspends the asset, not the credential. Apply never adopts a mismatched identity. Which findings are stored, and how status proves an evaluation ran.
- **D4-55.** The `identity.read` mismatch object. The declared-identity record. The engine-ID pin re-checked at each run. The register is found by firmware allowlist.
- **D4-56.** A network control is operator configuration beside C1, recorded in the chain, cited as `operator_attested`, and never from a device.
- **D4-57.** An audit citation never reads as passive evidence, and `audit` is not a node ID.

## Open risks

- **No hardware (B-01).** No SEL family may be called supported.
- **HR-18.** Whoever holds the advisory key decides what every site believes. Separate anchors, the test-key refusal and the version floor are built in, whatever the decision.
- **"Operator-attested" means whoever can write the node's configuration** (C3). The `policy.apply` record names no person, so an operator identity or a control is as trustworthy as the configuration file's access control.
- **An unrecorded control moves a finding out of `mitigated`** (C4 on #469). If the control record cannot be written, the asset is evaluated with no controls. This is D4-56's intended fail-toward-fewer-mitigations behaviour, and the `asset-controls-not-recorded` alarm raises it.
- **An SNMP agent is hostile input** (AP-28, SC-14). The BER decoder is bounded and memory-safe, but it is tested only against the fake agent and the corpus so far.
- **A tagged `otsec_testclock` build accepts a test set and test keys.** CI pins that release builds refuse them. A tagged build must never be deployed.
- **Carried:** every risk in `docs/phase-4a-exit.md` that is not closed above.

## Limitations recorded in item 3

- **A configuration-read asset is `confirmed` only from its second read** (D4-56). The first stored snapshot counts as a change, so the class errs toward the weaker one for one read interval.
- **A mismatch on an operator identity is not cited in the finding** (D4-55). C12 0.1 refuses identity evidence of a different source from the identity. The mismatch shows in `identity.read`, in status and in the chain's `asset.suspend` record. Citing it in the finding is a C12 0.2 item.
- **The declared-identity and control records are not held from pruning** (D4-55, D4-56). Holding them would stop audit pruning altogether. Instead the node keeps each cited `policy.apply` reference in `declared-identities.json`. A file entry is trusted only for a record already pruned from the chain, below its first retained record; a record still in view comes from the chain. If the file is lost, the cost is one new record and one revision for each finding that cited it (C3 on #458). A lost file never changes a class.
- **SNMP profile placeholders.** The SNMP profile's `password_attempts` and `secret_policy` are placeholders, because those values do not apply to SNMP in the same way. Accepted for item 3 as a C1 0.4 item.
- **`product-not-named` findings are not stored** for an entry with no earlier finding for the asset. Status proves the evaluation ran under the set (D4-54).

## Lessons

- **A truth table written before the code finds design gaps, not only bugs.** GT-ADV's D8 and D9 found that no control could be recorded, and GT-ADV's D10 and D11 shaped two rulings in D4-53.
- **A pin that fails on purpose keeps a gap visible.** #467's pin kept V-M7 honest while CI was green.
- **Two ID forms that can collide are a contract defect,** even when no configuration makes them collide today (F-025).
- **Fix noise at its source, not in the comparison.** V-M8's paired runs stopped the kernel's router solicitations instead of filtering them, so the test still sees every packet.
- **Waits counted from the wrong instant fail only on slow runners.** #471's wait was right on desk and wrong on hosted Windows.

## Where the eight capabilities stand

| Capability (brief §1) | Phase 4 item 3 | Planned |
| --- | --- | --- |
| 1.1 Asset management and monitoring | Identity attributes with their source. SNMPv3 identity reads through the collector for the SEL-2731/2741, built and tested at Go level, with V-M1 not yet run. Vulnerability applicability (R9) end to end on the real binaries for the SEL-751, `simulated`. | V-M1. Real advisories after HR-18. Other families. |
| 1.2 Secure engineering and remote access | Not built. | Phase 4, item 5. |
| 1.3 Configuration and baseline monitoring | Unchanged. The configuration read now also feeds identity. | |
| 1.4 Syslog and SER collection | Unchanged. | |
| 1.5 Custom IED command framework | C3 0.4 SNMP read operations, and the SNMPv3 client. | |
| 1.6 Intrusion detection | Not built. | Phase 4, item 4. |
| 1.7 Modular and additive architecture | `asset` and `applicability` each enable and disable on their own. Every contract change was additive. | |
| 1.8 Centralized and distributed deployment | Single-site node only. | Phase 4, item 6. |

## Next coordinated tasks

1. **V-M1**, on the owner's choice: C6 builds GT-MIB's agent from the RFC texts and runs V-M1.
2. **C12 0.2**: cite a mismatch on an operator identity. **C1 0.4**: the SEL-2731/2741 profile from measurement, after H-17.
3. **The next Phase 4 item**, after the owner's check (D4-34).

## Owner sign-off

Not yet given.
