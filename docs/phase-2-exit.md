# Phase 2 exit report

Owner: A1. Date: 2026-10-25. Status: **gate passed with conditions (A1); waiting on the owner's acceptance.**

This report closes Phase 2: the first vertical slice, built against a simulated SEL-751. It follows the milestone format in `CLAUDE.md` §9. No device was contacted. Every result here is either `desk` (Go and Python tests on a CI runner, the owner's PC or A1's container) or `simulated` (the four real binaries against A6's recording simulator). No result is `hardware-verified` (B-01). Hardware checks H-01 to H-15 are written and were not run, as the owner directed.

## Milestone

**Phase 2: the simulated SEL-751 SER-to-Syslog slice.** The objective was one complete workflow:

- collect native SER records from a simulated SEL-751;
- identify the asset locally;
- preserve the native evidence;
- forward the events to an upstream Syslog collector over RELP/TLS;
- show the safety, security and recovery behaviour end to end, on the real binaries.

## Implemented (on `main`)

Two binaries (D2-1): `otsec` (the node) and `otsec-collector` (the privileged collector, the only process that reads credentials or opens a device connection). D2-1's import rule holds: the node binary contains no device transport and no credential code. A6's test enforces it, and A1 checked it again before every merge.

| Component | Owner | Main PRs | Reviewers |
| --- | --- | --- | --- |
| Telnet client that refuses every option; SEL-751 parsers for `ID`, `SER`, `SHO P 1`; the C2 session dialogue `sel751.Run`; register revision 3 | A2 | #75, #85, #99, #111, #114, #122, #133, #137 | A6, A3 |
| Collector: C7 IPC over a named pipe or Unix socket, credential store and sealing, durable state (`collector_seq`, the failed-auth floor), run pipeline, binary and Windows service with T-5 hardening, asset suspensions, the hosted SEL-751 adapter | A3 | #79, #82, #90, #97, #106, #112, #117, #121, #124, #125, #131 | A6, A2, A5 |
| SER normalizer with read alignment (C2 result to C4 events); C6 forwarder over RELP/TLS with durable acknowledgement | A4 | #78, #81, #89, #94, #103 | A6, A2, A3, A5 |
| SQLite C5 store; node configuration and runtime; collection scheduler; read-only CLI (`otsec health`); both services under the SCM and the installer; forwarder wiring; suspension handling and adoption; shared admin folder; runtime pruning | A5 | #77, #84, #92, #98, #102, #107, #108, #109, #116, #119, #120, #126, #127, #129, #135, #136 | A6, A3, A4 |
| Slice harness, RELP receiver oracle, rsyslog leg, reconciliation, end-to-end suites, installer and safety checks | A6 | #76, #104, #118, #128, #132 | A1, and the owners of what each test covers |

Contract changes in Phase 2, each approved by A1 and reviewed by the affected owners:

| Contract | Version | What changed |
| --- | --- | --- |
| C2 | `otsec.adapter/0.4` | 0.2: `failed.unexpected_password_prompt` and the probe QUI exemption (D2-14). 0.3: `failed.identity_unreadable`, which suspends nothing (D2-17). 0.4: the unanswered language probe, which suspends nothing (D2-19). |
| C6 | `otsec.syslog/0.2` | RELP/TLS peer check by name, and the durable-write acknowledgement (D2-9). |
| C7 | `otsec.authz/0.3` | 0.2: `asset.clear_suspension` (D2-15). 0.3: `asset_suspended`, naming the suspension the collector holds (D2-18). |
| C8 | `otsec.audit/0.2` | Node-state actions for a collector reset and asset suspensions (D2-15). |

C1, C3, C4 and C5 are unchanged at 0.1. C3's SEL-751 content is at revision 3. Decisions D2-1 to D2-21 are in `docs/phase2/A1-decisions.md`.

## Independently verified

A6's status table, "Phase 2 slice status" in `docs/verification.md`, is the record. It gives each V-S criterion with its evidence class, the tests that show it, and what is still open. A6 wrote every end-to-end test from its own transcription of the manual, never from the owners' test data.

### End to end on the real binaries (`tests/integration/slice/`, Linux)

The four processes are the simulator, `otsec-collector`, `otsec node` and the RELP receiver over mutual TLS. Each suite also runs `check.py` over the simulator's recording.

| Check | Result at `MAIN-COMMIT` |
| --- | --- |
| **V-S6** recovery from interruption | **Pass.** 100 seeded interruptions (receiver and node SIGKILLed, half mid-burst; simulator and collector killed between sessions) against a buffer that grows and renumbers every row. All 240 rows reached the receiver under exactly one event ID each, and every resent ID carried the same bytes. At most 5 events were resent after any of the 53 upstream breaks, against the RELP window of 128. |
| **V-S7** no write to the device | **Pass.** Every line every simulator received, across all recordings, is a read-only register line, with no non-printable and no before-prompt line. The register passes A6's deny corpus. |
| **V-S9** store full | **Pass.** The warning comes before runs stop. No session opens while the store is full, including after a SIGKILL and restart. Once the receiver is back, confirmed events are pruned and runs resume in 113 s with no operator, and all 308 rows arrive once. The same test fails on main before #135. |
| **V-S12** failures are observable | **Pass.** Unreachable, auth failure, timeout, hang mid-SER, malformed row, upstream down and store full each show in `otsec health` as a code or alarm that names it, and none reads `ok`. A late device and a hung SER now differ by their detail (#136, #137). Upstream down took 77 s, inside D2-21. |
| **V-S4** duplicates and gaps | **Pass**, with D2-21's reading of the ambiguous overlap. |
| **V-S3** time | **Pass.** No offset is invented, and native time text is kept through a fall-back hour. SEL-751 documents no unsynchronized flag, so that case has nothing to test. |
| **V-S13** session safety | **Pass.** One session per device, at most one password per session, `QUI` last. A collector killed with Level 1 open leaves the floor behind, and the next runs are refused (D2-20). |
| **V-S1, V-S2, V-S5, V-S10, V-S11, V-S16, V-S17, V-S19** | Pass at the level A6's table states, mostly end to end on one documented example. Each row names what is still owed. |
| **V-S8, V-S15** | Pass in part. The end-to-end hash check (V-S8) and the hostile framing cases end to end (V-S15) are not run. |
| **V-S14** | Not applicable to Telnet beyond detection, which passes. |
| **V-S18, V-S20** | Not run. There is no central role yet, and no OS-support check. |

### Mutation testing

A6 mutated the owners' code for each gate change, and A1 re-ran selected mutants before merging. The counts here are the final ones on each PR:

- #131, the floor held until QUI: 10 of 10 killed.
- #133, the unanswered probe: 7 of 8 killed. The survivor is equivalent, because `await` never returns a prompt together with an error.
- #135, runtime pruning: 15 of 15 killed.

### Where tests ran

- **CI.** `.github/workflows/ci.yml` runs Go on Linux and Windows, pytest, and the `integration` job, which runs the slice suites on Linux with `OTSEC_SLICE_REQUIRED=1`, so a skip fails the job. GitHub Actions has been the main test path since D2-13. Every PR in this report merged with every CI job green on its head. #132 split the three long end-to-end files into an `integration-long` job, one runner per file, so each stays inside its 20-minute limit. The python job leaves the slice directory to the integration jobs. CI now has seven jobs, and the merge rule is that all of them are green.
- **The owner's PC (Windows 11).** This is the second Windows run (D2-13). The elevated pass at `c486e42` used `OTSEC_REQUIRE_ELEVATED=1`, so nothing could skip:
  - `platform/node` passed 65 of 65, including the 27 tests that need elevation;
  - `platform/store/protect` passed;
  - every installer row passed: both services run as virtual accounts with only `SeChangeNotifyPrivilege`, the WER exclusion is in place, the node service ran for 90 s on 127.0.0.1, and uninstall left a clean result;
  - the non-admin half passed 13 of 13.

  #129 ran non-elevated at `8a062d4`. It skipped the elevated test and left nothing behind.
- **A1's container (Linux).** Before each merge, A1 ran `go vet`, `gofmt`, the Windows cross-vet, `go test -race ./...` and the D2-1 dependency check, all on the PR merged with `main`.

## Exit-gate items

| Gate item (`docs/agent-handoffs.md`, "Phase 2 exit gate") | State |
| --- | --- |
| The slice suite passes on the owner's PC (Windows) and on Linux, rsyslog included, from one commit on `main` | **Met on Linux, with a condition on Windows.** The Linux suites, rsyslog included, pass at `MAIN-COMMIT`. The end-to-end suites cannot run on Windows as interactive processes, for three reasons: the collector requires the installer's WER exclusion, the harness uses a Unix socket and the Unix user ID, and the admin folder admits only the service SIDs (A6). The Windows evidence is the Go units and the elevated installer run at `c486e42`. **Condition:** the slice run against the installed services on the owner's PC, proposed as the first Phase 3 task (D2-21). |
| Every component is merged, with its reviewers' records | Met. Table above. The review records are on each PR and in `tests/safety/reviews/`. |
| No safety or security objection is open | Met. A3 and A6 accepted every PR listed. The open high risk under D2-11 is tracked below. It is not an objection to the simulated slice, because D2-4 and D2-10 keep every endpoint on the simulator. |
| V-S6, V-S7 and V-S9 pass | Met, `simulated`. See the end-to-end summary above. |
| This report records what is `simulated` and what needs a lab relay | Met. See "Unverified assumptions" and A6's table. |

**Conditions carried into Phase 3:**

- the Windows slice run against the installed services (gate item 1);
- the D2-11 admin-signed C7 requests, the C1 endpoint path field and the port-server rule (D2-16), and A3's §9 key store (D2-12), all before any `device-observed` endpoint;
- the Phase 1 conditions still open: the pinned-key enrollment rule (before any SSH family) and replacing PEN 32473 (before production).

## Owner decisions needed

1. **Accept Phase 2 with the conditions above, and choose what comes next.** A proposed Phase 3 list is under "Next coordinated tasks". Nothing in it contacts a device.
2. **Plaintext Syslog outside the lab** (carried from Phase 1, decision 1). It does not block anything simulated.
3. **A lab relay.** Every hardware check (H-01 to H-15) and every claim of support waits on an owner-authorized lab SEL-751. Until then the slice can be accepted only as `simulated`. This needs no decision now. It is listed so the dependency stays visible.

## Failed or incomplete

- **The Windows end-to-end run.** The slice ran end to end on Linux only (gate condition 1, D2-21).
- **Not covered on Windows:**
  - the installer's `config\admin` folder;
  - the collector tests that need the installed service accounts;
  - `TestHarden` on the site image;
  - the content of a crash dump.
- **Not run:**
  - V-S8 end to end: each stored event's raw hash against the recording, including after a forced parser failure;
  - V-S15's hostile framing cases end to end;
  - V-S7's 24-hour soak and its byte-for-byte transcript comparison;
  - V-S18 (central) and V-S20 (OS support).
- **V-S2 end to end** covers one documented SER example. The criterion asks for three, from two sections.
- **A database that fails at open stays failed until the node restarts.** C5 says `ModeFailed` needs a restart. Main's store-full run at `9c50395` showed the cost: after a crash, the node's open met `otsec health`'s open during WAL recovery and failed with `SQLITE_BUSY_RECOVERY`, so every run stopped until the next restart. #138 removes that cause by setting `busy_timeout` before any statement that reads the file. A bounded retry of a transient open failure is proposed for Phase 3 (A5), and health shows the failed database meanwhile.
- **The floor's full 31 minutes** were not run end to end, because that is too long for CI. The tests show the refusals inside the floor.
- **Hardware.** H-01 to H-15 are written and were not run, as the owner directed.

## Unverified assumptions

Everything below rests on the SEL-751 manual (S22, date code 20260910), the simulator, or both. Tests built from the same manual share its errors.

- **The QUI reply and framing.** The probe grammar, the prompt's position relative to `ETX`, and the `SHO P 1` layout are assumed until a capture exists (H-13). What a Spanish port replies is H-12.
- **Level 1 after a dropped connection.** D2-20 holds the floor until QUI, because the relay may keep Level 1 until `TIDLE`. Whether it does is H-15 (b).
- **A pending password across connections** (H-15 (a)), and the `TIDLE` of a port-server path (D2-16, H-13).
- **Identity.** The FID ground truth exists only on a device (H-01).
- **The SER buffer under overrun and after a clear** (H-07), and timestamps across time-source loss and DST (H-10).
- **Device load and limits**: the session limit, lockout and CPU load at the poll rate (H-03 to H-05).
- **V-S7 (b) on hardware**: settings and the SER buffer unchanged after 24 h (H-08).
- **The site platform.** The PC run was a Windows 11 desktop, not the LTSC site image (H-14).

## Architectural decisions

D2-1 to D2-21 are in `docs/phase2/A1-decisions.md`. These matter most for later phases:

- **D2-1:** two binaries. Only the collector holds credentials or device transports, and A6's test enforces the import rule.
- **D2-4 and D2-10:** three locks keep every endpoint on the simulator: the `device-observed` refusal, the D1-24 label, and loopback-only addresses.
- **D2-9:** the RELP/TLS peer is checked by name, not by CA alone.
- **D2-11:** the credential install path is an oracle for a compromised node. Admin-signed requests are required before any device.
- **D2-15:** a `collector_seq` reset holds collection until an administrator acknowledges it. The node keeps asset suspensions, and only an exact-match administrator file clears them, on both sides.
- **D2-16, D2-20:** the failed-auth floor starts at `ACC` and now holds until QUI, which amends D1-20. A relay's `TIDLE` may shorten the floor only on a direct Ethernet path.
- **D2-17, D2-19:** an unreadable reply or a silent link suspends nothing. A reply that was read and is wrong still suspends.
- **D2-18:** the collector names the suspension it holds, and the node adopts it, so both sides agree after a crash.
- **D2-21:** the Phase 2 gate rulings, covering V-S12's upstream-down timing, V-S4's ambiguous overlap and the Windows gate condition.

## Open risks

- **No hardware (B-01).** No SEL family may be called supported.
- **D2-11 (open, high).** A compromised node can test guesses against stored secrets at the install budget's rate. The cure is admin-signed C7 requests. The design exists, as the C7 0.4 candidate, and is not merged. This blocks any `device-observed` endpoint.
- **D2-12.** The TLS key is a file and is stored unencrypted. This is lab-only until A3's §9 key store lands.
- **D2-16.** A port-server path has no safe floor until the port's `T_OUT` is known.
- **Quarantines are kept for good.** Repeated quarantines can fill `adapter-evidence`. Runs then stop, after a warning, until an operator acts. Phase 2 has no audited way to export or remove a quarantine, or to clear a halted asset.
- **Rollback across versions.** Two rollback cases fail closed, and the first release must tell operators about both:
  - a collector built before #131 refuses a state file that holds `level_open`;
  - a node or collector at C2 0.3 quarantines a run with `language_probe: "unanswered"`.
- **Carried from Phase 1:** residual SER loss with repeated keys (D1-17), plaintext Telnet to the relay (lab only, ADR-0005), PEN 32473, and the 31-minute floor on a flaky link.

## Where the eight capabilities stand

The owner asked where each requested capability lands. Nothing has been dropped. Phase 2 built one workflow on purpose, as the brief directs.

| Capability (brief §1) | Phase 2 | Planned |
| --- | --- | --- |
| 1.1 Asset management and monitoring | One asset, identified by FID, with suspension, health and last result. No inventory or discovery. | Phase 4, with each new SEL family. |
| 1.2 Secure engineering and remote access | Not built. The threat model and the Q1 comparison are in Phase 0. | Phase 4, item 3. |
| 1.3 Configuration and baseline monitoring | Not built. `SHO P 1` is read for posture only. | Phase 4, item 1. |
| 1.4 Syslog and SER collection | SER retrieval, normalization, evidence and RELP/TLS forwarding, end to end. Receiving device Syslog is designed (C1 listeners, C4, C6) and not built. | Receiving: proposed for Phase 4 beside item 1, as the vendor-neutral path of ADR-0006. |
| 1.5 Custom IED command framework | The C2 adapter, the signed C3 register, the read-only egress check and the hosted SEL-751 adapter. | Each new family extends it. |
| 1.6 Intrusion detection and anomaly detection | Not built. Zeek and Suricata are evaluated in Phase 0. | Phase 4, item 4. |
| 1.7 Modular and additive architecture | Contracts C1 to C8 (Phase 1), two binaries, D2-1's import rule enforced by test. | Done for the slice. |
| 1.8 Centralized and distributed deployment | Single-site node only, under the SCM. No central role (V-S18). | Phase 4, item 5. |

The Phase 4 order is the brief's recommendation. The owner may reorder it, for example to bring IDS or asset inventory forward.

## Next coordinated tasks (proposed; the owner decides)

1. **The Windows slice against the installed services** (A5 and A6, on the owner's PC with the owner's UAC approval). Closes gate condition 1.
2. **Admin-signed C7 requests** (A3, C7 0.4), with **the C1 endpoint path field and the port-server rule** (A2, D2-16). Both are needed before any `device-observed` endpoint.
3. **A3's §9 node key store** (A3 with A5). Replaces the D2-12 file resolver.
4. **An audited quarantine export and a way to clear a halted asset** (A5 with A3).
5. **V-S8 end to end**: every stored event's raw hash checked against the recording (A6).
6. **A bounded retry of a transient open failure** (A5, C5 amendment; A6 contract tests, A3 review; brief in `docs/phase2/A5-p3-failed-open-retry.md`): `Resume` from `ModeFailed` only for `store-open-failed` with a busy or locked cause, at most once per tick, with the suspension rebuild before any run and a `store.mode_change` on recovery. Integrity, format and settings failures stay terminal.
7. **Then Phase 4's first expansion**, in the order the brief recommends, starting with configuration and baseline monitoring, re-ranked by measured risk.

A lab relay, if the owner authorizes one, would let A6 run the H checks and move items from `simulated` to `hardware-verified`.

## Owner sign-off

Pending.
