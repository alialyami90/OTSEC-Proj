# Phase 3 exit report

Owner: A1. Date: 2026-10-27. Status: **draft. The gate is not decided: gate item 1, the slice against the installed services on the owner's PC, has not run.**

This report closes Phase 3: hardening the simulated SEL-751 slice so that a `device-observed` endpoint can later be allowed, and starting the owner's monitoring goals (ADR-0008) at their first rung. It follows the milestone format in `CLAUDE.md` §9 and mirrors `docs/phase-2-exit.md`. No device was contacted. Every result is `desk` (Go and Python tests on a CI runner or A1's container), `simulated` (the real binaries against A6's recording simulator), or from the GitHub-hosted Windows runner where that is stated. No result is `hardware-verified` (B-01). H-01 to H-15 are written and were not run, as the owner directed.

## Milestone

**Phase 3: a hardened slice and the first monitoring rungs.** The objectives, from the Phase 3 briefs in `docs/agent-handoffs.md`:

- close the Phase 2 conditions: the Windows run against the installed services, admin-signed C7 requests (D2-11), the C1 endpoint path field (D2-16), the `DATE_F` read, and the node key store (D2-12);
- give operators an audited way out of a full quarantine, and let a busy database open recover without a restart;
- show V-S8 (raw evidence preserved) end to end;
- receive device Syslog, the first event rung of ADR-0008 and the vendor-neutral path of ADR-0006;
- record which collection rung each SEL family reaches, and write the acceptance criteria for every requirement ADR-0008 added before any of them is built.

## Implemented (on `main`)

| Component | Owner | Main PRs | Reviewers |
| --- | --- | --- | --- |
| C1 endpoint `path` (`direct`, `port-server`); C3 context reads and SEL-751 register revision 4; C2 0.5 `refused.endpoint_path` and `settings`; the SEL-751 adapter 0.2.0 (the path rule, `DATE_F` from `SHO G`, `TIDLE` only after `ok` or `partial`); collection-method rungs for every SEL family and the SEL-751 FTP assessment | A2 | #149, #156, #164, #175, #183 | A6, A3, A4 |
| C7 0.4 and 0.5 admin-signed requests and the collector's verifier (nonce spent durably, clock high-water mark, repeat answer); C8 0.3 and 0.4; the collector's path check; the node key register and non-exportable CNG key store; the pipe peer grant under the SCM (D3-9); the install-key lock; the CNG pointer fix | A3 | #146, #153, #155, #157, #160, #180, #184, #186, #187, #190, #193, #201 | A6, A2, A5 |
| Syslog receive (RFC 5425 TLS by default, RFC 6587 TCP and RFC 5426 UDP per listener, D3-5) with raw bytes stored before parsing, sender correlation, unknown-sender budget and per-source limits; C4 0.2 and C6 0.3 sender TLS leaf; the RTAC size fix; unknown-sender spend charged as read (#178's defect); the SER normalizer reading `DATE_F` (D3-11) | A4 | #150, #167, #170, #174, #178, #196, #203 | A6, A3, A2, A5 |
| C5 0.2 busy-open retry and 0.3 `Discarder`; the node's busy retry; quarantine export and audited clear; listener wiring and sizing; the node relay of signed credential requests (PR 1 of #181) and its limits; the node's unknown-budget count across restarts; the relay stall test | A5 | #145, #147, #151, #152, #154, #163, #169, #189, #197, #198, #202 | A6, A3, A4 |
| V-M1 to V-M8 criteria; the `SHO G` simulator switch; V-S8 end to end; independent tests for every Phase 3 PR; property-based waits for slow runners; the relay end-to-end check; the unknown-budget restart check on the real binaries; the `uintptr` AST rule | A6 | #142, #144, #158, #166, #172, #188, #191, #194, #195, #199 | A1, and the owners of what each test covers |
| ADR-0008, Phase 3 briefs, D3-1 to D3-11, HR-11 and HR-12, Go 1.26.10 | A1 (A3 for the threat model) | #143, #148, #161, #162, #165, #168, #171, #192, #200 | A3, A6 and affected owners |

#179 (A5, the harness's Windows service mode, which gate item 1 runs on) merged as `ccb94b2`. **Not merged at this draft:** #204 (A5's handoff) and #206 (A6's gate table). Open A5 PRs deferred until after the gate, because none is on the gate path: #176 (the node reading its TLS keys from the key store), #177, #181 (the signed-files design, whose PR 1 became #189) and #182 (the refused-identity detail and the record-bound comment). Relay PR 2 of #181 (signed `clear-*` files and A5's N1/N3 items) is not started.

Contract versions on `main`:

| Contract | Phase 2 exit | Now | What Phase 3 added |
| --- | --- | --- | --- |
| C1 | `otsec.asset/0.1` | `0.2` | `Endpoint.path`; only `direct` gets a session; a 0.1 endpoint is refused until an administrator sets the path (D2-16). |
| C2 | `otsec.adapter/0.4` | `0.5` | `refused.endpoint_path`; `Result.settings` carrying `DATE_F`. |
| C3 | `otsec.register/0.1` | `0.2` | Context reads (D3-2); the envelope accepts every readable minor (D3-4). SEL-751 content revision 4 (`SHO G`). |
| C4 | `otsec.event/0.1` | `0.2` | `source.sender.tls_leaf_sha256`: which credential spoke, never asset identity. |
| C5 | `otsec.store/0.1` | `0.3` | `open-busy`, the one open failure `Resume` retries; `Discarder` (D3-1). |
| C6 | `otsec.syslog/0.2` | `0.3` | `tlsleaf`. |
| C7 | `otsec.authz/0.3` | `0.5` | Admin-signed requests and `admin_unverified` (D2-11); admin-signed node kinds, `repeat_of`, `AdminAcceptance`. |
| C8 | `otsec.audit/0.2` | `0.4` | `quarantine.exported`, `quarantine.cleared` (D3-3); claimed and verified admin groups, `repeat_of`. |

Every change bumped the minor, kept a reader for the previous version, and had A6's independent contract tests before merge.

## Independently verified

A6's "Phase 3 status" table in `docs/verification.md` and `docs/phase3/A6-handoff.md` are the record. A6 wrote each test from the rule text, mutated the code under test, and posted a PASS or FAIL on the PR. Two first verdicts were FAIL and were fixed before merge: #153 accepted a replay after the clock went forward and back (fixed with a clock high-water mark), and #175 read `TIDLE` outside `SHO P 1`.

| Check | Result |
| --- | --- |
| **V-S8** raw evidence end to end | **Pass**, `simulated`. `test_slice_evidence_e2e.py` checks every stored capture, record and forwarded message against the bytes the simulator's recording says it sent, including a report whose row 5 is damaged so it does not parse. The oracle is the recording, not the product's parser. |
| **Received Syslog** end to end | **Pass**, `simulated`. `test_slice_syslog_receive_e2e.py` and `tests/integration/syslogreceive/`: raw bytes stored and hash-matched; hostile framing never crashes, hangs or loses an earlier message; a flood from one source does not displace another; a wrong TLS anchor is refused; an unknown sender is kept and alarmed. The unknown budget holds across SIGKILL restarts on the real binaries (`test_slice_unknown_restart_e2e.py`, #199). |
| **C7 admin-signed requests** (D2-11) | **Pass.** 24 of 24 mutants killed on the contract (#146); replay after a restart and after a clock step is refused (#153); the C7 0.5 repeat answer: 23 of 23 mutants killed (#184). The node relay (#189): A6's independent end-to-end check, 18 of 18 against main, with the collector's own decision log as the oracle. |
| **C1 path and the collector's path check** | **Pass.** 10 of 10 and 2 of 2 mutants killed. A `port-server` or path-less endpoint gets no session. |
| **`DATE_F`** | **Pass**, `simulated`. 10 of 10 `dateOrder` mutants killed under D3-11. Ambiguous dates (day 12 or less) read correctly in MDY, DMY and YMD in A6's ad hoc check. The slice's stored events no longer carry `date-format-assumed:MDY` (0 of 8). **Not run:** the full slice reconcile against a simulator set to DMY and YMD (A2 and A6). |
| **Quarantine export and clear; busy-open retry** | **Pass.** 8 of 8 mutants killed on the clear (#163); 15 of 17 on the retry contract (the 2 survivors fail closed); the busy-open slice runs in `integration-long`. |
| **Node key store** (§9) | **Pass on the hosted Windows runner**, Software KSP only: D3-7's claims (a) to (c). The TPM provider is untested (T-2). Not yet used by the node (#176). |
| **Pipe identity under the SCM** (D3-9) | **Pass on the hosted Windows runner**: two virtual-account services; the wrong-SID node is refused; only the two query rights are granted. |
| **Capability-matrix rungs** | **Pass**: 12 of 12 cells A6 checked match their citations (#183). |

### Defects found by independent tests in Phase 3

- **The unknown budget over-granted across a restart** (#178). A6's property test failed on Windows only: the spend was taken in the writer while the restart count went by received time, so on a slow store a record read before the window and committed inside it fell out of the count. A4 fixed it in #196 by charging an unknown sender as it is read; A5's #198 made the node pass the count, failing closed if it cannot read the stream. Unit tests had passed throughout.
- **Memory corruption in the UDP receive path on Windows** (D3-10). Two panics with the signature of a corrupted string header (`1<<36`, the size of `sockaddr_in`, in a field nothing writes). A6's stress runs: Go 1.26.0 crashed 2 of 42; Go 1.26.10 crashed 0 of 41; 1.26.0 under `-race` crashed 0 of 23 and found no race. The likely cause is golang/go#78041, fixed in 1.26.2. **The cause is inferred, not proven**: about 62 clean runs would be needed to exclude the 1.26.0 rate at 95 percent. The move to 1.26.10 also stands on its standard-library security fixes.
- **Stack pointers handed to CNG** in `modules/security/nodekey` (#201). The syscall wrapper lacked `//go:uintptrescapes`, so buffers could move during the call. Found when A6's Windows test read a corrupt public key. The module was never linked into `cmd/otsec`. A6's AST rule now flags the pattern in every package (#199).
- **A pre-existing data race** in `CredStore.InstallKey` (#190).

### Where tests ran

- **CI** is the main test path (D2-13). It now has **ten jobs**: Go on Linux and Windows, pytest, `integration`, and six `integration-long` legs (including `busy_open`, `admin_relay` and `unknown_restart`). Every Phase 3 PR merged with every job green on its head, checked by A1 at each merge, with one exception: #197 merged on CI from a base older than three later merges, and main's Windows job went red until #202 (see "Lessons").
- **The owner's PC** was not used in Phase 3. The installed-services run (gate item 1) is the one planned use.
- **A1's container (Linux).** Before merges where CI predated main, A1 ran `go vet` (Linux and `GOOS=windows`), `gofmt`, the affected package tests with `-race`, and the affected end-to-end suites on the PR merged with `main`.

## Exit-gate items

| Gate item (`docs/agent-handoffs.md`, "Phase 3 exit gate") | State |
| --- | --- |
| The slice passes against the installed Windows services on the owner's PC from one commit on `main` | **Not met.** The harness's service mode (#179) has run on the hosted Windows runner, elevated, against the real installer: in run svcdry6 every service-mode test passed with nothing left behind; its other errors came from the admin-relay leg's platform check, which #199 fixed. The rerun on #179's merged head (f0d6e31, Go 1.26.10) is svcdry7. #179 is merged (`ccb94b2`); A6 passed it on run 40464065233 (159 passed, the 27 stated Windows skips, nothing left behind). The owner's run needs the owner's choice of how the PC gets Go 1.26.10, and the owner's own elevated session. |
| C7 0.4, the C1 path field, the `DATE_F` read and the key store merged with reviewers' records, and A6's negative tests pass in CI | **Met, with one condition.** The key store is merged and tested, but the node does not read its TLS keys from it yet (#176); the D2-12 file resolver stays behind its lab flag until then. |
| The quarantine export and clear, and the failed-open retry, merged and tested | **Met.** |
| V-S8 passes end to end, and received Syslog passes A6's tests end to end on the real binaries | **Met**, `simulated`. |
| The capability matrix states each SEL family's rung with citations, and `docs/verification.md` has criteria for every ADR-0008 requirement | **Met.** #183 and V-M1 to V-M8 (#144). |
| No safety or security objection is open, and this report records what remains `simulated` | **Met** for objections: A3 and A6 have none open. A3's conditions before any `device-observed` endpoint or listener are listed under "Open risks"; they are conditions, not objections to the simulated slice. |

## Owner decisions needed

1. **How the PC gets Go 1.26.10** (the decision card in the thread). A1 recommends replacing the portable Go folder inside OTSEC with the official 1.26.10 archive, checked against its published SHA-256.
2. **A session for the installed-services run** (gate item 1), in the owner's own elevated shell, with the owner present.
3. **Accept Phase 3**, with the conditions listed here, and confirm the Phase 4 order (ADR-0008).

## Failed or incomplete

- **Gate item 1** (above).
- **No end-to-end Windows check of the admin relay or of `config\admin`'s ACLs.** The relay suite needs SIGSTOP and POSIX modes and is skipped on Windows; only the C7 contract tests run there. This is owed.
- **Signed `clear-*` files** (relay PR 2 of #181) are not built, so the clear-suspension and clear-quarantine files are still unsigned administrator files under D2-15's folder rule.
- **The full DMY and YMD slice reconcile** has not run (A2 and A6).
- **Not run, carried from Phase 2:** V-S7's 24-hour soak, (c) and (d); V-S6's link cut in the middle of a SER read; V-S9's file-system exhaustion; V-S15's hostile framing end to end on the SER path; V-S18 and V-S20.
- **A5's Phase 3 handoff** is open as #204.

## Unverified assumptions

Everything in the Phase 2 list still stands. Phase 3 adds:

- **The `SHO G` layout** is `documented-untested`. S22 prints no `SHO G` reply, and the date order it states is for command responses, not SER rows.
- **The SEL-751 FTP rung.** What a Level 1 FTP credential can write is unknown. No FTP rung is granted until hardware test Q3, which needs the owner's authorization and an out-of-service lab relay. A3's D7 and D8 objection stands until then.
- **Per-family Syslog layouts** rest on documented examples (RTAC, SEL-2730M, SEL-2488). No device has sent to the platform.
- **The Windows UDP corruption's cause** (D3-10, above).
- **The node key store's TPM provider** (T-2).

## Architectural decisions

D3-1 to D3-11 are in `docs/phase3/A1-decisions.md`. These matter most for later phases:

- **D3-3 and HR-11:** before any `device-observed` Syslog listener, unknown-sender storage needs an absolute bound (its own C5 stream and quota), not only the per-window budget.
- **D3-5 (owner decision):** plaintext Syslog receive is allowed, enabled per listener. TLS is the default; a plaintext listener is shown in health, and plaintext never raises binding confidence (HR-12).
- **D3-7:** a node key's boundary is non-export plus every account other than Administrators and the service.
- **D3-8:** a collector run's relayed audit records follow its decision record in the chain.
- **D3-9:** the collector grants its node two query rights, and the node keeps checking the server's token.
- **D3-10 and A3's standing rule:** build with the latest patch of a supported Go minor; pin `govulncheck` in CI on every PR and weekly; toolchain and dependency bumps reviewed by A3 and A6 and never auto-merged.
- **D3-11:** a C2 0.5 result with no `DATE_F` keeps the pre-0.5 date rule, because refusing it would stop collection while the relay's SER buffer overwrites.

## Open risks

- **No hardware (B-01).** No SEL family may be called supported.
- **HR-11 (open).** Unknown senders' storage is bounded per window and, since #196 and #198, across restarts, but not absolutely. A forward wall-clock step followed by a restart refills the budget. This gates the first `device-observed` listener.
- **HR-12.** A spoofed known address on a plaintext listener spends no unknown budget.
- **D2-12** until #176: the node's TLS key is still a file.
- **D2-16.** A port-server path stays refused until `T_OUT` evidence exists (H-13).
- **UDP loss.** The OS can drop a well-behaved sender's datagram before it is read, and that loss is not counted (RFC 5426). Use TCP or TLS where loss matters.
- **A repeat that names a lost first decision** can only be cross-checked against the collector's own log.
- **Rollback across versions.** In addition to Phase 2's two cases, every contract at a new minor in Phase 3 needs the release note its rollback requires.
- **Collector state replace on Windows.** Any process reading `state.json` can make the collector's replace fail, and the collector then refuses every run until a restart (see the limitation below). This fails closed, but it is an availability risk at a site with antivirus or indexing, and it is a condition before the first site deployment.
- **Carried:** residual SER loss with repeated keys (D1-17), plaintext Telnet to the relay (lab only, ADR-0005), PEN 32473, the 31-minute floor on a flaky link.

## Limitations recorded in Phase 3

- `otsec health` shows a relay refusal by code only; the relay checkpoint lags the decision records (shown safe by A6's end-to-end step 3).
- Listener health counts trail forwarded data by up to the 10 s forwarding check.
- The unknown-budget count covers what is stored, not records already pruned or forwarded. Counting it at start is a scan; its cost at quota is not measured.
- About one record per handoff can slip in the ε-plus-resolution window of the unknown budget.
- A refused quarantine manifest or clear file is re-verified every tick.
- The collector clears its failed-auth floor about 10 ms after `QUI`; a kill in that gap leaves the floor in place, which fails safe.
- **A collector state write that fails stops collection until a restart.** If another process holds `state.json` open without delete sharing (an antivirus scanner, a backup agent, or the harness before #179's fix), the collector's rename fails, its state breaks for good, and every run is refused with `collector_state_unavailable`: no sequence number is reused and no `ACC` is sent. This fails closed and shows in health and the audit chain, but needs a manual restart. If the break comes after `ACC`, the floor on disk runs from `ACC`, not the session's end, so after a restart it could end up to one session length early (A3). The existing tests force the failure at the temporary file, not at the rename; A3's Windows test that holds the file open (#205) pins this behaviour. A5's race check on the hosted Windows runner shows how likely this is: with a reader looping beside it, the collector's `MoveFileEx` replace failed 1556 of 3000 times even though the reader shared delete, against 0 of 3000 with a POSIX-semantics rename. So any reader of the file (antivirus, an indexer, a backup agent) can stop collection. Fixing it is a Phase 4 item and a condition before the first site deployment: a POSIX rename (`FileRenameInfoEx`) with the fail-closed path kept as the fallback, not a retry alone (A6, A3).

## Lessons

- **Independent property tests found real defects that unit tests missed** (#178's restart count, the CNG pointers), and Windows CI repeated them.
- **Evidence hygiene.** A6 found that two items of its own #189 check had run on a tree without later fixes, struck them through and re-ran them. Corrections stay visible.
- **Wall-clock assumptions fail on loaded runners.** Four syslogreceive tests and the relay stall test assumed timings; they now check properties (progress, bounds from `ctx.Deadline()`).
- **Merging on stale CI.** When a PR's CI predates newer `main`, its Windows leg must run against the merged result before merge. A Linux-only local check was not enough for #197.
- **Syscall pointer liveness.** Every Windows syscall wrapper that takes `...uintptr` needs `//go:uintptrescapes`, with the conversion inside the call expression. A6's AST rule enforces it.

## Where the eight capabilities stand

| Capability (brief §1) | Phase 3 | Planned |
| --- | --- | --- |
| 1.1 Asset management and monitoring | Received Syslog correlates senders to C1 assets and keeps unknown senders. The rung each SEL family offers for identity is recorded. No inventory or SNMPv3 identity. | Phase 4, item 3 (R1.8, with R9). |
| 1.2 Secure engineering and remote access | Not built. Admin-signed requests are the first independently authenticated path. | Phase 4, item 5. |
| 1.3 Configuration and baseline monitoring | Not built. Rungs recorded; the SEL-751's rung waits on the FTP assessment and Q3. | Phase 4, item 1. |
| 1.4 Syslog and SER collection | SER with the relay's date order; device Syslog received, stored raw, normalized, correlated and forwarded, end to end on the real binaries. | Event-behaviour baseline: Phase 4, item 2. |
| 1.5 Custom IED command framework | C3 context reads; the path rule; the SEL-751 adapter at 0.2.0. | Each new family extends it. |
| 1.6 Intrusion detection | Not built. Criteria V-M6 written. | Phase 4, item 4. |
| 1.7 Modular and additive architecture | Every contract change was additive, with readers for earlier minors. | — |
| 1.8 Centralized and distributed deployment | Single-site node only. | Phase 4, item 6. |

## Next coordinated tasks

1. **Gate item 1**: the owner's run on the PC (A5 and A6, the owner present).
2. **After the gate**: #176 (key store in the node), #177, and relay PR 2 of #181 (signed `clear-*`, N1/N3).
3. **Phase 4**, briefed in `docs/agent-handoffs.md` in ADR-0008's order: configuration retrieval, baseline and prior approval; the event-behaviour baseline; vulnerability applicability with SNMPv3 identity; IDS; secure engineering access; the central role. The hygiene items from Phase 3 (HR-11's absolute bound, `govulncheck` in CI, `runtime.Version()` in status, a configurable UDP receive buffer, a sound faster unknown count) go into the first briefs they touch.

## Owner sign-off

Not yet given.
