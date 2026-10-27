# Phase 3 decisions (A1)

Decisions A1 made during Phase 3, numbered D3-n. Phase 2's are in `docs/phase2/A1-decisions.md`; the gate rulings that opened Phase 3 are D2-21 and ADR-0008.

## D3-1: C5 0.3 `Discarder.Discard` for the audited quarantine clear (P3-A5)

Date: 2026-10-26. Design: `docs/phase3/A5-quarantine-export.md` (A5; A3 agreed to the authorization with conditions A3-1 to A3-5).

**Approved**, as a C5 minor (0.3), with these conditions on the contract:

1. **Static scope.** `Discard` refuses any stream whose name is not under the quarantine prefix, as well as any stream that has a consumer. "No consumer" is a runtime state (a consumer can be unregistered at the moment of the call); the prefix is the property the contract can promise. Confirmed events are never within its reach.
2. **Captures.** A capture is removed only when no retained record of any stream refers to it, the rule `PruneStep` already states.
3. **Bounded steps, after the measurement.** The design asked for one transaction at `SyncFull`, because A3-2 refuses a retry once any listed seq is gone. E-A5-3 applies, so A5 measured the WAL a single-transaction delete writes (autocheckpoint off, simulated): 32 captures of 1 MiB wrote 128 KB (freed overflow pages are not journaled); 20,000 small events wrote 9.8 MB, 140% of the class bytes; 20,000 events with 1 KiB captures wrote 19.7 MB, 72%. The cost scales with rows, not bytes, and many small quarantines need a WAL about the size of the quota, far beyond the reserve. One transaction is therefore **refused**, and the bounded form is approved: `Discard` takes at most `DiscardStepEvents` seqs per call (50 was the first figure; A5's measurement on #151 fixed it at 16: 16 seqs spread across a 40,000-event stream wrote 387 KB of WAL against the 512 KiB bound, 50 wrote 997 KB), refuses more, removes in one `SyncFull` transaction those still stored, and skips a seq already gone without counting it, so a retry completes. A3-2 stays whole on the node's side: every listed seq is checked present and hash-equal before `quarantine.cleared` is written; the record names the stream's contiguous seq range; the node then discards in steps. If the node stops partway, the chain record is the authority: before each run the node finishes any recorded clear whose range still holds events, raising `quarantine-clear-incomplete` meanwhile, and a re-applied file still changes nothing (A3-4). Nothing above the recorded range is ever touched, so a record added after the export survives. The PR's test shows one 16-event step of the worst shape stays under `WALBoundBytes`. A3 reviews the resume rule.
4. **Result.** `Discard` returns the count removed and the bytes freed, so the `quarantine.cleared` record and `otsec health` can show the effect, and the quarantine-room alarm clears through the existing headroom path, not by a new one.

**Brief amendment.** The P3-A5 brief said the read-only CLI "records `quarantine.exported` in the audit chain". The CLI cannot write the chain, and must not: it opens the store read-only. A5's resolution stands: the CLI leaves its manifest (hashes only) in `config/admin`, and the node verifies the manifest against its own stream under the protected-file rule and writes the record. The two C8 actions are A3's to add. `clear-quarantine.json` is unsigned in this PR and moves to the signed form together with `clear-suspension.json` and the reset acknowledgement under C7 0.4, which is A5's node-side task in Phase 3.

## D3-2: C3 0.2 `Package.context` so a read-only context line can be sent for an operation (P3-A2)

Date: 2026-10-26. Raised by A2: `SHO G` is in register rev 3 as `sel.settings.show_global` (read-only, Level 1, approved 2026-10-23), but C2 `CheckLines` lets an operate line through only as the invocation's own operation or the `read_by` of a precondition, warning or firmware condition. `DATE_F` is not a check (`MDY`, `YMD` and `DMY` are all valid), so `sel.ser.read_all` cannot read it today without bending a precondition's meaning.

**Approved**: C3 0.2 adds `Package.context`, a list of `{id, setting, read_by, for, values, reason}`. `CheckLines` lets `read_by` through only when the invocation's operation is named in `for`. The adapter reports the value in C2 `settings` (name, value, span; C2 0.5). A value outside `values`, or a SER row that does not fit the order, is a parse error, never a skip. Register content rev 4 adds the `DATE_F` entry and corrects its citation to S22 Table 4.84 p. 4.225. The deny corpus is unchanged: `SHO G` with a setting argument stays denied.

Conditions: (1) `read_by` must name an operation of the same package that is read-only and at the same or a lower access level than the operation in `for`; a context line is still a line sent to the device, so it counts against the per-run line and rate limits and appears in the raw capture like any other. (2) A2 drafts the C3 0.2 format change with A1 as approver (A1 owns the format but does not become its implementer); A3 reviews the `CheckLines` change as security-sensitive and A6 re-runs the deny corpus and adds the "context line for an operation not in `for` is denied" case. (3) Order: C1 0.2 (#149), then C3 0.2 with content rev 4, then C2 0.5, then the SEL-751 adapter.

## D3-3: `quarantine.cleared` is written by the node; the file's principal is `requested_by` (amends D3-1)

Date: 2026-10-26. Raised by A3 on #155 (C8 0.3). D3-1 said the record carries the named principal; A3's contract makes the actor the node and puts the file's principal in `quarantine.requested_by`, because an unsigned `clear-quarantine.json` cannot prove who wrote it. That is 0.2's `asset.suspension_clear` rule applied the same way. **Accepted.** The actor becomes the person once the file is a signed admin request (C7 0.4; A5's node-side task in Phase 3).

A3's condition on #150, recorded here: before any device-observed Syslog listener is configured, unknown-sender storage needs an absolute bound (a separate C5 stream and quota), not only the per-window budget. Phase 3 listeners are simulated, so this gates the first production listener, not #150.

## D3-4: the register envelope accepts every minor the reader decodes (C3 0.2, #156)

Date: 2026-10-26. `authz.VerifyRegisterPackage` compared the envelope's `contract` to `register.ContractID` exactly, so after an upgrade to C3 0.2 every 0.1-stamped envelope in a collector configuration would be refused until re-stamped (SC-18). The envelope is a wrapper; what carries security is the signed payload, which names its own contract and is validated by `register.Validate`, and the anti-rollback floor. **Ruling:** the envelope check accepts any contract in `register.Readable`, with a test that a 0.1 envelope around a 0.1 payload still verifies. A3 owns the line and reviews it on #156, or lands it as its own PR before the Phase 3 gate; if A3 shows a security reason for the exact match, the release note stands instead.

## D3-5: plaintext Syslog receive is allowed, enabled per listener (owner decision)

Date: 2026-10-26. The owner answered A1's question on #150 ("Allow plaintext Syslog (UDP/TCP) receive outside the lab, or TLS only?") with **"Allow plaintext, per listener."** Consequences:

- A4's listener (#150) is unchanged: `Config.Plaintext` is the switch for RFC 6587 TCP and RFC 5426 UDP, and TLS (RFC 5425) is the default.
- A5's node configuration (#154) carries the setting per listener. It is never implied by the lab flag alone, a plaintext listener is shown in health and recorded at start, and a configuration with no explicit setting is TLS.
- The reason is evidence: SEL-2488 and SEL-2730M Syslog is documented as UDP (#149), and many fielded devices cannot send TLS. A plaintext listener's messages keep the evidence class the listener is configured with and carry `sender.transport` so an analyst can see they were not authenticated.
- Unchanged: the D2-4/D2-10 loopback lock on collection endpoints until the hardware gate, A3's unknown-sender condition (D3-3) before any device-observed listener, and the binding rule that plaintext never raises binding confidence.

## D3-6: the audit chain must show a restart the busy-open retry made invisible (#147)

Date: 2026-10-26. A6's independent check of the node's busy-open retry (#147) passed on two conditions. Both land in #147, not as follow-ups, because #147 is what makes each path reachable:

1. The only new path that lifts an asset's halt (`reload` after the retry opened `evidence.db`) had no test of the D2-15 control, that an unauthorized-line quarantine keeps the asset halted. A5 adds both halves (stays halted with `collection-disabled`; resumes when no such line exists).
2. When `audit.db` was busy at start, the process's `service.start` and `store.mode_change` records were never written, so the chain shows "audit: failed to collecting" with no record that the node restarted; before #147 a failed audit database kept the node down. When the retry opens `audit.db`, the node writes the unrecorded records with their original times before any run, or, if a chain ordering rule forbids that, one record naming them. The "not recorded" alarm gets its own code instead of `audit-store-full`.

## D3-7: a node key's DACL gives Administrators full control; the boundary is non-export plus every other account (#157)

Date: 2026-10-26. The credential design's section 9 said an administrator may manage and delete a node key but never use it. The CNG tests on the hosted Windows runner (elevated, high integrity) showed the Software Key Storage Provider does not honour that shape. A3's rights probe (#157, run 40382848418) records the rule: the KSP checks every DACL change, delete and open against the DACL in force, and the handle makes no difference. A DACL change needs generic write; write-DAC alone is refused (NTE_PERM), even through the creating handle. Delete by name needs the delete right, and opening by name needs read. With Administrators at `GA`, `GR|GW` or `FA`, an administrator may open, sign, read the DACL, change it again and delete. At `GR` alone, a second change and a delete are refused. At `RC|WD|SD`, open and a second change are refused, and delete is allowed. A3's redesign is **accepted**: `Create` keeps the provider's default DACL, `Request` sets the final DACL once after the certificate request is signed, and that DACL is SYSTEM and Administrators full control plus generic read for the node service. The reasoning: a local administrator can run as SYSTEM anyway, so an ACE that denies Administrators use is a boundary against nobody. Full control includes generic write, so Administrators could also change the DACL to grant themselves use. The property the design claims from now on is that the private key cannot be exported under any blob type by any account, and that no account other than SYSTEM, Administrators and the node service can open or sign with it. Section 9, `doc.go` and the threat model say so in the same PR; A6 tests those three claims. **Not taken:** an Administrators ACE of `RC|WD|SD`, which would let an administrator delete the key without opening it by name. It adds no boundary, because SYSTEM keeps full control and an administrator can run as SYSTEM, and it costs the administrator the ability to read or repair the DACL. Evidence class for the DACL behaviour: the hosted Windows runner, recorded by `TestCNGRightsProbe`, not the owner's PC. (Corrected 2026-10-26, twice, on A3's probe readings. The first wording said a second DACL change is always refused. The second said write-DAC lets Administrators change the DACL, and that `RC|WD|SD` refuses a delete. The probe shows a change needs generic write and `RC|WD|SD` allows a delete.)

## D3-8: a collector run's relayed audit records follow its decision record in the chain and read earlier (C8)

Date: 2026-10-26. A6 found that relayed collector records (`device.session.open` and the rest) carry times about 18 ms before the node's `collector.request` decision record that precedes them in the chain. A5 traced it (`platform/node/schedule.go` `runOnce`; `modules/security/collector/runaudit.go`). Three records are involved:
- The node's info record for the request is stamped when built. It is committed through audit-before-act before the request leaves, so D1-11 holds.
- The collector stamps each relayed record with the host clock as it acts.
- After the reply, the node builds the allowed or denied decision record. It commits that record first, then the relayed records, in one transaction.

Chain order is commit order. C8 promises order by `seq` and the hash chain, never time order across records. **Ruling: no reorder.** The batch stays as it is, and C8's doc says so. A6 adds a check, keyed per collector request: the info and decision records carry the request ID, and the relayed records carry the invocation ID of the run that decision allowed. For each request, the info record comes before the decision in `seq`, and the decision comes before the relayed records. In time, the info record is at or before every relayed record, and those are at or before the decision (`test_slice_busy_open_e2e.py`). This holds because the node and its collector share a host clock, as D2-1 places them. A collector on another host would need a clock-offset rule first.


## D3-9: the collector grants its node two query rights; the node keeps checking the server's token (#180)

Date: 2026-10-26. When the node and the collector run as installed services, each under its own virtual account, every `collectorwire.Dial` failed closed. `checkServer` needs `PROCESS_QUERY_LIMITED_INFORMATION` on the pipe server's process and `TOKEN_QUERY` on its token, and the default DACLs of a service process and its token grant only SYSTEM and the account itself. A5's service-mode dry run found it ([run 40397915060](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40397915060)). **Ruling: accepted as A3 proposed.**

- At startup, before the pipe exists, the collector's `Listen` merges two allow entries for the configured peer (the node's service SID): `PROCESS_QUERY_LIMITED_INFORMATION` on its own process DACL and `TOKEN_QUERY` on its own token's DACL. Nothing else is granted, and every existing entry stays.
- If either grant fails, `Listen` returns an error and the collector does not start.
- W-1's check is unchanged. The server's token must hold the collector's service SID (or the configured `ep.Peer`) as user or enabled group. A process that took the pipe name without that SID, or without having made the grants, is refused.
- What the node gains is the collector's image name, its start and exit times and exit code, and the token's user, groups and privileges. None of these is secret. The node cannot read the collector's memory, duplicate its handles or use its token.
- The token's DACL is not `TokenDefaultDacl`. Objects the collector creates later, such as its store files and pipes, are not opened to the node by this.

**Rejected:** matching `GetNamedPipeServerProcessId` to the SCM's process ID for `otsec-collector`. It trusts a process ID instead of the token, which leaves a PID-reuse window, and it needs the service DACL to grant the node `SERVICE_QUERY_STATUS`.

Evidence: `TestListenGrantsPeerQuery`. A6's independent two-service test passed claims (a) to (d) on the hosted runner (`tests/security/collectorwire_services_windows_test.go`, landing in A6's next PR). A5's service-mode dry run 4 ([run 40405064964](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40405064964)) installed both services, and the node checked the collector. Evidence class: hosted Windows runner, simulated devices, not the owner's PC. Small follow-ups (A5's notes on #180): a comment that a partial grant on failure is intended, a test for a repeated `Listen`, and a comment on the token DACL versus `TokenDefaultDacl`.

## D3-10: build with Go 1.26.10, not 1.26.0 (#179's Windows panic)

Date: 2026-10-27. Status: **accepted**. A3 passed it for security and A6 on content (#200). On [#179's Windows job](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40443162073/job/121988031206) (merge `0e9d6b0`, Go 1.26.0), `tests/integration/syslogreceive` panicked inside `json.Marshal`, called from `receive.record` on the UDP read path (`payUnknown`, `serveDatagrams`).

Which field went bad: going by the frame addresses and `event.Event`'s field offsets, it was `Received.Clock.Source`. That string is empty in this path and no code writes it, yet its length word held `1<<36`, with a nil data pointer.

- `1<<36` is the 32-bit value 16 sitting in the upper half of a zero word. 16 is `sizeof(sockaddr_in)`, the address length that `WSARecvFrom` returns for an IPv4 sender.
- Go 1.26.2 fixed golang/go#78041 (behind #77975). On Windows, `internal/poll` kept `recvfrom`'s address-length out-parameter on the goroutine stack while an overlapped receive was still running, so the kernel could write it into memory after the stack had moved.
- A4 found nothing on the receive path that could write the field: `normalize.Syslog` copies `Received` verbatim, no `msg` or `Event` is shared between goroutines, and `modules/telemetry` has no `unsafe`.
- A5 found no corruption fix in modernc sqlite v1.61.0, memory v1.12.1 or libc after v1.79.0.

**Ruling:** the root module's `go` line moves to `1.26.10`, the latest patch release, which CI picks up through `go-version-file`. The release also carries the stdlib security fixes after 1.26.0 (crypto/tls, crypto/x509, net/http and others), which the product uses. The receiver is a product path: a node built with 1.26.0 that receives UDP Syslog on Windows can corrupt memory. `platform/experiments/phase0/go.mod` stays at 1.26.0. It is a Phase 0 experiment that CI does not build and that is never shipped, so it is not an exception to this rule.

**Standing rule (A3's review, adopted for Phase 4):**
1. Product binaries are built with the latest patch release of a supported Go minor (one of the two newest), and a move to the next minor is planned before ours leaves support.
2. A CI job runs a pinned `govulncheck ./...` on every PR and weekly, and fails when a vulnerability is reachable.
3. A toolchain or dependency bump is a normal PR, reviewed by A3 and A6, with no auto-merge.
4. Optional: the node and the collector report `runtime.Version()` in their status.

**Evidence and its limit:** A6's Windows stress test on #199 ran two sets of `TestUnknown*`. Go 1.26.0 crashed 2 of 42 runs. Both crashes were "JSON decoder out of sync - data changing underfoot?" in `event.Decode` under `store.assignSeq` on `writeDatagrams`, the UDP path again. Go 1.26.10 crashed 0 of 41. Go 1.26.0 with `-race` crashed 0 of 23 and reported no race. 0 of 41 is suggestive only: at the 1.26.0 rate, p≈0.13, and about 62 clean runs would rule it out at 95%. So the root cause stays **inferred**, not proven. The bump stands on its security fixes either way, and the exit report carries the crash as resolved-by-inference.

**Owner's PC:** with `GOTOOLCHAIN=auto`, the portable Go 1.26.0 on ALI's PC would download 1.26.10 the first time it builds. That download needs ALI's answer before the next run on that PC. Whichever way ALI chooses, the default `GOSUMDB` stays on. Otherwise ALI installs the official archive after checking its SHA-256 against go.dev/dl.

## D3-11: a C2 0.5 SER result with no DATE_F keeps the pre-0.5 date rule (#203)

Date: 2026-10-27. A2's review of #203 found that `sel751` stamps every result C2 0.5. Under a register package with no context read for `sel.ser.read_all` (revision 3), its results carry parsed rows and no settings. Under my earlier plan ruling (a parsed row without a usable DATE_F is `ErrResult`), every SER read on a revision-3 site would go to quarantine. **Ruling:** for C2 0.5 and later:

1. If DATE_F is MDY, DMY or YMD, it is used. A caller order that disagrees is `ErrInput`.
2. If DATE_F is present with any other value and a row is parsed, the result is `ErrResult`. This is defence only: the adapter refuses such a package before connecting.
3. If DATE_F is absent, the pre-0.5 rule applies: the caller's order if one was given, otherwise MDY with `date-format-assumed:MDY`.

**Rejected:** refusing SER in the adapter under a package without the DATE_F read. A revision-3 site would stop collecting until revision 4 was activated, and the relay's finite SER buffer could overwrite native records in the meantime. Option 3 keeps the bytes and the parsed rows, and it states the assumption on each event.

## D3-12: the A-team hands over to the B-team with the roles unchanged (owner)

Date: 2026-10-27. The owner asked for agents A1 to A6 to be replaced by fresh agents B1 to B6. Each B agent has the same role, responsibilities, tools and instructions as its A agent; only the name changes.

The handoff is in `handoffs/`:

- `HANDOFF-SUMMARY.md`, written by A1;
- one `B{n}-handoff.md` per agent, written by the matching A agent;
- one `B{n}-ack.md` per agent, written by each B agent.

**Ruling.** Older records keep the A names, because they record who did what. In them, A*n* reads as the role that B*n* now holds. No ownership changes in the handoff. A role change, if one is wanted later, is proposed in a handoff note and decided separately.

Phase 3 stays pending the owner's acceptance, so the Phase 4 briefs stay drafts. Every standing rule carries over unchanged: D2-4, D2-5, D2-10, D2-11, D2-13 and D3-10, and the owner's rules for their PC.

Cutover happens only when every ack is confirmed with no open questions. At cutover A1 to A6 retire and B1 leads.

**Numbering note (found by A4 while writing its handoff).** The label "D3-3" names two different things:

- this file's D3-3, the `quarantine.cleared` ruling;
- A3's unknown-sender condition, HR-11, as cited in `docs/threat-model.md`, D3-5 above, `A4-syslog-receive.md`, `A3-handoff.md` and `A5-handoff.md`.

The records stay as written. From now on, cite HR-11 for the unknown-sender condition, and use D3-3 only for `quarantine.cleared`. The exit report now cites HR-11.

## D3-13: a pull request that changes only Markdown skips CI (owner)

Date: 2026-10-27. The owner asked why docs-only PRs ran CI. The answer was that `ci.yml` ran on every pull request, with no path filter, so a handoff file waited 15 to 20 minutes for all ten jobs.

**The owner's decision:**
- Markdown-only PRs skip CI.
- The handoff PRs that were still running CI (#213, #214 and #218) are merged without waiting.

**Ruling.** `ci.yml`'s `pull_request` trigger now runs only when the PR changes a file that is not Markdown. Changes under any `testdata/` directory still trigger it, because tests read two test-data READMEs (`contracts/asset/testdata/README.md` and `contracts/adapter/testdata/README.md`). Every push to `main` still runs the full suite, so a Markdown merge is still tested on `main`.

D2-13 otherwise stands. A PR that changes code, tests, data or workflows merges only when every job is green on its head.

