# A1 decisions during Phase 1

Owner: A1. One entry per decision made while the contracts are reviewed. Each entry names the question, the decision, the reason, and who must act. Decisions that change architecture also go into an ADR.

## D1-1. Who holds NodeID: a leaf package (2026-10-24)

- **Question (A4, C1-A4 change 1):** C4 imports `contracts/asset` for the asset ID, and C1 needs C4's NodeID, which creates an import cycle. There were two options: a leaf package, or two copies of the pattern kept in step by an A6 test.
- **Decision:** a leaf package `contracts/node`, owned by A1 like `contracts/version`. It holds NodeID and the event stream token, with their validation and tests. C1 and C4 both import it, and neither keeps a copy.
- **Reason:** one definition per concept (contracts/README.md). A test that keeps two copies in step catches drift only after it has happened.
- **Action:**
  - A4 adds `contracts/node` in #29, which merges first, and adds its row to the contracts/README.md table.
  - A2 switches C1 to import it once #29 merges.

## D1-2. Syslog endpoint semantics in C1 (2026-10-24)

- **Decision:** A4's change C1-A4-2 stands as written: host is the expected source address, port is never the device's ephemeral source port, and there is one asset per (transport, host) per node.
- **Status:** A2 reports it applied at b627e50.

## D1-3. Collecting node under N-1 redundancy (2026-10-24)

- **Question (A2):** which node collects from an asset when a site has more than one node.
- **Decision for 0.x:** exactly one collecting node per asset (D9), as C1 states. Moving collection to another node is an explicit operator action, recorded by C8. Other nodes may still receive the asset's Syslog. Automatic collector failover is out of scope until Phase 4, distributed operation.
- **Reason:**
  - Two nodes collecting from one relay double the session load on a device with few Telnet sessions (V-S13).
  - They also produce two event streams for the same SER rows.
  - Failover needs leader election, which the first slice does not need.
- **Action:**
  - A5 records the rule in A5-node-posture.md.
  - A6 adds a negative test: a second node's collection request for an assigned asset is refused.

## D1-4. Storage exhaustion states in C5 (2026-10-24)

- **Question:** what the node does when no reserve is left (ADR-0004 item 8, F-013, F-014). A5 proposed a two-tier reserve and a blocked startup. A6 proposed an explicit "full" state.
- **Decision:** both proposals, under two named states.
  - **blocked:** there is no open headroom. The store is not opened and the lock is held.
  - **drain-only:** the store opened after a degraded recovery. The node forwards and prunes, and accepts no new events.
- **Common rules:**
  - Both states are reported on the node health surface and in a C8 audit record.
  - In both states the collector stops pulling SER, so events stay on the relay. If the relay's buffer wraps meanwhile, the next collection records a gap marker.
  - C5 defines the exit condition for each state.
  - A failed reserve release stops startup.
- **Action:**
  - A5 writes this into C5 (#33).
  - A6 tests blocked, drain-only and failed release under V-S9.

## D1-5. Prune boundary and replay windows (2026-10-24)

- **Question (A4, C5-A4, blocking):** the best-effort prune boundary uses max(cursor, aged), so it can prune a mode B replay window before the replay happens.
- **Decision:** the boundary may not pass any open replay window (R-A5-5: nothing a consumer still needs is pruned). If storage pressure forces a prune past it, that is an explicit loss, recorded with a gap marker and an audit record. It is never silent.
- **Action:** A5 changes C5. A4 re-checks.

## D1-6. Register format changes from A2's C3 review (2026-10-24)

- **C3-A2 change 1:** operations may list phases (operate, probe). sel.id runs in both. `Matcher.Permit(phase, line)` is the egress check.
- **C3-A2 change 2:** posture warnings are in the package (MAXACC, FTPACC and HTTPACC above 1).
- **C3-A2 note 5:** a probe operation must be literal and need access level 0 (`ProbeAccessLevel`).
- **Content:** the corrected package is A2's `contracts/register/testdata/sel-751.json`, after #27 merges. `sel-751-phase0.json` stays as the lossless Phase 0 conversion record.
- **FID count:** A6 confirmed 78 unique FIDs and withdrew the count of 84.

## D1-7. A read after an empty read is not a gap (2026-10-24)

- **Question (A6, C4-A6 Q4):** C4 reports a read that follows an empty read as a gap, so clearing a relay's SER buffer raises `ser.gap` twice. The first gap, the clear itself, is real. The second is not, because nothing can have been dropped from an empty read.
- **Decision:** A6's recommendation is accepted. When the previous read is empty but not nil, `Align` returns `ok` and adds every record. C4's doc.go states the case that cannot be detected: if the buffer wraps completely between two reads, records are lost without trace, and that is true after any read, not only after an empty one.
- **Action:** A4 changes `Align` and adds the case to `align_test.go`. A6's V-S4 case expects exactly one gap per clear.

## D1-8. An authentication line is sent in auth only (2026-10-24)

- **Question (A6, C3 re-check at 6a776bc):** the format allowed a session line such as `ACC` to be listed for probe as well.
- **Decision:** `Validate` refuses a session line that lists auth together with any other phase. The format cannot tell which line elevates a session, so a package that puts `ACC` in probe alone is caught by A2's and A3's content review and by C7's signature, not by `Validate`.

## D1-9. C4 decoding is strict (2026-10-24)

- **Question (A6, C4-A6 optional 6):** `encoding/json` matches keys to fields without regard to case, lets a duplicate key overwrite the first, and ignores unknown fields. A6 showed that the result of decoding an event depended on key order.
- **Decision:** C4 gets a strict `Decode`, the same rules as C3. Stored events are evidence, so every reader must read them the same way. Checking only at the C7 IPC boundary would leave stored and forwarded copies unchecked.
- **Action:** A4 adds `Decode` in #29. A shared helper may move into a leaf package later, but only once a third contract needs it.

## D1-10. One strict decoder for every contract (2026-10-24)

- **Question (A6, C1 review in #36):** C1 decodes as loosely as C4 did. An `IDENTITY_BINDING` key that differs only in case silently replaces the binding. This is the third contract to need strict decoding.
- **Decision:**
  - `contracts/internal/strictjson`, owned by A1, is the one strict decoder.
  - It walks the document against the target's Go type. A struct object may hold only its fields' exact JSON names, each once, with no case variants. A map may hold any keys, each once. Nothing may follow the value.
  - Every contract that decodes a document crossing a process, network or storage boundary uses it: C1, C2, C3, C4, C6, C7 and C8. C3 already does, at #27.
  - There are two entry points:
    - **`Decode`** rejects unknown fields. It is for strict contracts: C3, C7 IPC requests, and C2 invocations.
    - **`Forward`** is for contracts whose readers accept later minors: C1, C4 and C2 results. It ignores an unknown key only when the key does not case-fold to a field name (`strings.EqualFold`, which also covers the Kelvin sign and long s that `encoding/json` folds). Duplicate keys are always rejected.
    - A2 and A4 both pointed out that rejecting every unknown field would make each new field a major version change. `Forward` is their option (a).
  - D1-9 is satisfied through this package.
- **Action:**
  - A4 (C4) and A2 (C1) switch their `Decode` functions to `strictjson.Decode` once #27 merges.
  - A3 uses it in C7 and C8.
  - A6's contract tests probe each contract's `Decode` with case-variant and duplicate keys.

## D1-11. Audit before act stops credentialed collection when audit cannot be written (2026-10-24)

- **Question (A3, C5-A3-4):** under audit before act (C5-A3-3), a full or failed audit store means no receipt for an audit record. Two options:
  - collection that uses a device credential stops;
  - collection continues, and one gap record is written afterwards.
- **Decision:** collection that uses a credential stops. Passive intake, such as received Syslog, continues.
- **Reason:**
  - Using a credential without an audit record is the attack path the audit chain exists to expose (Q7, P5: privileged access fails closed).
  - Stopping is safe for OT, because SER rows stay in the relay's buffer and a later wrap shows up as a `ser.gap` event (D1-4).
  - Collection pauses are visible through C5 modes and health events.
- **Action:**
  - A5 adds this to C5's storage-full rules.
  - A3 records it in C7 and C8.
  - A6 adds a V-S9 case: with the audit store full, no `ACC` is sent and Syslog is still received.

## D1-12. Align has a hard input bound (2026-10-24)

- **Question (A6, C4 re-check R-1):** `Align`'s gap path allocates (n+1)(m+1) `int32`. A SEL-751 read of at most 1,024 rows costs 4 MB. But a fault or an attacker on the Telnet path can send far more: 50,000 rows comes to about 10 GB and takes down the node.
- **Decision:** the bound is enforced in both places.
  - **C4 ceiling:** `event.MaxAlignRows = 2048`, which costs at most about 16 MB. `Align` itself refuses a longer read with an error and allocates nothing. The contract function protects itself and does not rely on its callers.
  - **Per-family limit:** each capability profile (C1 `profile.go`, used by C2) states its own `max_read_rows`, at or below the C4 ceiling. For SEL-751 that is 1,024, taken from the manual. *Corrected 2026-10-24: profiles live in C1, not C2 (D1-18).*
  - **Over-limit reads:** a read over the limit is a failed parse. Its bytes are kept, a `parse.failed` health event is raised, and no records are aligned or stored from it.
  - **Raising the ceiling:** a minor version may raise it when a family's evidence calls for it.
- **Action:**
  - A4 adds the ceiling and a test, before #29 merges.
  - A2 adds `max_read_rows` to C2 profiles.
  - A6 re-runs the oversize probe.

## D1-13. Readers upgrade before writers (2026-10-24)

- **Question (A6):** a 0.1 reader rejects a later-minor enum value. That is safe, but a newer site node's events then fail at an older central node.
- **Decision:** central nodes and every receiver of a contract (C4 events, C8 audit) upgrade before the nodes that write it. A site node never emits a minor version its central node has not declared support for. In 0.x the operator follows this order by hand. An enrollment-time version exchange that enforces it belongs to Phase 4, distributed operation.
- **Action:** A5 records the order in deploy notes and in `A5-node-posture.md`. C6 (A4) states that the Syslog payload carries the C4 identifier, so a receiver can tell a version it cannot read apart from a malformed event.

## D1-14. A gap must never lose a new record (2026-10-24)

- **Question (A6, C4 re-check S-1, rated "should"):** a gap with repeated keys can lose a new record.
- **Decision:** S-1 is required before #29 merges. Silently losing a native record breaks EP-1, and `Align` sits on the path of every SER read. S-2 (second 60 checked against local time, not UTC) and S-3 (`invalid-time` with a `wall_clock` present validates) are small, so A4 fixes them in the same change.

## D1-15. Audit is forwarded only over RELP with TLS (2026-10-24)

- **Question (A4, C8-A4, ADR-0004 item 6):** should the audit stream, or at least its checkpoints, require a `relp-tls` target?
- **Decision:** yes, for the whole audit stream, not only its checkpoints.
- **Rules:**
  - C6 forwards audit records only to `relp-tls` targets. A configuration that names any other transport for audit is refused at load, with a reason code.
  - An audit consumer is always a required consumer. Audit is pruned only after a RELP acknowledgement (C5-A3-2).
- **Reason:**
  - Off-node checkpoints are what cover the residual A3 named: a local administrator can bypass the node's own protections.
  - Without an application-level acknowledgement, the node cannot tell a checkpoint that arrived from one that was lost. UDP, plain TCP and TLS-TCP all give no such acknowledgement.
  - An unauthenticated target could also receive the chain.
- **Other events:** they keep the targets ADR-0004 allows, with `forward.unconfirmed` raised where delivery cannot be confirmed.
- **Action:** A4 writes this into C6. A3 notes it in C8. A6 adds a negative test: an audit target over UDP is refused.

## D1-16. A node clock step becomes a C4 event (2026-10-24)

- **Question (A4, C8-A4):** C8's `clock.change` has no C4 counterpart.
- **Decision:** add `time.node-stepped` to C4's platform event types. It goes in alongside C6 as an additive 0.1 change, reviewed with C6, so it does not hold #29.

## D1-17. Residual SER loss with repeated keys is documented, not hidden (2026-10-24)

- **Note (A4, A6):** D1-14 closes the case A6 raised. One case remains that cannot be detected from the reads alone: when keys repeat, a new record identical to an old one, and placed before the first distinct new record, cannot be told apart from the old one.
- **Decision:** C4's doc.go states the limitation. V-S4 reports the residual measured by A6's randomized model, and it is listed as an open risk in the Phase 1 exit document.
- **Evidence:** SEL-751 SER rows carry millisecond timestamps, so identical rows need identical text in the same millisecond. Only a device run will show how often that happens.

## D1-18. Family session limits live on the C1 capability profile (2026-10-24)

- **Question (A2, C7-A2):** C7 says the collector takes session limits from the register or the profile, and neither has a field for them yet.
- **Decision:** add `session_limits` to the C1 capability profile, next to `max_read_rows` (D1-12). Each value stays at or below the C2 ceilings. C3 stays a list of lines and the conditions for sending them; per-family timing and counts are profile facts with citations.
- **Fields for 0.1:**
  - concurrent sessions;
  - the minimum interval between collections;
  - password attempts per session;
  - the failed-auth floor;
  - the idle timeout the platform assumes (`TIDLE`).
- **A2's SEL-751 finding (S22 p. 7.33, p. 7.16):**
  - The relay re-prompts `Password: ?` up to three times.
  - A Telnet session closed without `QUI` stays elevated until `TIDLE` expires, which is 1 to 30 minutes.
  - So the failed-auth floor must be longer than the largest `TIDLE`. A first prompt that is already elevated gets no password and does not suspend the credential (`refused.session_elevated`).
- **Action:**
  - A2 adds the fields to #32.
  - A3 reads C7's limits from the profile.
  - A6 models re-prompting and persisted elevation in the recording simulator.

## D1-19. The family secret policy lives on the C1 capability profile (2026-10-24)

- **Question (A2 C7-A2-7, A6 C7 re-check):** `ValidateSecret` takes a `SecretPolicy` from its caller. A zero `MnemonicLen` silently selects whole-word mode, which lets `quiet123`, `close!` and `serial99` through, and a zero policy accepts anything. `Allowed` is matched unanchored.
- **Decision:** the policy is a family fact with a citation, like `session_limits` (D1-18). It goes on the C1 capability profile as `secret_policy`, so the collector never builds it itself.
  - A profile with an adapter operation above level `0` must carry a `secret_policy`. A zero or missing policy is a validation error, never "accept anything".
  - Whole-word matching is an explicit mode. `MnemonicLen` 0 is invalid, not permissive.
  - `Allowed` is matched against the whole secret (`^(?:…)$`).
  - SEL-751: `[!-~]{1,12}`, mnemonic length 3 (S22, as cited by A2).
- **Action:**
  - A2 adds `secret_policy` to the C1 profile in #32.
  - A3 makes the zero policy and zero `MnemonicLen` invalid and anchors `Allowed` in #38 now, and reads the policy from the profile once #32 merges (`TODO(C1)` until then).

## D1-20. The failed-auth floor starts when the password is sent (2026-10-24)

- **Question (A2, C7-A2-1 re-check):** C7 starts the floor only after a second `Password: ?`. A session can also end after the password is sent and before `=>` is seen: a timeout, a transport close or a collector crash. The relay may then still be at `Password: ?` or elevated until `TIDLE` expires (S22 p. 7.16, p. 7.33).
- **Decision:** A2's fix. The collector writes the floor time durably before the slot sends the password, and clears it only when `=>` is confirmed. A crash at any point therefore leaves the floor in force. This blocks #38.
- **Amendment (2026-10-24, A6 C2 change 14):** the floor starts when `ACC` is sent, not when the password is. The collector writes the floor time durably before the transport sends `ACC`, and clears it only when a Level 1 prompt (`=>`) is received. Why: C2 sends nothing after an unanswered `ACC`. If the relay keeps a pending `Password: ?` across connections (H-15 (a), unknown), the next session's wake line would be taken as a wrong password. Starting the floor at `ACC` keeps that next session at least TIDLE plus one minute away. The cost is a 31-minute wait after any `ACC` that times out. Owners: A3 changes the C7 wording (`doc.go`, `InsideFailureFloor`, `A3-credential-design.md`), and A2 corrects the C2 `dialogue.go` comment in the D1-24 PR. Reviewers: A6 and A2. No code path changes in 0.1, because the floor time is written by the Phase 2 collector.
- **Floor values:** once #32 merges, `FailureFloor` takes `session_limits.failed_auth_floor_ms` and `idle_timeout_ms` from the C1 profile. A `SHO P 1` reading may shorten the floor, never below the read `TIDLE` plus 1 minute. Not blocking.

## D1-21. Q5 passes: push sources stay out of C2 (2026-10-24)

- **Evidence:** `docs/phase1/A2-q5-rtac.md` (A2, documentation only; no RTAC contacted). The SEL RTAC fits C1 and C4 with three special cases, all in C1, and none in C2. Forcing it through C2 would take about nine.
- **Decision:** accepted as a pass. C2 stays command/response only. A device that only sends (Syslog) is covered by C1, C6 and C4, and its profile names no adapter operation. A suspension stops adapter sessions, never reception (now in C1).
- **Open for the owner, Phase 2:** production use of plaintext UDP Syslog (RTAC, SEL-2730M, SEL-2488). In 0.1 it is accepted for the lab only, as Telnet is (ADR-0005). It goes into the Phase 1 exit document as an owner decision.
- **Deferred:** the `relays` endpoint marker (S3) until a site enables the RTAC Syslog Collector.

## D1-22. Insecure forwarding targets need an acknowledged scope, and send no device text by default (2026-10-24)

- **Question (A3 C6 item 5, raised by A4):** should `tcp`, `udp` and plain `relp` targets require an administrator-acknowledged scope, and leave out device text by default?
- **Decision:** yes to both, as A4 recommends.
  - **Scope.** A C6 target on any transport other than `relp-tls` or `tls` must carry an acknowledgement with the same shape as C1's insecure-endpoint acknowledgement: by, at, reason and scope. Setting or changing it is a C8 audit record. In 0.1 the only scope is `lab-only`, as in C1 (ADR-0005). A production scope for an insecure upstream link (for example `same-segment`) needs the owner's decision and a later minor. It joins the plaintext UDP Syslog question from D1-21 in the Phase 1 exit document.
  - **Device text.** Each target has a `device_text` setting. It defaults to off on insecure transports and on for `relp-tls` and `tls`. Turning it on for an insecure target is part of the acknowledged scope.
  - **Reporting.** Text left out by configuration is reported once, as the target's state at load and in its audit record, not as a `forward.text-omitted` event per message. `forward.text-omitted` stays for omission caused by size.
  - The two insecure golden renderings change accordingly.
- **Why:** without this, a SER row crosses the WAN in clear text by default, and the platform would open a weaker path than the one C1 already refuses for downstream links without an acknowledgement.
- **Action:** A4 applies it in #42. A3 and A6 check the change when they re-check C6.

- **Amendment (2026-10-24, A4 on #42).** Leaving out only the raw record does not close the concern: the normalized `subject`, `value` and `summary` still say which element picked up, and when. On a target with device content off, those three fields are left out as well. The setting is named `device_content` rather than `device_text`, because it covers everything derived from the device record. What remains is the event type, asset, times, severity and record hash, which is enough for an analyst to look the event up on the node. The `dtext_omitted="config"` marker and the once-only report apply to all of it.

## D1-23. Every device-origin event says whether its device was real (2026-10-24)

- **Question (A4, C2-A4):** a C4 event does not say whether its device was a real device or a simulator. A simulated SER read would be forwarded upstream looking exactly like a device read, which breaks principle 10 (no fabricated validation).
- **Decision:** accepted as A4 proposes, as an additive C4 0.1 change before Phase 2 begins.
  - `source.evidence_class` is required on every device-origin event, with the C1 values `device-observed` or `simulated`. An unknown value reads as `simulated`, because that is the weaker claim.
  - For `adapter-poll` events it is set from C2 `Result.target`. For received Syslog it is set from the C1 endpoint, and an endpoint fed by a simulator or a replay is `simulated`.
  - C6 renders it as `evc` on every message, so a SIEM can filter out simulated events. C6 never drops the field to make room, so a size failure stays a failure.
  - The C4 golden examples carry `simulated`, because they are built from documented fixtures.
- **Reviewers:** A6 (P10 and the chain test) and A2 (as the C2 producer). A4 makes the change in a new PR and adds `evc` to C6 there too.
- **Why now:** Phase 2's first workflow runs only against the simulator. Every event it forwards must say so.

## D1-24. A C1 endpoint says whether a simulator is behind it (2026-10-24)

- **Question (A6, on #59):** D1-23 and C2 `Result.target` say the evidence class is set "from the endpoint's configuration", but the C1 `Endpoint` has no such setting. Nothing supplies the label, so a collector would have to guess it.
- **Decision:** an additive C1 0.1 change, made by A2 after C2 (#51) merges.
  - `Endpoint.target` is required, with the values `device-observed` or `simulated`. It is set by an admin when the endpoint is configured, never from what the far end reports. A missing or unknown value fails validation; it is never defaulted to `device-observed`.
  - C2: the collector copies it into `Result.target`. A check that takes the C1 asset (as `CheckAgainst` does) refuses a result whose `target` differs from its endpoint's.
  - C4 and C6 (D1-23): received Syslog takes the evidence class from the endpoint the message arrived on, by the same rule.
  - Safety interlock for Phase 2: until the owner authorizes a lab device, the node refuses to run any invocation against an endpoint whose `target` is `device-observed`. Phase 2 configures it as node policy; it is not a contract field.
- **Reviewers:** A6 (P10, the chain test), A3 (the label is a security claim), A4 (the C4 consumer).
- **Why now:** Phase 2 forwards events. Every one must carry a label that comes from configuration, not from a default.
