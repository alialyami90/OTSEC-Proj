# D3: the trust design of the sensor link, and the sensor host (P4-4-L1)

D3, 2026-11-11. This is the design note for brief P4-4-L1 (`docs/agent-handoffs.md`, "Phase 4 item 4, second part", D4-86). It is Markdown only. It changes no contract and proposes no code for merging. Reviewers: D5 (can the node do it), D4 (can the sensor do it) and D6 (can each rule be tested). D1 approves.

**Revised on 2026-11-11 after the reviews of PR #624 at `2935220a`.** D5 and D4 passed it with notes, and D6 failed it on two points: the mirror port (O-1) and the audit cap (§11.2). D1 ruled on four things, each marked where it applies: three processes on the sensor host (SL-3), the signature check at the sensor's end (SL-5), the order of a revocation (SL-R2), and the three threat-model rows beyond the brief's list. The reviewers' findings are cited as "on #624"; D3 did not re-derive them, except where a file is named.

**Nothing in this note is built.** Every rule below is a requirement. No sensor, dialer, listener or enrolment exists (`docs/agent-handoffs.md`, "What already exists"). Nothing is `hardware-verified`, and no device family is called supported.

## 0. Sources, labels and words

**Evidence classes.**

- A statement about what exists today is `desk`: read on `main` at `1f5b307f` from the file it names. ADR-0009's decision for option (b) was read from PR #618 at `a16f8497`, which is not merged.
- A statement marked **assumption** is D3's understanding of Linux or of an engine. No manual page, kernel source or engine document was read for this note. Each assumption names the test that decides it.
- A rule is a requirement, and is not evidence of anything.
- The threat-model rows this brief rewrote (TB6, AP-30, AP-31, AP-32 and AP-34) are as they stood before option (b) at `1f5b307f`: `git show 1f5b307f:docs/threat-model.md`.

**Read for this note** (`desk`): ADR-0009 at `a16f8497`; `docs/threat-model.md` (TB6, AP-10, AP-24, AP-30 to AP-36, SC-11, SC-14, SC-19, HR-13, HR-14, HR-19, HR-20); `docs/phase4/D5-sensor-node.md` §1, §2, §4 and §5; `docs/phase4/D4-c13-netobs.md` §1, §2, §3.3 and §6; `docs/phase4/D3-c7-0.10-c8-0.12.md`; `contracts/authz` (0.10: `adminsig.go`, `approval.go`, `netack.go`); `contracts/audit` (reader 0.12); `platform/sensorlink/link.go`; `platform/node/netsensor.go`; `modules/security/nodekey/doc.go`; the reviews on PR #618; D4-82 to D4-86.

**Words.**

- **Sensor host:** the Linux machine at a site that captures mirrored traffic (option (b), D4-85).
- **Capture stage:** the project's own program on the sensor host that holds the packet socket, discards PRP duplicates and feeds the engine through a pipe (SL-3).
- **Engine:** the decoder on it (Zeek is provisional, ADR-0009). It parses hostile packets.
- **Link agent:** the project's own program on the sensor host that holds the link key, listens for the node, takes the engine's output and sends C13 records.
- **Link:** the mutual-TLS connection that the node opens to the link agent.
- **Pin:** `sha256:` and the hex SHA-256 of a key's DER `SubjectPublicKeyInfo`. A pin names a key, never a name and never a certificate authority.
- **Enrolment:** the admin-signed statement that pins each end to the other (§3).
- **Generation:** a number that rises by one at each enrolment of one `sensor_id`.

**How to read a rule.** Each rule has an ID (SL-*n*), the attack path it answers, and the test that would show it (SL-T*n*, §12). A test names the control that must make it fail, so that D6 can show the test sees the fault.

## 1. Who holds what

| Party | Holds | Never holds |
| --- | --- | --- |
| **Node** | Its own link key, a `tls-key` entry of the node key register used for sensor links only (non-exportable, `modules/security/nodekey`). For each sensor: `sensor_id`, generation, the sensor's pin and address, `not_after`, the signed enrolment's bytes, the highest run counter and the last committed position (§5), and the pins it has revoked. The enrolments and the revoked pins are kept where pruning the audit stream cannot lose them (SL-6). | A sensor's private key. A login, key or password for the sensor host. |
| **Link agent** | The sensor's private key. The node's pin and address. Its `sensor_id` and generation. Its run counter. One administrator public key, to check an enrolment (§3). | Any platform credential (SL-21). |
| **Capture stage** | The packet socket on the monitoring interface. It writes the redacted ring. | A send call. The link key. An address on the management interface (SL-3). |
| **Engine** | The reading end of a pipe from the capture stage, and its own output in memory-backed storage. | A packet socket. A route, a resolver or any interface but the loopback of its own empty network namespace. The link key (SL-3). |
| **Collector** | The administrators' pinned public keys, as today. It verifies the enrolment and revocation requests. | Anything about a sensor beyond the request it verified. It opens no connection to a sensor host. |
| **Administrator** | Their signing key, off the node and off the sensor (as today, C7 0.4). | — |

## 2. The credential

**SL-1. One key pair per enrolment of a sensor, made on the sensor host, never exported.** The link agent makes the key at install. No command exports it, no backup holds it, and no image, repository or configuration tool carries it. A re-imaged or replaced host makes a new key and needs a new enrolment (SL-6).

- *Answers:* AP-34 (a). A key shared across sensors, or baked into an image, lets one stolen copy speak for every sensor. With one key each, a stolen key speaks for one sensor until it is revoked (§6).
- *Test:* SL-T1.

**SL-2. The identity is the key, pinned at the other end. There is no certificate authority.** Each end presents a self-signed certificate whose only job is to carry its public key. The other end accepts it only when the key's pin equals the pin in the live enrolment. The node's key is ECDSA P-256, as the key register makes them (`nodekey/doc.go`). The sensor's key is P-256 unless D4 shows a reason for another type; a pin does not depend on the type.

- *Why no CA.* A CA key that can mint sensor identities would be a new asset to protect (threat model, asset 8). SC-11's central enrolment is not built, so there is no issuer and no "credential like a node's" to copy (D5 on #618). Two pins per link is the least that works, and removing a pin revokes at once, with no revocation list to distribute.
- *Answers:* AP-34 (a), AP-8's rogue enrolment.
- *Test:* SL-T3.

**SL-3. Three processes on the sensor host, each under its own account, and only the link agent can read the key.** This is D4's shape (review of #624), and D1 adopted it as the design the briefs build on. **It is a design to be shown, not one that is shown.**

1. **The capture stage** is the project's own memory-safe program. It holds the packet socket, calls no send function, does the PRP duplicate discard, and feeds the engine through a pipe. It is the only program that sees raw frames, so it is also the one that redacts them by position and writes the ring (D4 on #624 at `ca96b813`).
2. **The engine** holds no packet socket at all. It reads the pipe, and it runs in an empty network namespace, so it has no route, no resolver and no management interface by construction and not by a setting.
3. **The link agent** holds the key and checks the enrolment's signature (SL-5). It takes allow-listed lines from the engine, in one direction only (SL-22), maps them to C13, and cites frames from the redacted ring. It is the project's own memory-safe code (SC-14), because it is the only program on the host that parses bytes from the network side of the link.

- *What settles it.* E-D4-03 (P4-4-S2) shows whether the engine reads a pipe offline under `unshare -n`. The C-11 rig's sender on an already-open socket (P4-4-R1) shows whether dropping a capability is a barrier to sending. **The capability drop stays as a second measure, and is never the only one** (SL-26).
- *Answers:* AP-30 and AP-32. The program that parses hostile bytes has no socket to send on, no network to reach and no key to take. A decoder exploit then holds the engine's account. It can lie through its output as this sensor (AP-34 (b)), but it cannot send onto the station LAN, reach the management network, or take the key away and speak as the sensor from somewhere else or after the host is cleaned.
- *Where the key rests.* A file readable by the link agent's account alone, or a TPM-held key. That is a hardware choice, and it is the owner's (§10, O-2). With a file, root on the sensor host can copy the key. With a TPM, root can use it and cannot copy it. **Assumption:** that a TPM-held key cannot be copied by root. No TPM document was read for this note, and an H-row decides it (§12).
- *Test:* SL-T2.

## 3. Enrolment, with no trust on first use

**SL-4. Neither end accepts a key because it was the first one it saw.** The node dials an address only when a live enrolment names it. The link agent does not listen at all until it holds an enrolment, and then completes a handshake only with the pinned node key.

- *Answers:* AP-8's rogue enrolment and an attacker on the path at first contact, who under trust on first use would become the sensor for good.
- *Test:* SL-T3.

**SL-5. An enrolment is an admin-signed C7 request, `node.sensor_enrol`, that names both ends** (§11.1): `sensor_id`, generation, the sensor's pin and address, the node's pin and address, and `not_after`. The administrator's client draws the `sensor_id`; the sensor does not choose its own. Addresses are IP literals. No hostname is used, because name resolution is not trusted and no internal hostname may be recorded.

The steps, each done at a console or in the administrator's client and none over the link:

1. On the sensor host, the link agent makes its key and shows its pin on the console.
2. The administrator reads the node's link-key pin from the node's key register.
3. The administrator's client builds the request from those two pins. **The administrator takes the sensor's pin from the sensor's own console, never from the node,** for the reason HR-14 gives for baseline digests: a compromised node must not be able to supply the value a person signs.
4. The node relays the signed request to the collector, which verifies it as it does every admin kind: signature, the key's kinds, nonce, window, and the binding to this node (`VerifyAdminRequest`).
5. The node checks the request against its own state (SL-6), writes C8 `sensor.enrolled`, and only then records the enrolment. If the audit write fails, the enrolment is not applied.
6. The same signed bytes are carried to the sensor host's console. The link agent verifies the signature against the administrator public key it was installed with, checks that the sensor pin is its own key's and that the generation is above the one it holds, and takes the node's pin, the node's address, its `sensor_id` and `not_after` from the signed body. It then opens its listener.

So both pins come from one signed statement, and the node's audit chain records it.

- *What the sensor does not check.* The 15-minute lifetime of an admin request is judged at the collector's clock. The link agent does not judge it: a site visit takes longer, and the sensor host's clock may not be set yet. An old enrolment cannot be replayed to the agent, because it must name the agent's own key and a higher generation.
- *What the signature does not do.* It does not protect against a compromised node, which can already write anything to its own store. It stops a person who can write the node's configuration and holds no enrolment key (AP-14), it stops trust on first use, and it leaves a record.
- *The check at the sensor's end is kept* (D1's ruling on #624, on D6's preference), on two conditions. An import test shows that neither of today's product binaries, `cmd/otsec` and `cmd/otsec-collector`, can reach the verifier that leaves out the collector's checks (§11.1). And the fallback is recorded for each deployment that uses it.
- *The fallback* is that an installer types the node's pin at the sensor's console. The sensor's end is then pinned by hand and by nobody's signature, and a wrong or hostile entry is caught only when the node's dial fails. The link agent states which way it was pinned (asked of C13 0.2), and the node shows it in status, so a deployment pinned by hand is never mistaken for one pinned by signature.
- *Answers:* AP-8, AP-14, AP-34 (a).
- *Tests:* SL-T3, SL-T4.

**SL-6. The node applies an enrolment only when all of these hold;** otherwise it writes `sensor.enrolled` with outcome `denied` and changes nothing.

- The collector accepted the request.
- `node_spki` is the pin of the node's own link key, read from its key register.
- The generation is one above the last enrolment of that `sensor_id`, or 1 for a new one.
- The sensor's pin is not one the node has revoked (§6).
- The sensor's pin is not one the node holds for a fork (SL-16).
- `not_after` is at most 366 days after the request's `issued_at`. That is the ceiling HR-17's design gives a standing approval, and D1 may set another.

A new enrolment of the same `sensor_id` replaces the old pin at once. **One `sensor_id` has at most one live key.**

**The live enrolments and the revoked pins must not depend on the audit stream alone,** because that stream is pruned (D5 on #624). The node keeps them in durable state that it folds from its C8 records. D5 would use a configuration-class document, as suspensions are kept. The mechanism is P4-4-L3's; the requirement is that a pruned audit stream never brings a revoked pin back or loses a live enrolment.

- *Answers:* replay of an old enrolment; a clone that keeps an old key after a re-key.
- *Test:* SL-T4.

**SL-7. Enrolling and revoking a sensor are grants of their own.** `node.sensor_enrol` and `node.sensor_revoke` are not in `DefaultAdminKinds`. A key signs one only when its pinned list names it (D4-68 rulings 8 and 9), and the grant appears in the chain as `policy.apply` with `admin_keys` before its first use (C8 0.12's ordering rule). A key allowed `node.network_baseline_ack` gains neither, and the reverse.

- *Answers:* AP-14. Whoever can enrol a sensor chooses what the node believes about the network, and whoever can revoke one can blind the site.
- *Test:* SL-T4.

**SL-8. Expiry follows the rules of the node's other TLS links.** The node enforces the enrolment's `not_after`, which an administrator signed, and not the dates the sensor wrote into its own certificate. It raises an expiry alarm from 30 days before, the warning that D4-11 item 3 and `platform/node/README.md` give listeners and forward targets. A running link is not cut at expiry, and its alarm repeats hourly (HR-13). A new dial after `not_after` is refused until a new enrolment. The link agent applies the same date to the node's pin.

- *Answers:* a pinned key that outlives the care taken over it (R8.5).
- *Test:* SL-T5.

**What enrolment does not change.** `network_sensor.evidence_class` must be `simulated`, and `device-observed` is refused (`platform/node/netsensor.go`). An enrolment lifts nothing there. A sensor on a real network needs the owner's authorization and its own gate.

## 4. Binding: one sensor cannot speak as another

**SL-9. The node's configuration names each sensor's address, pin and `sensor_id`, and the node dials only when they equal the live enrolment.** A `network_sensor` entry with no enrolment, or one that differs from it in any of the three, dials nothing and raises an alarm (`sensor-not-enrolled`, a draft name).

- **A missing or mismatched enrolment is an alarm, never a failure at start.** Today a `network_sensor` section that fails its checks fails the node's start (`platform/node/netsensor.go`; D5 on #624). If an enrolment did the same, a sensor's paperwork would stop SER and Syslog collection (SL-20). The section's own shape checks stay as they are.
- **This is also the local way to stop a link.** Editing or removing the entry stops the dial, with no collector and no audit write needed (SL-R2).

- *Answers:* AP-14. A configuration change alone cannot point the link at another machine.
- *Test:* SL-T5.

**SL-10. The authenticated key decides the `sensor_id`; a record's own field never does.** After the handshake, the connection belongs to the one sensor whose pin matched. Its hello (SL-13) must state that `sensor_id` and generation, or the node closes the connection before it reads a record. Every record's `sensor_id` must equal it. A record under any other `sensor_id` is refused, is never stored, is counted (today's `sensor-id` reason, `platform/sensorlink/link.go`), and raises an alarm and a C8 `sensor.link_refused` record. The stream a record is stored in is chosen from the authenticated key, so with several sensors on one node, sensor A's key can never write to sensor B's streams.

- The link stays open after such a record, as C13 keeps it open after any refused record. A sensor that means to lie would not send a wrong ID, so closing gains nothing and loses coverage.
- *Answers:* AP-34 (a): one compromised sensor speaking as another.
- *Test:* SL-T6.

**SL-11. The link agent binds too.** It sends records only on a connection whose client key equals the node's pin. The host firewall admits the link's port only from the node's address. The address is a filter and not an identity: anything on that network can forge it.

- *Answers:* a host on the management network that connects to the sensor to read the site's observations or to feed the agent's parser.
- *Test:* SL-T7.

**SL-12. TLS rules for the link.** TLS 1.3 only. Both certificates are required, and both pins are checked at every handshake against the enrolment in force at that moment. No session resumption and no early data, so a revoked or replaced key cannot ride a ticket from an earlier session. No system roots and no trust by name (HR-15). A handshake timeout. At most one connection for each sensor.

- *Answers:* downgrade; a clone that resumes an old session after a re-key; a slow handshake that holds the dialer.
- *Test:* SL-T8.

## 5. Replay and resume: what C13's channel must carry

These are requirements on `otsec.netobs/0.2` (brief P4-4-L2). D4 chooses the field names and the encoding.

**What TLS already gives.** Bytes recorded from one connection cannot be replayed into another, because each handshake has fresh keys and the sensor signs the new handshake. The rules below are for what TLS cannot see: a sender that holds the key and replays, re-orders, restarts from an old state, or is a copy.

**SL-13. A hello in each direction before any record.**

- Node to sensor: `sensor_id`, generation, and the last position the node committed: run counter, `run_id` and `seq`.
- Sensor to node: `sensor_id`, generation, its run counter, its `run_id`, the first `seq` it will send, the oldest `seq` its buffer still holds, and its clock.

**SL-14. Every record is ordered by (generation, run counter, `seq`).** The link agent keeps a **run counter** on disk. It starts at 1 for each generation and rises by one at each start of the agent, **of the engine or of the capture stage** (D4 on #624): a restarted engine has forgotten the flows that the node still holds open, and the node clears its open-flow table only on a new run. **The agent syncs the counter to disk before it sends the hello,** so a crash after the hello cannot bring the same counter back under another `run_id`, which the node would read as a fork (D5 on #624). `run_id` stays C13's name for a run, and the hello ties it to its counter. The node keeps, for each `sensor_id` and generation, the highest run counter it has accepted, that run's `run_id`, and the last `seq` it committed. It saves them with the commit, so the checks hold across a node restart.

The node refuses the hello, closes the connection, raises an alarm and writes `sensor.link_refused` when:

| Case | Reason | What it means |
| --- | --- | --- |
| The run counter is below the highest accepted | `run-regressed` | An old run replayed, a restored snapshot, a host re-imaged with no new enrolment, or a copy |
| The run counter equals the highest, with another `run_id` | `run-forked` | Two holders of one key: a copy |
| `sensor_id` or generation differ from the enrolment | `binding` | A stale or wrong enrolment at the sensor |

- **Within a run,** `seq` rises by one from the hello's first `seq`. A `seq` at or below the last one taken in this connection is refused (today's `seq` reason), so a re-ordered stream cannot pass. On a resumed run, a `seq` at or below the last committed one is a resend: it is dropped and counted as a duplicate, and never stored twice.
- **A gap** is counted, as today (`SeqGaps`). It must be matched by drops that the sensor declares in its next heartbeat. A gap the sensor does not declare raises an alarm, because a loss nobody owns is how a record is made to vanish (P5). Declaring a gap needs a counter of the numbered records evicted from the agent's buffer, which is asked of C13 0.2 (D4 on #624).
- **Records left from the previous run** need a rule in C13 0.2: they are flushed before the next run's hello, or declared lost in it. Either way, no record of an older run follows a newer run's hello.
- *Answers:* AP-34 (a) by replay; a cloned or rolled-back sensor.
- *Test:* SL-T9.

**SL-15. The node acknowledges what it has committed, not what it has received.** The acknowledgement names a run and the highest `seq` committed to the store. The link agent trims its buffer only up to it. After a break, a continuing run resumes from the acknowledged `seq` plus one. Records that fell out of the buffer are lost, declared and counted. This is the lesson of C-04 and E-01: an acknowledgement is worth what the receiver had made durable.

- *Test:* SL-T9.

**SL-16. A re-image and a copy.**

- **A re-image destroys the key** (SL-1), so the host needs a new enrolment at the next generation, and its run counter starts again at 1 under it. The node's own stream numbers carry on, and the detector's checkpoint counts in those, so nothing on the node resets. The open-flow table is cleared, as on any new `run_id` today.
- **A re-image that keeps the key** (a TPM-held key) loses the run counter, so the node refuses it as `run-regressed` until an administrator enrols it again. That is deliberate: a re-image is an event a person attests to.
- **A copy** holds the same key and the same state. The node cannot tell a copy's first connection from the original's restart. It can tell once both have connected: the second arrives with a counter the node has already seen, under another `run_id`. On `run-forked` the node stops dialling that sensor and holds the link until an administrator enrols it again **with a new key**, or revokes it, because one of two key holders is false and the node cannot tell which. Enrolling again with the same key would leave the copy in place, so the node denies it (SL-6; D5 on #624).
- **What a fork costs.** The network at that sensor is unwatched from the hold until someone makes a new key on the sensor host, which is a visit to the site. The coverage gap is recorded and the alarm stands for all of it. The sync of the run counter before the hello (SL-14) is what keeps an honest crash from causing one.
- **Residual.** A copy that always moves its counter forward is accepted until the original shows up. Against a stolen key only revocation helps (§6). A TPM-held key removes copies made from a disk or an image (O-2). A sensor that is a virtual machine can be copied by a snapshot (O-9).
- *Test:* SL-T9.

**SL-17. Time and late records: constraints for P4-4-L2 and P4-4-L3.** The bounds are theirs to set. D3's constraints:

- The node never orders, prunes or expires anything by the sensor's clock. It adds its own received time, as today.
- A sensor clock outside the skew bound raises the skew alarm. While it is outside, a tie between an observation and one of the node's own sessions (AP-35) is not made: the flow is judged untied, which alerts. Skew must never suppress. Every scheduled session then alerts for as long as the skew lasts, so those alerts are aggregated, with the skew alarm naming the cause, and they do not fill the alert class (D5 on #624; how is P4-4-L3's).
- A backlog after an outage may delay an alert, and never suppresses one. The hold for the node's own sessions stays bounded while it waits for a backlog, as AP-35 requires today.
- The node does not serve time to the sensor. That would be an inbound port on the node (SL-18) and a second channel to the sensor (SL-19).
- *Answers:* AP-35. A sensor whose clock is wrong, by fault or on purpose, moves observations into or out of a session's window.
- *Test:* none in this note. P4-4-L3 names it (its items 4 and 5), with the gate's skew-alarm line.

## 6. Revocation

**SL-R1. `node.sensor_revoke` is admin-signed and names the `sensor_id`, its generation and pin, a reason, and optionally `suspect_from`:** the time from which the administrator no longer trusts what the sensor sent. Absent, it means from enrolment.

**SL-R2. It closes the link at once, before the node's own record.** D1 kept this order as the fail-closed one (ruling on #624). Once the collector has accepted the request, the node saves the revoked state, closes the connection and stops dialling, and then writes C8 `sensor.revoked`. For every other admin decision the node's record comes first, and a failed write stops the decision (D4-68 ruling 9). Here that order would keep a revoked sensor trusted, which is failing open.

- **Audit before act still holds.** D1-11 (`docs/phase1/A1-decisions.md`) is the rule that collection which uses a credential stops when its audit record cannot be written. SL-R2 does not break it: a revocation uses no credential, and the collector's decision is in the audit chain, as `collector.request`, before the node acts on it (D5 on #624).
- **If the node's own write fails,** the link stays closed, status shows the record as owed, and the node writes it once when the chain accepts writes again.
- **If the revoked state cannot be saved,** the dialer for that sensor stays off for the rest of the run, and at its next start the node derives the state again from the decision in the chain.
- **What a revocation still needs.** It waits for the collector, and it cannot be recorded while the audit store is full. The protective path that needs neither is the local one: an edited or removed `network_sensor` entry stops the dial (SL-9). That revokes nothing and marks nothing, and the signed revocation follows when it can be made.

**SL-R3. Records already stored are kept, and marked.** Nothing is deleted: they are evidence. The store is append-only, so the mark is not written into them, and it needs no rewrite: a reader applies it from each record's commit time and the `through_seq` (D5 on #624). `sensor.revoked` carries, for each of the sensor's streams, the last committed `seq` (`through_seq`), with `suspect_from`. Every reader (status, an export, a screen later) shows that sensor's records at or below `through_seq` and committed at or after `suspect_from` as coming from a revoked sensor. The node also commits a health event to the health stream, not to the sensor's alert stream (D5 on #624), so an upstream collector sees the revocation in a stream it already receives. **Records held at intake when the revocation lands are committed before `through_seq` is taken,** or they would land above it unmarked. None is dropped silently.

**SL-R4. Later records are refused.** The node never dials a revoked pin again. A revoked pin can never be enrolled again, under any `sensor_id`. The next enrolment of that `sensor_id` carries a higher generation and another key.

**SL-R5. The network baseline is acknowledged again.** From `sensor.revoked`, the acknowledgement of that sensor's baseline is void. After a new enrolment, the rules that need an acknowledged baseline do not run for that sensor until a person signs `node.network_baseline_ack` again. Whether they sign the old document or learn a new one is their judgement, and the administrator's client must show whether the learning period overlaps the suspect period. While the acknowledgement is void and the sensor is feeding, the node shows a standing alarm, so the weaker detection is never silent. No administrator's client exists yet, so the overlap view is a requirement on one (as HR-14 is). **This rule also rests on something that is not built:** the node does not yet apply `node.network_baseline_ack` (D5 on #624; at `1f5b307f` no file under `platform/` or `cmd/` outside the tests names `netack`).

**SL-R6. A re-key with no compromise is not a revocation.** A new enrolment of the same `sensor_id`, with reason `rekey` and a new key, replaces the old pin at once (SL-6), and the acknowledgement stands. That gives the enrolment grant nothing new: a sensor can lie about traffic under any baseline, and a baseline can only be widened by `node.network_baseline_ack`, which is another grant (SL-7).

**SL-R7. Nothing is sent to the sensor.** The link carries no revoke command (SL-19). The node stops trusting, which is all that safety needs. What is done with the machine is a site procedure (O-4).

**SL-R8. If the node's own link key is lost or replaced,** every sensor of that node is enrolled again at its console, at the next generation.

- *Answers:* a compromised or stolen sensor host (AP-34 (a), HR-21); a baseline learned through a sensor that was already false (AP-36 (a)).
- *Test:* SL-T10, and SL-T20 for SL-R8.

## 7. Direction, and what the link carries

**SL-18. The node opens the link and gains no inbound port.** It dials each sensor as it dials its forward targets, and its firewall allows that one destination. The link agent's listener is bound to the sensor host's management address only: never a wildcard address, and never the monitoring interface, which has no address. It is closed until the sensor is enrolled (SL-4).

- *Answers:* AP-34 (1). Nothing on the station LAN can reach the channel, and enabling a sensor adds no way into the node.
- *Tests:* SL-T11, SL-T7.

**SL-19. The link carries the sensor's C13 records and the node's acknowledgements, and nothing else.**

- Sensor to node: the hello, heartbeats and observations.
- Node to sensor: the hello and acknowledgements.
- Each end decodes strictly from a closed set, and treats the other as hostile input. The node's messages to the sensor are small and bounded, and carry no text.
- **An acknowledgement's only effect is to move the agent's trim cursor,** as TB5 limits a RELP response to moving the forwarding cursor. An acknowledgement for another run, or above the highest `seq` sent, is counted and closes the connection.
- **No command and no configuration reaches the sensor over the link:** no rule or baseline, no capture filter, no time, no update, no restart, no request for logs or ring files. The link agent has no code path from a link message to anything but the trim cursor.
- *Answers:* AP-7's shape, one hop down. A compromised node that could configure its sensors could switch off redaction, load a rule that transmits (AP-32), or use them as a foothold beside the station LAN. With this rule a compromised node gains nothing on the sensor host, and a compromised sensor gains nothing on the node beyond lying (AP-34 (b)).
- *Consequence.* The sensor's settings change only through the signed update (SL-25) or at the console (SL-23). The node learns them from the coverage statement, and `sensor-coverage-mismatch` is its check.
- *Asked of C13 0.2* (D4 on #624): a digest of the effective configuration in the coverage statement, over the engine's scripts, the allow-list, the redaction slots and `prp_window_ms`. A local edit that switches redaction off then shows at the node as a digest it does not expect. Like the rest of the coverage statement it is the sensor's own word, so it shows an edit and not a compromise (AP-36).
- *Test:* SL-T12.

**SL-20. A sensor that is cut, blind or flooding must never stop SER or Syslog collection.** The separate store classes and quotas exist (C5 0.9). No flood over a network link has run (D3 on #618). Under option (b) the dialer and the reader add their own bounds: the frame cap (64 KiB, C13), a read deadline, bounded memory for each link, and a redial back-off. P4-4-L3 item 8 names the test.

Four things P4-4-L3 must keep (D5 on #624):

- a missing or mismatched enrolment is an alarm, never a failure at start (SL-9);
- sensor work stays off the scheduler's tick, or is bounded there, so a slow link cannot delay collection;
- `sensor.link_refused` stays capped by time (§11.2), because a full audit store stops credentialed collection (D1-11, V-S9, `TestAuditFullSendsNothing`);
- a sensor's faults stay inside the `network` database.

- *Answers:* AP-19, AP-34 (5).
- *Test:* SL-T13, which is P4-4-L3's.

## 8. Secrets on the sensor

**SL-21. The sensor host holds no platform credential.** No device credential, which stay with the collector alone. No node key. No administrator's private key. No credential for a forward target, for central or for the advisory set. It holds its own link key, and public values: the two pins and one administrator public key.

- *Answers:* AP-1. The sensor host parses hostile input in C and C++ (AP-30), so whatever it held would be the first thing lost.
- *Test:* SL-T14.

**SL-22. No unredacted secret is at rest on the sensor host, and none is sent.** Two measures cover it, because one cannot. D4-67's redaction by position, with D4-68 ruling 13, works on frames. It cannot reach an engine's log fields, because the engine decodes the unredacted bytes (D4 on #624). So frames are covered by the redaction, and the engine's output by an allow-list that the link agent enforces:

| Place | Rule |
| --- | --- |
| **The capture ring** | Written with the redaction already applied, as AP-33 (3) and D5's note §4 say. It is optional, its size is the owner's to set, and zero is allowed (O-11). |
| **The engine's own logs** | An allow-list, not a deny-list, **enforced at the link agent** and not trusted to the engine's configuration. The engine writes to bounded, memory-backed storage only. The agent takes only the listed fields of the listed streams, and refuses and wipes any stream that is not listed. D3's review of #618 named Zeek's SNMP community field. Where a Telnet password ends up in an engine's default output is `unknown`, and so is every other field, because no engine document was read: E-D4-03 searches every engine output over GT-PCAP's secret cases (P4-4-S2). **Assumptions:** that an engine's output can be closed to such a list, with no secret left in a listed field; and that the engine's logs and temporary files can be kept in memory-backed storage. E-D4-03 decides the first, and E-D4-03 with SL-T15 the second. |
| **The link agent's buffer** | If it is kept on disk, it holds only C13 records as they will be sent: frames already redacted, and allow-listed fields. It is bounded, and it is in SL-T15's search. |
| **Temporary files** | A private, memory-backed directory for each of the three programs. |
| **Swap** | None. No swap device or file, and no hibernation. |
| **Core dumps** | Off for the capture stage, the engine and the link agent, and no kernel crash dump. A crash is counted, and is never written out. |
| **The system log** | The link agent never logs record bytes. The engine's standard output and error can hold text from packets, so they go to a bounded, memory-backed log. |
| **The link** | C13 records only (SL-19), whose cited frames are already redacted. |

- **A slot that cannot be placed fails closed and is counted,** as D4-67 rules: the bytes of the side that carries it are not written anywhere, and C13's `logins_not_placed` counter shows it in the heartbeat.
- **Redaction cannot be switched off in anything a site could run** (D1's ruling on #624). SL-T15's control for frames switches redaction off for one named slot. That switch exists only in a test-only build of the capture stage, which is the program that redacts (SL-3), and it is set in the rig's own configuration. The site's binary does not contain it: its strict configuration reader refuses, at start, a configuration that names the switch, and a build check shows that the switch is absent from the site binary. SL-T15 shows the refusal. **What this does not stop:** root on the sensor host can still run a test build. That is an edit of the host, and what shows it is the configuration digest seen at the node (SL-19; D4 on #624 at `ca96b813`).
- **What this does not cover.** Live packets in memory hold every cleartext secret on the mirrored segment, and root on the sensor host reads the wire in any case. That is HR-21, and no rule here closes it.
- *Answers:* AP-33, HR-19. A stolen or copied sensor disk, a log shipped for support, or a crash file must not hand over the passwords of the site's devices, the platform's own Level 1 password among them (HR-1).
- *Test:* SL-T15.

## 9. The management side of the sensor host

Every rule in this section is a requirement on the host. None is built, and several depend on choices that are the owner's (§10).

**SL-23. Who may log in, and how.** Named accounts, one for each person, and no shared account. No password login over a network. No login from the node: the node holds no credential for the sensor host (§1). No login from the station LAN: the monitoring interface has no address. Whether a network login exists at all is O-5.

- *Answers:* HR-21. Root on the sensor host is a position on the mirrored traffic of the whole site.
- *Test:* SL-T16.

**SL-24. Physical custody.** Whoever can touch the sensor host can take its disk (the ring, and the link key if it is a file), start another system on it, or attach to its ports. The requirements are a locked enclosure, a firmware password with a verified start-up chain, and unused ports off. Who holds the key to the enclosure, and whether the disk is encrypted and how it unlocks, are O-3 and O-4. A replaced or rogue box holds no enrolled key, so the node refuses it (SL-4).

- *Answers:* AC-12's position, moved to the sensor.
- *Test:* an H-row. It needs a machine.

**SL-25. The update path makes AP-10's three refusals.** The sensor host must refuse a tampered package, a package below its anti-rollback floor, and an unsigned package. This holds for the engine, its packages, the project's own sensor programs and the base system. **Not built: no signed release exists, and no updater for the sensor.** Which key signs, and who builds the image, depend on O-7.

- *Test:* SL-T17.

**SL-26. Does AP-31 cover the sensor host? Yes, re-read for Linux,** and the threat model's AP-31 row now says so.

- **AP-31 (1), pinned and never fetched,** applies in full and to more than a driver: the engine, each engine package (ICSNPP) and the project's sensor programs are at pinned versions, carried by a signed release, listed in an SBOM, and never fetched at install or at run time. **Nothing is fetched at run time** means the sensor host has no route to the internet and no name resolver, and the engine's own fetchers are absent or off: its package manager (`zkg`, ADR-0009), any feed download, and any version check. D7 raised this on #618. **Assumption:** that the engine runs with no route and no resolver. Under SL-3 it has neither by construction, in an empty network namespace, and E-D4-03 shows whether it runs so.
- **AP-31 (2), capture rights for the sensor's account only,** becomes: `CAP_NET_RAW` is granted to the capture stage's unit alone, never to the engine, and it is dropped once the capture socket is open.
- **AP-31 (3), receive only,** is AP-32's subject. One point must be plain. **Assumption:** on Linux a packet socket needs `CAP_NET_RAW` to be created, and an open one can still send after the capability is dropped. If so, dropping the capability stops the opening of new sockets, and does not stop the holder of an open one from sending on it. That is why SL-3 gives the socket to the project's own capture stage, which calls no send function, and gives the engine, which parses the hostile bytes, no socket at all. The capability drop is a second measure, and never the only one. P4-4-R1's C-11 rig, with its `PACKET_QDISC_BYPASS` sender, decides the assumption.
- **The Windows driver text** of AP-31 applies only if option (a) or (c) is reopened.
- *Test:* SL-T18, and R1's `CAP_NET_RAW` case.

**SL-27. Management that sits below the operating system.** A board management controller or Intel AMT on the sensor host is access below every rule above (AP-24). It must be absent, off, or on the management network only. **The monitoring interface is never a port shared with out-of-band management,** because such a controller transmits on its port whatever the operating system is told, which breaks C-11 below the level any test in CI can see. This is ADR-0007 item 8's rule for the node, applied to the sensor.

- *Test:* an H-row. It needs the machine.

**SL-28. The sensor host is not a bridge.** It forwards nothing between its management interface and its monitoring interface, and nothing between two monitoring interfaces. A host attached to both LANs of a PRP network could otherwise join the two networks whose independence protection relies on (P1, AP-16's shape). Against a compromised host, only the attachment holds (AP-32 (1), O-1).

- *Test:* SL-T19.

**SL-29. The time source reaches the sensor host on its management interface only.** A PTP or NTP client on the monitoring interface would transmit there. Which source the site gives is O-10. The node's skew check (SL-17) is the control that does not depend on the answer.

- *Test:* the C-11 rig (P4-4-R1). A time client on the monitoring interface shows as frames from it, so C-11's zero-frames test, with its negative control, covers this rule (D6 on #624 at `ca96b813`).

## 10. Choices that are the owner's

D3 decides none of these. D1 brings them to the owner, with the recommendation on the sensor's host that D4-86 already owes them.

| | Choice | Options, and what each costs in risk |
| --- | --- | --- |
| O-1 | **How the sensor attaches at each site** | **A TAP:** receive-only by construction. **It is the only option that holds against a compromised sensor host,** until an H-row shows otherwise for a switch model. It costs hardware for each monitored link, and one for each LAN on PRP. **A mirror port:** it **counts as one that accepts ingress until an H-row shows, for that switch model, that it refuses it** (D6 on #624). C-11 then rests on the sensor host's software alone, and a compromised host can send onto the station LAN (AP-32). D2 reads the SEL switches' mirror port as taking no ingress during a mirror session (`desk`, D2 on #618; not shown on hardware), and nothing relies on that reading. A mirror port needs a change to the switch's configuration, and the H-row needs a switch: each needs the owner's authorization. **A mirror port shown by its H-row to refuse ingress:** holds against a compromised host as far as that switch model does. |
| O-2 | **Where the sensor's private key rests** | **A TPM-held key:** root can use it and cannot copy it (an assumption, SL-3), and a copied disk or image is not a second sensor. It needs hardware with a TPM. **A file:** a stolen or copied disk is a working copy of the sensor until it is revoked (SL-16). |
| O-3 | **Disk encryption on the sensor host** | **None:** a stolen disk gives the ring, the configuration and a file-held key. **Unlocked by the TPM:** restarts unattended, and protects a disk taken alone, not a whole box that is taken and started. **Unlocked by a person at each start:** protects the whole box, and every power loss is a coverage gap until someone attends. |
| O-4 | **Physical custody** | Who holds the key to the enclosure, whether it is the node's cabinet or the network cabinet beside the switch, and whether contractors enter it. The network cabinet is closest to the mirror port and is opened by more people. Also: what is done with a revoked or retired machine. |
| O-5 | **Remote login to the sensor host** | **Console only:** the least remote surface, and every change or patch is a site visit, so patches come late (AP-30). **SSH from one named management host, with a key for each person:** patches arrive on time, and that host and those keys become part of the sensor's trust. **The owner's existing remote-management tool:** adds that tool, and whoever runs it, to the same trust. |
| O-6 | **The network between the node and the sensor** | **A cable of its own between the two:** nothing else can reach the link agent's listener or sit on the link's path. It needs a spare port on each machine, and management and updates then come by the console or by media. **The site zone's network:** no extra port, and every host in that zone can reach the listener's port (SL-11 and SL-12 are then the only walls). |
| O-7 | **Who builds and patches the sensor's image** | **The project ships an image:** one signed release covers the engine and the base system, AP-10's refusals are the project's to build, and the project becomes the distributor of everything in the image (D7 on #618). **The site installs the system and the engine:** the distribution's own update channel and keys become a trust anchor on the sensor host, and the pins of AP-31 (1) rest on the site's procedure. Either way, someone must patch a host that parses hostile traffic in C and C++, and the risk of AP-30 grows with every month it is not patched. Also: which distribution, and how long it is supported. |
| O-8 | **Out-of-band management on the hardware** | **Hardware without it:** nothing to configure. **Present and off:** rests on a firmware setting. **Present on a port of its own on the management network:** a second way into the host, with its own credentials (SL-27). |
| O-9 | **A physical machine or a virtual one** | **Physical:** as above. **Virtual:** the hypervisor's administrators are root on the sensor, a snapshot is a copy (SL-16), and C-11 rests on the virtual switch as well. |
| O-10 | **The sensor host's time source** | The site's NTP server, authenticated or not, or a clock signal. An unauthenticated source can be forged from the management network. The node's skew alarm is the check in each case (SL-17). |
| O-11 | **The capture ring on the sensor** | Its size, zero included. A ring gives packets beyond the eight an observation cites. It sits on a host the platform cannot audit: whoever can log in to the sensor host can read it, and AP-33 (2)'s audited read covers the node's store only. |
| O-12 | **On PRP: one host with two monitoring ports, two hosts, or one LAN only** | **One host:** one machine sees both LANs and, if compromised or misconfigured on mirror ports that accept ingress, could join them (SL-28). **Two hosts:** twice the hardware and patching, and no single machine touches both. But the PRP discard cannot run, because no stage sees both copies, so the node gets each flow twice under two `sensor_id`s (D4 on #624); what the node does with them is for C13 0.2 and P4-4-L3. **One LAN only:** one host and one port, nothing touches both LANs, and no discard is needed. Traffic that is on the other LAN alone is not seen, and the coverage statement says so. Each sensor has its own key and `sensor_id` under all three (SL-1). |

## 11. Proposals for C7 and C8

These are proposals for D1's approval with D4, D5 and D6. No file under `contracts/` changes in this brief.

### 11.1 C7 0.11 (`otsec.authz/0.11`)

Two admin-signed kinds, gated at minor 11 in `kindSince`, added to `adminKinds`, and **not** added to `DefaultAdminKinds` (SL-7). The payload format stays `otsec.authz.admin-request/0.4`, as for every kind since 0.5: an older reader refuses the new body as a payload error.

```go
KindNodeSensorEnrol  RequestKind = "node.sensor_enrol"
KindNodeSensorRevoke RequestKind = "node.sensor_revoke"

// NodeSensorEnrolBody (since 0.11) pins one sensor and this node to each other.
type NodeSensorEnrolBody struct {
	SensorID      string `json:"sensor_id"`      // lowercase UUID, drawn by the administrator's client
	Generation    string `json:"generation"`     // decimal from 1; one above this sensor_id's last enrolment
	SensorSPKI    string `json:"sensor_spki"`    // "sha256:" and 64 hex digits, over the sensor key's SubjectPublicKeyInfo
	SensorAddress string `json:"sensor_address"` // an IP literal and a port; never a hostname
	NodeSPKI      string `json:"node_spki"`      // the node's link key, the same form
	NodeAddress   string `json:"node_address"`   // an IP literal: the source the sensor admits
	NotAfter      string `json:"not_after"`      // RFC 3339, UTC; at most 366 days after issued_at
	Reason        string `json:"reason"`         // "new", "rekey", "renew" or "replace"
}

// NodeSensorRevokeBody (since 0.11) ends trust in one enrolment.
type NodeSensorRevokeBody struct {
	SensorID    string `json:"sensor_id"`
	Generation  string `json:"generation"`
	SensorSPKI  string `json:"sensor_spki"`
	Reason      string `json:"reason"`                 // "compromised", "lost" or "retired"
	SuspectFrom string `json:"suspect_from,omitempty"` // RFC 3339, UTC; absent means from enrolment
}
```

- **The collector** checks the shape only, as it does for `node.network_baseline_ack`: it does not know the node's sensors. Signature, the key's kinds, the nonce, the window and the numbering are as for every admin kind. A refusal names no target.
- **The node** applies an accepted request under SL-6 or SL-R2 to SL-R4.
- **A verification without a collector.** The link agent checks an enrolment's signature (SL-5 step 6) with none of the collector's state. That needs an exported function that makes the envelope, key, signature and payload checks and returns the decoded request, without the binding, window and replay checks. Its documentation must say that it is for the sensor's end only. **An import test must show that neither of today's product binaries, `cmd/otsec` and `cmd/otsec-collector`, can reach it** (D1's ruling on #624), so it belongs in a package that only the sensor's program imports.
- **Schema and goldens:** `schema/admin-request.json` gains the two kinds and bodies, with one golden of each.

### 11.2 C8 0.13 (`otsec.audit/0.13`)

Three actions, written by the node, gated at minor 13 in `actionSince`. The target is the sensor (`Target.sensor_id`, since 0.12). Readers go before writers, as #532 §7 set.

| Action | When | Carries | Outcome |
| --- | --- | --- | --- |
| `sensor.enrolled` | Before the node records an enrolment (SL-5 step 5) | `decision_seq` and `payload_sha256`, as the acknowledgement records carry them; a `sensor` object with the body's fields, and `previous_generation` and `previous_spki` when it replaces an enrolment | `succeeded`, or `denied` with a reason code: `generation`, `revoked-key`, `forked-key`, `node-key` or `not-after` |
| `sensor.revoked` | After the link is closed (SL-R2) | `decision_seq`, `payload_sha256`, generation, pin, reason, `suspect_from` when given; `streams`, each stream of the sensor with its `through_seq`; `baseline_digest`, the acknowledgement it voids, when there is one | `succeeded`, or `denied` when the node holds no such enrolment |
| `sensor.link_refused` | A peer failed authentication or binding | generation; a reason from a closed set: `peer-key`, `binding`, `run-regressed`, `run-forked`, `sensor-id`, `expired`; `count`, the refusals since the last record of that reason | `denied` |

- **`sensor.link_refused` is capped twice: by stretch and by time.** It is written at most once for each sensor and reason in a stretch, and a stretch ends at the next accepted hello. That alone is not a bound, because an enrolled sensor produces accepted hellos at will (D6 on #624). So it is also written **at most once an hour for each sensor and reason,** on the node's monotonic clock: with six reasons, at most six records an hour for each enrolled sensor, whatever the sensor or anyone at its address does. **A restart does not start the hour again** (D5 on #624 at `ca96b813`). A sensor cannot restart the node. But if it could make the node crash, the service manager would start it again after 60 s, and a cap that began afresh at each start would allow about 8,600 records a day for each sensor. So at start the node takes each reason's last record time from the audit chain, which it already reads at start, and holds the cap from that time. That one comparison is on the wall clock, because a record's time is all that survives a restart; within a run the monotonic clock holds. Refusals past the cap are counted in health and status, and the next record's `count` carries them.
- **Why the cap is a safety matter.** A full audit store stops credentialed collection (D1-11, V-S9, `TestAuditFullSendsNothing`). Without the time cap, a compromised sensor could fill the audit class and stop SER collection, against SL-20 and the gate. SL-T13 has a leg for it.
- **The other two actions cannot be driven by a sensor.** `sensor.enrolled` and `sensor.revoked` follow an admin-signed request that the collector accepted, and its nonce is spent once.
- **A link that opens or closes is not an audit record.** The node's `sensor.coverage-gap` health events record it (D5's note §1), and a reconnect loop would otherwise write to the chain at will.
- **Chain checks** (`VerifyChain`), as far as a view shows:
  - a succeeded `sensor.enrolled` carries a generation one above that sensor's last succeeded enrolment;
  - after `sensor.revoked`, no later `sensor.enrolled` succeeds with that pin, under any `sensor_id`;
  - C8 0.12's rule for `admin_keys` covers both kinds as it stands: a decision is applied only under a `policy.apply` that shows the signing key holds the kind.
- **A reader's rule, not a chain break:** a `config.baseline_acknowledged` of kind `network` that precedes the latest `sensor.revoked` for its sensor is not in force (SL-R5).
- **Schema:** `schema/record.json` gains the three actions, the `sensor` object, `streams` and the reason codes.

### 11.3 Not a contract: the alarms

The node's alarm codes are D5's to name with P4-4-L3. This note uses draft names only: `sensor-not-enrolled`, a sensor-identity alarm (SL-10), a clone alarm (SL-16), an undeclared-gap alarm (SL-14), a void-baseline alarm (SL-R5), and the expiry alarm (SL-8). `sensor-blind` and the skew alarm are already in D5's brief.

## 12. The tests

Each is a case for D6's rig (P4-4-R1) or a contract test. "Control" is the change that must make the test fail. Where a row says H-row, only a machine can show it, and nobody runs it without the owner's authorization.

**The sensor needs a root file system of its own in the rig** (D6 on #624). Without one, SL-T1, SL-T14, SL-T15 and SL-T16 search the runner's file system and mean nothing.

| Test | Shows | How | Control | Where |
| --- | --- | --- | --- | --- |
| SL-T1 | SL-1 | Install the link agent twice from one image in two namespaces: the two pins differ. Search the image for a private key: none. | An image with a key baked in is found by the search. | Rig |
| SL-T2 | SL-3 | From the engine's account and from the capture stage's, opening the key file fails. The engine holds no packet socket, and its network namespace has the loopback interface only and no route. A link check finds no send or inject call in the capture stage. | Run the engine under the agent's account: the open succeeds. Start the engine in the host's namespace: the interface check fails. | Rig |
| SL-T3 | SL-2, SL-4, SL-5 | (a) A sensor with no enrolment has no open port. (b) A node with a `network_sensor` entry and no enrolment sends no SYN and raises its alarm. (c) A peer with another key at the enrolled address fails the handshake, no record is accepted, and `sensor.link_refused` (`peer-key`) is written. | A node that takes the first key it sees accepts (c). | Rig, over the real link |
| SL-T4 | SL-5 to SL-7 | A key without `node.sensor_enrol` in its list is refused (`authority`), and so is a key that holds only `node.network_baseline_ack`. An enrolment with a skipped or repeated generation, a revoked pin, or another node's pin is `denied`. The agent refuses an enrolment that names another key, a lower generation, or a bad signature. An import test: neither `cmd/otsec` nor `cmd/otsec-collector` can reach the verifier for the sensor's end. | The kind added to `DefaultAdminKinds` makes the first case pass. An import of the verifier added to the node fails the import test. | Contract tests; rig for the agent |
| SL-T5 | SL-8, SL-9 | Change the address, the pin or the `sensor_id` in the configuration after enrolment, one at a time: no SYN leaves and the alarm is raised; restored, the node dials. A node started with a missing or mismatched enrolment starts, collects SER and Syslog, and raises the alarm. On the test clock: the expiry alarm 30 days before, a running link kept past `not_after`, and a new dial after it refused. | A node that dials from its configuration alone passes none of the first part. | Rig; node tests on the test clock |
| SL-T6 | SL-10 | Two enrolled sensors, A and B. The test-only C13 source, with A's key, sends a record under B's `sensor_id` on A's link: B's streams do not change, A's refusal count rises by one, and the alarm and `sensor.link_refused` (`sensor-id`) follow. | A node that files a record by its own `sensor_id` field stores it in B's stream. | Rig, over the real link (gate) |
| SL-T7 | SL-11, SL-18 | A client with another key, from the node's address: the handshake fails at the sensor and no record byte is sent. From a third address: the firewall refuses. The listener is not bound to a wildcard address, and nothing listens on the monitoring side. | A listener on a wildcard address is found by the bind check. | Rig |
| SL-T8 | SL-12 | A peer that offers TLS 1.2 is refused. A second connection that offers resumption makes a full handshake or fails, and is never resumed. After a re-key, the old key is refused on its next handshake. | Session tickets on: the resumption case passes with the old key. | Rig |
| SL-T9 | SL-13 to SL-16 | (a) A link cut in a run and resumed: every record is in the store once, in order. (b) An earlier run's stream replayed by the test source: `run-regressed`, nothing stored. (c) Records of the current run sent again: dropped as duplicates. (d) A re-ordered stream: the earlier `seq` refused. (e) A second source with the same key and counter and another `run_id`: `run-forked`, and the link is held. (f) A gap the sensor does not declare: the alarm. (g) After a node restart, (b) and (c) still hold. (h) A connection's recorded bytes replayed at the node's next dial: the handshake fails. (i) After (e), an enrolment with the same key is `denied` (`forked-key`), and one with a new key is dialled. (j) The agent killed just after its hello and started again: a new run, and no fork. (k) The engine restarted alone: the run counter rises. | A node that keeps no run counter accepts (b) and (e). An agent that sends its hello before it syncs the counter turns (j) into a fork. | Rig, over the real link (gate: "a replayed stream is refused") |
| SL-T10 | SL-R1 to SL-R6 | Revoke over the real link: the connection closes within the rig's bound and no SYN follows. `sensor.revoked` is in the chain with each stream's `through_seq`. The earlier records are still stored, and the reader reports them marked. The same pin enrolled again is `denied`. A new key at the next generation is dialled. The baseline's rules stay off and the standing alarm is up until a new acknowledgement. With the audit write made to fail, the link still closes and the record is written later. **With the node killed between the close and the write:** after the restart the link stays closed, the record shows as owed, and it is written once. With records held at intake when the revocation lands: each is at or below `through_seq`. A re-key keeps the acknowledgement. The legs on the baseline wait until the node applies `node.network_baseline_ack`. | A node that applies the revocation only after the audit write keeps the link open when the write fails. | Rig (gate: "a revoked one") |
| SL-T11 | SL-18 | The node's listening ports are the same set with sensors configured and without. From the sensor's namespace, no port on the node answers beyond that set. | A node built with a listener for sensors shows a new port. | Rig (gate: "no inbound port") |
| SL-T12 | SL-19 | Messages from the node's side that are of an unknown type, oversized, shaped like a setting, or an acknowledgement above the highest `seq` sent: the sensor's configuration, its rule set and its interface state are unchanged, the message is counted, and the connection closes. A contract test pins the closed set of message types in each direction. A redaction slot switched off by a local edit on the sensor changes the configuration digest, and the node raises `sensor-coverage-mismatch`. | An agent that accepts a setting changes its configuration. A digest that leaves the redaction slots out does not change. | Rig; contract test |
| SL-T13 | SL-20, §11.2 | P4-4-L3 item 8's test: a flood, a cut and a blind sensor over the real link while SER and Syslog run, with no loss and no drop in their throughput. **The audit leg:** with a small audit class, a sensor that alternates accepted hellos with refused ones for longer than the cap's hour, under every reason it can cause: the `sensor.link_refused` records stay within the cap, the audit store does not fill, and SER collection goes on. **With the node restarted repeatedly under the same flood,** the count still holds. | For the audit leg: with the time cap removed, the audit class fills and credentialed collection stops; and with a cap that begins afresh at each start, the restart leg exceeds the count. For the flood: D3 proposes the observation class's quota check removed, so that the flood takes the volume; D5 may name a better one with P4-4-L3. | Rig (gate) |
| SL-T14 | SL-21 | A search of the sensor host's whole file system for every test secret of the platform's run finds none: the device passwords, the USM keys and the administrators' private test keys. | A test credential planted on the sensor host is found. | Rig |
| SL-T15 | SL-22 | Replay the GT-PCAP cases that hold third-party test secrets in every slot through the real sensor. Then search its file system, its memory-backed directories, the ring, the agent's buffer, the system log and the link's bytes as the node reads them. The image's configuration names no swap and no dump target. After a forced crash of the capture stage, of the engine and of the agent, no dump file exists and the search is still clean. A secret planted in the ring's directory is found in every run, which shows that the search sees the ring at all. **The refusal:** the build a site would run, started on the rig's configuration with a redaction slot off, refuses to start, and a build check finds the switch absent from that binary. | **Two controls, one for each half of the search** (D1's ruling on #624). **(1) The engine-output half:** the allow-list is widened to pass a stream that is not listed. That stream must then carry the planted secret to where the search finds it, which shows that the allow-list is what kept it out (D4). **(2) The frame half, the ring and the link's bytes:** redaction is switched off for one named slot, in the rig's own configuration and never in a build a site could run. The search must then find the secret in the ring and on the link, which shows that redaction is what kept it out (D6). For the refusal: a build that honours the switch outside the rig starts, and the leg fails. | Rig (gate: AP-33's key search); an H-row for swap and the kernel crash dump on a running machine |
| SL-T16 | SL-23 | On the built image: no account has a password that a network login accepts, no account is shared, and nothing listens on the management interface but the link's port and whatever O-5 allows. | An image with a password login is found. | Rig for the image; an H-row for the machine |
| SL-T17 | SL-25 | The updater refuses a tampered package, one below the floor and an unsigned one, and installs a good one. | Each refusal removed in turn. | Not possible until an updater exists |
| SL-T18 | SL-26 | With no route out of the sensor's namespace, a full replay runs, and the capture of the management interface shows the link's traffic only: no name lookup and no other connection. The installed versions equal the pins. | A sensor set to fetch a package shows the attempt. | Rig |
| SL-T19 | SL-28 | With two monitoring interfaces and the management interface in three namespaces, a frame sent into one never appears on another, and forwarding is off. | Forwarding switched on shows the frame. | Rig; O-1 decides what holds on a machine |
| SL-T20 | SL-R8 | The node's link key is replaced. The sensor refuses the node's handshake and sends no record. An enrolment that names the old node pin is `denied` (`node-key`). After a new enrolment at the next generation, taken at the sensor's console, the link comes up. | An agent that accepts any client key from the node's address keeps the link up after the key change. | Rig |

**H-rows that D6 has yet to name** (D6 on #624), each written and not run:

- whether a mirror port refuses ingress, for each switch model (O-1, AP-32 (1));
- a TPM-held key cannot be copied off the machine (O-2);
- no swap and no kernel crash dump on the running machine, which SL-T15 cannot show on a hosted runner;
- SL-24's custody and SL-27's out-of-band controller.

**The one rule with no test in this note** is SL-17, whose test P4-4-L3 names. SL-29 is covered by the C-11 rig, and SL-R8 by SL-T20.

## 13. What D5 and D4 are asked to confirm

D5 and D4 reviewed `2935220a` and passed it with notes. Their notes are in the rules above, and the lists below are as revised.

**D5, for the node:**

1. A link key in the key register used for sensor links only, and a dialer that checks a pin at every handshake with resumption off (SL-2, SL-12).
2. Saving, with the commit, the highest run counter, its `run_id` and the last committed `seq` for each sensor and generation (SL-14).
3. Dialling only when the configuration equals the live enrolment (SL-9), and choosing the stream from the authenticated key (SL-10).
4. Closing the link before the node's own audit write on a revocation, with the dialer off for the run when the state cannot be saved (SL-R2), and the mark by `through_seq`, taken after the held records are committed (SL-R3).
5. Holding the link on `run-forked` (SL-16), and the standing alarm while an acknowledgement is void (SL-R5).
6. No new listener (SL-18).
7. The live enrolments and the revoked pins in durable state that does not depend on the audit stream (SL-6).
8. The four failure rules of SL-20, and the time cap on `sensor.link_refused` (§11.2).

**D4, for the sensor:**

1. Three programs under three accounts: a capture stage that holds the packet socket, an engine with no socket in an empty network namespace, and the link agent with the key (SL-3).
2. Making the key at install, and checking an Ed25519 signature and a strictly decoded enrolment on the host (SL-1, SL-5).
3. A run counter kept on disk, raised at each start of any of the three programs and synced before the hello; a hello; a buffer trimmed only by acknowledgements; and a counter of the numbered records evicted from it (SL-13 to SL-15).
4. A closed set of two message types from the node, with no path to a setting (SL-19).
5. The engine's output held to an allow-list of streams and fields that the agent enforces, in memory-backed storage, with no swap and no core dump (SL-22).
6. Nothing fetched at run time (SL-26).
7. A digest of the effective configuration in the coverage statement, and how the sensor's end was pinned (SL-19, SL-5).

## 14. Limits

- **Everything here is `desk` and nothing is built.** No rule has a test yet. The tests of §12 are plans for P4-4-R1.
- **A compromised sensor host is not contained by this design.** It can read the mirrored traffic of the site, cleartext credentials included (HR-21), and it can lie to the node as itself (AP-34 (b), AP-36). The design stops it from becoming the node, another sensor, or a way into either, and makes it revocable.
- **Five assumptions are not verified,** and each is marked where a rule rests on it: that an open packet socket can send after `CAP_NET_RAW` is dropped (SL-26 on AP-31 (3), and AP-31); that the engine's output can be closed to a list, and that its logs and temporary files can be kept memory-backed (SL-22, and AP-33 (5)); that the engine can run with no route and no resolver (SL-26 on AP-31 (1), SL-3); and that a TPM-held key cannot be copied by root (SL-3, O-2). P4-4-R1 and P4-4-S2 decide the first four, and an H-row the last.
- **The three processes of SL-3 are a design to be shown.** No experiment has run an engine from a pipe in an empty network namespace.
- **SL-R5 rests on the node applying `node.network_baseline_ack`,** which it does not do yet.
- **No administrator's client exists,** so SL-5 step 3 and SL-R5's overlap view are requirements on one, as HR-14 is.
- **Not decided here:** the sensor host's hardware and operating system, every choice in §10, the bounds for skew, late records and the sensor's buffer (P4-4-L2 and P4-4-L3), and whether a node has one sensor or several (P4-4-L3).
