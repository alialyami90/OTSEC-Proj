# D3: the trust design of the sensor link, and the sensor host (P4-4-L1)

D3, 2026-11-11. This is the design note for brief P4-4-L1 (`docs/agent-handoffs.md`, "Phase 4 item 4, second part", D4-86). It is Markdown only. It changes no contract and proposes no code for merging. Reviewers: D5 (can the node do it), D4 (can the sensor do it) and D6 (can each rule be tested). D1 approves.

**Revised on 2026-11-11 after the reviews of PR #624 at `2935220a`.** D5 and D4 passed it with notes, and D6 failed it on two points: the mirror port (O-1) and the audit cap (§11.2). D1 ruled on four things, each marked where it applies: three processes on the sensor host (SL-3), the signature check at the sensor's end (SL-5), the order of a revocation (SL-R2), and the three threat-model rows beyond the brief's list. The reviewers' findings are cited as "on #624"; D3 did not re-derive them, except where a file is named.

**Revised again on 2026-11-11 under brief P4-4-L4** (`docs/agent-handoffs.md`, D4-87), against C13 0.2 as proposed (`docs/phase4/D4-c13-0.2-proposal.md`, #627, merged as `624beb58`) and the node's side (`docs/phase4/D5-sensor-node.md` Part 1, #628, merged as `d06fdb86`). **Both are reviewed documents, and neither is approved.** No rule and no test changed its number. What changed:

- **SL-3 has a new shape.** The process that holds the packet socket parses nothing, and redaction, reassembly and the PRP discard move to a stage that holds no socket. D1 ruled it with this brief, from D3's review of #626, as a design to be shown and not built. D1 gave that ruling by message, and records it on this change's PR.
- **The seven notes owed from #624** (D4-87): SL-3's wording; the assumption that a TAP is receive-only by construction (O-1, §14); SL-R7 named in SL-T12; controls for SL-T15's build check and crash leg and for SL-T2's link check; SL-T12's digest leg on the test-only build; and the missing legs of SL-T5, SL-T9 (g) and SL-T20.
- **The amendments C13 0.2 needs:** SL-13, SL-14, SL-15, SL-16, SL-17 and SL-19, and SL-R2, SL-R3 and SL-R6.
- **The couplings F1 to F10 found on `main`,** with D1's gate, in SL-20.
- **C7 0.11 and C8 0.13 written out as clauses,** each with the test that would show it, and a table of everything the two documents ask of C7 and C8 (§11).
- **The egress rule in its tested form** (SL-26, SL-T21), and the citation of E-D4-03 narrowed: the run reads files and not a pipe (SL-3, SL-26).

**Nothing in this note is built.** Every rule below is a requirement. No sensor, dialer, listener or enrolment exists (`docs/agent-handoffs.md`, "What already exists"). Nothing is `hardware-verified`, and no device family is called supported.

## 0. Sources, labels and words

**Evidence classes.**

- A statement about what exists today is `desk`: read on `main` at `1f5b307f` from the file it names. ADR-0009's decision for option (b) was read from PR #618 at `a16f8497`, which is not merged.
- A statement marked **assumption** is D3's understanding of Linux or of an engine. No manual page, kernel source or engine document was read for this note. Each assumption names the test that decides it.
- A rule is a requirement, and is not evidence of anything.
- **What P4-4-L4 added** is `desk`, read on `main` at `8ecdecc6`: the two documents named above; `contracts/authz` (0.10) and `contracts/audit` (writer 0.11, reader 0.12) as they stand; `modules/security/nodekey/register.go`; `platform/node/adminrelay.go`; and the reviews on #624 to #628.
- **One measurement is used, and it is `simulated`:** D6's rig self-test, in `docs/phase4/D6-sensor-rig.md` as PR #626 holds it at `554e065b` (not merged when this was written). It is run 43077596916 at `25826599`, job 130721405055, `CI-Linux`: kernel 7.0.0-1017-azure, a veth pair, senders run by root or by a stand-in, and no sensor. It is cited below as "run 43077596916", each time with its limits: **one kernel, on a veth pair.** It shows nothing for another kernel, a real NIC, an XDP socket, or root removing a rule.
- The threat-model rows this brief rewrote (TB6, AP-30, AP-31, AP-32 and AP-34) are as they stood before option (b) at `1f5b307f`: `git show 1f5b307f:docs/threat-model.md`.

**Read for this note** (`desk`): ADR-0009 at `a16f8497`; `docs/threat-model.md` (TB6, AP-10, AP-24, AP-30 to AP-36, SC-11, SC-14, SC-19, HR-13, HR-14, HR-19, HR-20); `docs/phase4/D5-sensor-node.md` §1, §2, §4 and §5; `docs/phase4/D4-c13-netobs.md` §1, §2, §3.3 and §6; `docs/phase4/D3-c7-0.10-c8-0.12.md`; `contracts/authz` (0.10: `adminsig.go`, `approval.go`, `netack.go`); `contracts/audit` (reader 0.12); `platform/sensorlink/link.go`; `platform/node/netsensor.go`; `modules/security/nodekey/doc.go`; the reviews on PR #618; D4-82 to D4-86.

**Words.**

- **Sensor host:** the Linux machine at a site that captures mirrored traffic (option (b), D4-85).
- **Socket holder:** the project's own program on the sensor host that holds the packet socket on a monitoring interface and copies each frame into a pipe. It parses nothing (SL-3).
- **Frame stage:** the project's own program that reads that pipe and holds no socket. It discards PRP duplicates, redacts frames, writes the ring and feeds the engine through a second pipe (SL-3).
- **Capture stage:** the socket holder and the frame stage together. Until P4-4-L4 it was one program, and C13 0.2 and the node's design use the word for that one program. §13 lists what the split asks of C13 0.2.
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
| **Socket holder** | The packet socket on the monitoring interface, and the writing end of one pipe. | A parser. A send call, or any system call outside its allow-list. The link key. An address on the management interface (SL-3). |
| **Frame stage** | The reading end of the socket holder's pipe, the writing end of the engine's pipe, and the redacted ring, which it writes. | A socket of any kind. A route, a resolver or any interface but the loopback of its own empty network namespace. The link key (SL-3). |
| **Engine** | The reading end of a pipe from the frame stage, and its own output in memory-backed storage. | A packet socket. A route, a resolver or any interface but the loopback of its own empty network namespace. The link key (SL-3). |
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

**SL-3. Four processes on the sensor host, each under its own account. The one that holds the packet socket parses nothing, the ones that parse hold no socket, and only the link agent can read the key.**

**This replaces SL-3 as merged in #624** (`551b03dd`). That text had three processes. Its one capture stage held the packet socket, discarded PRP duplicates, redacted the frames and wrote the ring, and the rule rested on that program calling no send function, with the capability drop "as a second measure". D1 adopted the shape below with brief P4-4-L4, from D3's review of #626. **It is a design to be shown. None of it is built, and the rig has not measured the parts listed under "What the rig still owes".**

**Why it changed.** The rig measured that a process which had dropped every capability still sent frames on the packet socket it already held, and could still set `PACKET_QDISC_BYPASS` on it (`simulated`: run 43077596916, one kernel, on a veth pair, with a stand-in and no sensor). So the capability drop is no measure against sending. And the capture stage of #624 parsed hostile frames, to reassemble and redact them, while it held a socket it could send on. That is one fault away from transmitting (D6's first note on #624; D3 on #626).

1. **The socket holder** is the project's own memory-safe program. It opens the packet socket on a monitoring interface, reads each frame into a fixed buffer, and copies it whole into one pipe, with its length and the interface it came from. **It parses nothing:** it reads no header, trusts no length field inside a frame, and reassembles nothing.
   - **A system-call allow-list,** set before it reads its first frame, which it cannot lift afterwards. It allows the receive calls on the socket's descriptor, writes on the pipe's descriptor only, waiting, and the read of the socket's statistics. Everything else is refused. That must include every way to send, and every way to get one back: `sendto`, `sendmsg` and `sendmmsg`; a `write` on the socket's descriptor; every `setsockopt`, so that neither `PACKET_QDISC_BYPASS` nor a transmit ring can be set; `socket`; the calls that copy or renumber a descriptor; the calls that move data between descriptors; and the set-up of the asynchronous I/O interface, whose operations a filter on calls does not see. Any option the socket needs is set before the filter.
   - **Its capability.** `CAP_NET_RAW` is granted to its unit alone, with no `CAP_NET_ADMIN`, and is dropped once the socket is open, with `no_new_privs` set. The drop has two uses and no other: no second packet socket can be opened, and no capability comes back by running a program. **It is not a measure against sending.**
   - **It sits behind the egress rule of SL-26,** which neither capture account can change.
2. **The frame stage** is the project's own memory-safe program, and it holds no socket of any kind. It runs in an empty network namespace, as the engine does, so that holds by construction. It reads the socket holder's pipe, discards PRP duplicates, reassembles as far as redaction needs, redacts by position and writes the ring, and feeds the engine through a second pipe. It is the program that refuses a configuration with a redaction slot off (SL-22).
3. **The engine** holds no packet socket at all. It reads the frame stage's pipe, and it runs in an empty network namespace, so it has no route, no resolver and no management interface by construction and not by a setting.
4. **The link agent** holds the key and checks the enrolment's signature (SL-5). It takes allow-listed lines from the engine, in one direction only (SL-22), maps them to C13, and cites frames from the redacted ring. It is the project's own memory-safe code (SC-14), because it is the only program on the host that parses bytes from the network side of the link.

"The capture stage", in this note, in C13 0.2 and in the node's design, now means the socket holder and the frame stage together. What the split asks of C13 0.2 is in §13, as requests to D4.

- *What counts against sending, in order.* (1) The socket holder parses nothing, so a crafted frame meets no parser in the one program that can reach the socket. (2) Its call filter. (3) The egress rule of SL-26. (4) **A TAP is the only measure that holds against a compromised sensor host** (AP-32 (1); O-1 says which TAP): root on the host removes (2) and (3). **Not measures against sending:** the capability drop; and a socket filter attached with `SO_ATTACH_FILTER`, which filters what is received. The second is D3's understanding of Linux and was not read from a source.
- *What the rig still owes* (P4-4-R1; D3 on #626 at `554e065b`). Until each has run, this rule is a design:
  - **the call filter:** a stand-in under the profile tries each send path in turn; each is refused, no frame reaches the rig's far end, and the stand-in still receives every frame. The control is the same stand-in with no profile, which run 43077596916 already shows sending;
  - **the split:** the frame stage's descriptor list shows no socket, the frames reach it complete and in order by hash, and a full pipe is counted;
  - **the other send paths behind the egress rule.** Run 43077596916 measured `send`, with and without `PACKET_QDISC_BYPASS`. It did not measure a `write` on the socket, `sendmsg`, a transmit ring, a move of data from another descriptor, or the asynchronous interface;
  - **whether a capture account can change or remove the rule,** which that run did not measure;
  - **the rule on the sensor image's own kernel and on a real NIC:** H-18 (d), written and not run, with its frame sent by a process that dropped every capability, on a socket opened before the drop.
- *What settles the engine's part.* Whether the engine reads a pipe with no network is not shown. E-D4-03 as built (#625) reads capture files in a container with no network. It can show that an engine completes with no route. It reads no pipe, and it records no attempted lookup or connection (D7 on #625). The pipe case is D4's follow-up to #625 (D4-87).
- **Assumptions,** each D3's understanding of Linux and not read from a source: that a system-call filter can tell the socket's descriptor from the pipe's; that operations of the asynchronous I/O interface pass a filter on calls, so its set-up must be refused; and that changing an nftables rule set needs a capability that neither capture account holds. The rig's legs above decide them.
- *Answers:* AP-30 and AP-32. A frame crafted to exploit a parser meets parsers only in the frame stage and the engine, which have no socket to send on, no network to reach and no key to take. The socket holder copies it and never reads it. A decoder exploit then holds the frame stage's account or the engine's. It can lie through its output as this sensor (AP-34 (b)), but it cannot send onto the station LAN, reach the management network, or take the key away and speak as the sensor from somewhere else or after the host is cleaned. The control for the parsers that remain is AP-30's fuzzing of the frame stage and the link agent.
- *Where the key rests.* A file readable by the link agent's account alone, or a TPM-held key. That is a hardware choice, and it is the owner's (§10, O-2). With a file, root on the sensor host can copy the key. With a TPM, root can use it and cannot copy it. **Assumption:** that a TPM-held key cannot be copied by root. No TPM document was read for this note, and an H-row decides it (§12).
- *Tests:* SL-T2 and SL-T22.

## 3. Enrolment, with no trust on first use

**SL-4. Neither end accepts a key because it was the first one it saw.** The node dials an address only when a live enrolment names it. The link agent does not listen at all until it holds an enrolment, and then completes a handshake only with the pinned node key.

- *Answers:* AP-8's rogue enrolment and an attacker on the path at first contact, who under trust on first use would become the sensor for good.
- *Test:* SL-T3.

**SL-5. An enrolment is an admin-signed C7 request, `node.sensor_enrol`, that names both ends** (§11.1): `sensor_id`, generation, the sensor's pin and address, the node's pin and address, `not_after`, and a reason (`new`, `renew`, `rekey` or `replace`). The administrator's client draws the `sensor_id`; the sensor does not choose its own. Addresses are IP literals. No hostname is used, because name resolution is not trusted and no internal hostname may be recorded.

The steps, each done at a console or in the administrator's client and none over the link:

1. On the sensor host, the link agent makes its key and shows its pin on the console.
2. The administrator reads the node's link-key pin from the node's key register.
3. The administrator's client builds the request from those two pins. **The administrator takes the sensor's pin from the sensor's own console, never from the node,** for the reason HR-14 gives for baseline digests: a compromised node must not be able to supply the value a person signs.
4. The node relays the signed request to the collector, which verifies it as it does every admin kind: signature, the key's kinds, nonce, window, and the binding to this node (`VerifyAdminRequest`).
5. The node checks the request against its own state (SL-6), writes C8 `sensor.enrolled`, and only then records the enrolment. If the audit write fails, the enrolment is not applied.
6. The same signed bytes are carried to the sensor host's console. The link agent verifies the signature against the administrator public key it was installed with, checks that the sensor pin is its own key's and that the generation is above the one it holds, and takes the node's pin, the node's address, its `sensor_id` and `not_after` from the signed body. It applies the reason's rule to its own key, as the node does (§11.1, C7-4): on a `renew` it keeps its run counter and its buffer, and on any other reason it starts run 1 and declares what it discards (C13 0.2, CH-12). It then opens its listener.

So both pins come from one signed statement, and the node's audit chain records it.

- *What the sensor does not check.* The 15-minute lifetime of an admin request is judged at the collector's clock. The link agent does not judge it: a site visit takes longer, and the sensor host's clock may not be set yet. An old enrolment cannot be replayed to the agent, because it must name the agent's own key and a higher generation.
- *What the signature does not do.* It does not protect against a compromised node, which can already write anything to its own store. It stops a person who can write the node's configuration and holds no enrolment key (AP-14), it stops trust on first use, and it leaves a record.
- *The check at the sensor's end is kept* (D1's ruling on #624, on D6's preference), on two conditions. An import test shows that neither of today's product binaries, `cmd/otsec` and `cmd/otsec-collector`, can reach the verifier that leaves out the collector's checks (§11.1). And the fallback is recorded for each deployment that uses it.
- *The fallback* is that an installer types the node's pin at the sensor's console. The sensor's end is then pinned by hand and by nobody's signature, and a wrong or hostile entry is caught only when the node's dial fails. The link agent states which way it was pinned (`pinned_by` in its hello; C13 0.2, CH-33), and the node shows it in status, so a deployment pinned by hand is never mistaken for one pinned by signature. The node raises a standing alarm while a live sensor reports `console`, and refuses nothing for it: the value is the sensor's own word, so a refusal would stop only an honest sensor (D1's ruling 4 on #628). A value that changes within one generation closes the connection as `binding`, because the way an end is pinned changes only with a new enrolment (SL-14).
- *Answers:* AP-8, AP-14, AP-34 (a).
- *Tests:* SL-T3, SL-T4.

**SL-6. The node applies an enrolment only when all of these hold;** otherwise it writes `sensor.enrolled` with outcome `denied` and changes nothing.

- The collector accepted the request.
- `node_spki` is the pin of the node's own link key, read from its key register.
- The generation is one above the last enrolment of that `sensor_id`, or 1 for a new one.
- The sensor's pin is not one the node has revoked (§6).
- The sensor's pin is not one the node holds for a fork (SL-16).
- `not_after` is at most 366 days after the request's `issued_at`. That is the ceiling HR-17's design gives a standing approval, and D1 may set another.
- The stated reason agrees with the pin: `new` for a `sensor_id` the node holds no enrolment of, `renew` with the pin of the last enrolment, and `rekey` or `replace` with another pin (§11.1, C7-4; D3's condition on D1's ruling 5 on #627).
- The sensor's address is the address of no asset in the node's configuration (SL-9; D1's ruling 5 on #628).

A new enrolment of the same `sensor_id` replaces the old pin at once. **One `sensor_id` has at most one live key.**

**The live enrolments and the revoked pins must not depend on the audit stream alone,** because that stream is pruned (D5 on #624). The node keeps them in durable state that it folds from its C8 records. D5 would use a configuration-class document, as suspensions are kept. The mechanism is P4-4-L3's; the requirement is that a pruned audit stream never brings a revoked pin back or loses a live enrolment. The node's design keeps them in a file of its own, `sensors.json`, folded from the audit stream by a consumer of its own, under D3's conditions (#628 §1.3): a rolled-back file is folded forward or the state is unknown; after a start nothing dials until one fold has read through the stream's head; and a read error never delays a revocation. **Its stated limit:** with the file lost and the stream pruned past what the fold needs, the state is unknown and nothing dials. A new enrolment is then applied with the previous state recorded as unknown (§11.2, C8-2), and a revoked pin that only the lost file held could be enrolled again by a new signature.

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
- **This is also the local way to stop a link.** Editing or removing the entry stops the dial, with no collector and no audit write needed (SL-R2). The node reads its configuration at start only, so the local stop is an edit and a restart of the node service (#628 §1.3).
- **The node never dials a device** (D1's ruling 5 on #628; P1). A sensor's address must be the address of no asset in the node's configuration, compared on the IP alone and whatever the port. Only the collector opens device sessions, and an enrolment must not make the node service send connections to a relay. It is checked at enrolment (`denied`, `asset-address`), at load, and at each dial. At load it is an alarm and never a refused configuration: that sensor is not started and is never dialled, and collection for the asset goes on (#628 §1.1).
- **No sensor check fails the node's start or refuses its configuration, except the section's own shape** (D1's recorded ruling 1 on #628, comment 6803459738; D3 and D6 agreed).

- *Answers:* AP-14. A configuration change alone cannot point the link at another machine.
- *Test:* SL-T5.

**SL-10. The authenticated key decides the `sensor_id`; a record's own field never does.** After the handshake, the connection belongs to the one sensor whose pin matched. Its hello (SL-13) must state that `sensor_id` and generation, or the node closes the connection before it reads a record. Every record's `sensor_id` must equal it. A record under any other `sensor_id` is refused, is never stored, is counted (today's `sensor-id` reason, `platform/sensorlink/link.go`), and raises an alarm and a C8 `sensor.link_refused` record. The stream a record is stored in is chosen from the authenticated key, so with several sensors on one node, sensor A's key can never write to sensor B's streams.

- The link stays open after such a record, as C13 keeps it open after any refused record. A sensor that means to lie would not send a wrong ID, so closing gains nothing and loses coverage.
- *Answers:* AP-34 (a): one compromised sensor speaking as another.
- *Test:* SL-T6.

**SL-11. The link agent binds too.** It sends records only on a connection whose client key equals the node's pin. The host firewall admits the link's port only from the node's address. The address is a filter and not an identity: anything on that network can forge it.

- *Answers:* a host on the management network that connects to the sensor to read the site's observations or to feed the agent's parser.
- *Test:* SL-T7.

**SL-12. TLS rules for the link.** TLS 1.3 only. Both certificates are required, and both pins are checked at every handshake against the enrolment in force at that moment. No session resumption and no early data, so a revoked or replaced key cannot ride a ticket from an earlier session. No system roots and no trust by name (HR-15). A handshake timeout. At most one connection for each sensor. ALPN `otsec.netobs/0`, the major only, is required at both ends (C13 0.2, CH-1): the pin is the control, and the name only keeps the port from being taken for another service.

- **In Go, pinning by key means that normal verification is off and `VerifyConnection` is the only check.** The node's design builds that configuration in one function, with a test that `InsecureSkipVerify` appears in that one product file only, and it refuses a resumed session, another TLS version and an ALPN that was not negotiated in the same check (#628 §1.1). HR-15 carries the review rule for this client.

- *Answers:* downgrade; a clone that resumes an old session after a re-key; a slow handshake that holds the dialer.
- *Test:* SL-T8.

## 5. Replay and resume: what C13's channel must carry

These are requirements on `otsec.netobs/0.2` (brief P4-4-L2). D4 chooses the field names and the encoding.

**What TLS already gives.** Bytes recorded from one connection cannot be replayed into another, because each handshake has fresh keys and the sensor signs the new handshake. The rules below are for what TLS cannot see: a sender that holds the key and replays, re-orders, restarts from an old state, or is a copy.

**SL-13. A hello in each direction before any record.**

- Node to sensor: `sensor_id`, generation, and the last position the node took (SL-15): run counter, `run_id` and `seq`. C13 0.2 names it `taken` (CH-6).
- Sensor to node: `sensor_id`, generation, its run counter, its `run_id`, the first `seq` it will send (`first_seq`), the newest `seq` it has numbered and synced (`newest_seq`), the count of numbered records it evicted before the node acknowledged them (`drops_channel`), and its clock.
- **This replaces "the oldest `seq` its buffer still holds"** in this rule as merged in #624. `first_seq` carries the same fact, and `newest_seq` with `drops_channel` lets the node match a gap to its declaration (CH-7, CH-15; D3 on #627, note 5). C13 0.2's hello carries more than this (CH-7). This rule requires only these fields.

**SL-14. Every record is ordered by (generation, run counter, `seq`).** The link agent keeps a **run counter** on disk. It starts at 1 for each generation and rises by one at each start of the agent, **of the engine or of the capture stage** (D4 on #624), and so of either of the capture stage's two programs (SL-3): a restarted engine has forgotten the flows that the node still holds open, and the node clears its open-flow table only on a new run. **The agent syncs the counter to disk before it sends the hello,** so a crash after the hello cannot bring the same counter back under another `run_id`, which the node would read as a fork (D5 on #624). `run_id` stays C13's name for a run, and the hello ties it to its counter. The node keeps, for each `sensor_id` and generation, the highest run counter it has accepted, that run's `run_id`, and the last `seq` it committed. It saves them with the commit, so the checks hold across a node restart.

C13 0.2 is stricter on two points, and D3 accepts both. The counter and the `run_id` are synced before the run's first record is numbered (CH-12). And a record is sent only after the sync that covers it (CH-19), so the node can hold more of a run than the sensor's disk holds only when that disk went back.

The node refuses the hello, closes the connection, raises an alarm and writes `sensor.link_refused` when:

| Case | Reason | What it means |
| --- | --- | --- |
| The run counter is below the highest accepted | `run-regressed` | An old run replayed, a restored snapshot, a host re-imaged with no new enrolment, or a copy |
| The run counter equals the highest, with another `run_id` | `run-forked` | Two holders of one key: a copy |
| `sensor_id` or generation differ from the enrolment | `binding` | A stale or wrong enrolment at the sensor |
| On a resumed run, the sensor's newest `seq` is below the `seq` the node took | `run-regressed` | The sensor's disk went back: a restored snapshot, a copy, or a file system that lost synced data (CH-13 row 5a; D3's B2 on #627) |
| The way the sensor's end was pinned differs from the first value the node saw in this generation | `binding` | It changes only with a new enrolment (SL-5; CH-33) |

- **Within a run,** `seq` rises by one from the hello's first `seq`. A `seq` at or below the last one taken in this connection is refused (today's `seq` reason), so a re-ordered stream cannot pass. On a resumed run, a `seq` at or below the last committed one is a resend: it is dropped and counted as a duplicate, and never stored twice.
- **A gap** is counted, as today (`SeqGaps`). It must be matched by drops that the sensor declares in its next heartbeat. A gap the sensor does not declare raises an alarm, because a loss nobody owns is how a record is made to vanish (P5). Declaring a gap needs a counter of the numbered records evicted from the agent's buffer. It was asked of C13 0.2 (D4 on #624), which gives it as `drops_channel`, with the capture spans of what was lost (CH-15, CH-40).
- **A declared loss is still a loss a person must see** (D3 on #627; P5). A declared span switches off the node's own-session check inside it. So the node checks each span, requires a rise in the count for a new or wider one, and opens a coverage gap and an alarm for it. A span that ends after the present is cut once, at the earliest of its own end, the message's clock, and the node's receipt time plus the skew bound. The last term rests on the node's clock alone (CH-40). Without the cut, one span stated to end in the year 2100 would keep the node's one independent check off for good (AP-36 (2)).
- **Records left from the previous run** are flushed before the next run's hello, or declared lost in it. C13 0.2 carries one run on each connection, oldest first, and a new run's hello declares what came before it (CH-16). Either way, no record of an older run follows a newer run's hello.
- *Answers:* AP-34 (a) by replay; a cloned or rolled-back sensor.
- *Test:* SL-T9.

**SL-15. The node acknowledges what it has taken, not what it has received.** This rule as merged in #624 said "committed". C13 0.2 acknowledges what the node has *taken*, and D3 accepts it (CH-17; D3 on #627, note 6). A record is taken once it is committed to the store, saved in the intake hold's checkpoint, a duplicate, a `seq` that was never received and is counted as a gap, or refused or dropped for good. **The count of a refused or dropped record is durable before the acknowledgement passes it** (D1's ruling 2 on #627): the run's refused and dropped totals are saved with the position, so a node crash never erases the only trace of a record that the sensor has trimmed. The acknowledgement names a run and the highest `seq` taken, and never more than the position the node has saved. The link agent trims its buffer only up to it. After a break, a continuing run resumes from the acknowledged `seq` plus one. Records that fell out of the buffer are lost, declared and counted. This is the lesson of C-04 and E-01: an acknowledgement is worth what the receiver had made durable.

- *Why "taken".* A record refused for good must not block the stream behind it, and the hold's checkpoint is durable.
- *Test:* SL-T9.

**SL-16. A re-image and a copy.**

- **A re-image destroys the key** (SL-1), so the host needs a new enrolment at the next generation, and its run counter starts again at 1 under it. The node's own stream numbers carry on, and the detector's checkpoint counts in those, so nothing on the node resets. The open-flow table is cleared, as on any new `run_id` today.
- **A re-image that keeps the key** (a TPM-held key) loses the run counter, so the node refuses it as `run-regressed` until an administrator enrols it again. That is deliberate: a re-image is an event a person attests to.
- **A copy** holds the same key and the same state. The node cannot tell a copy's first connection from the original's restart. It can tell once both have connected: the second arrives with a counter the node has already seen, under another `run_id`. On `run-forked` the node stops dialling that sensor and holds the link until an administrator enrols it again **with a new key**, or revokes it, because one of two key holders is false and the node cannot tell which. Enrolling again with the same key would leave the copy in place, so the node denies it (SL-6; D5 on #624).
- **The hold is durable** (D3's B4 on #627). The node keeps the held state with its sensor state, so a restart of the node does not dial the sensor again (CH-18; #628 §1.3). If that state cannot be written, the dialer stays off for the run, and the next start derives the hold from the fork's own audit record (`sensor.link_refused`, `run-forked`; §11.2, C8-4).
- **What a fork costs.** The network at that sensor is unwatched from the hold until someone makes a new key on the sensor host, which is a visit to the site. The coverage gap is recorded and the alarm stands for all of it. The sync of the run counter before the hello (SL-14) is what keeps an honest crash from causing one.
- **Residual.** A copy that always moves its counter forward is accepted until the original shows up. Against a stolen key only revocation helps (§6). A TPM-held key removes copies made from a disk or an image (O-2). A sensor that is a virtual machine can be copied by a snapshot (O-9).
- *Test:* SL-T9.

**SL-17. Time and late records: constraints for P4-4-L2 and P4-4-L3.** The bounds are theirs to set. D3's constraints:

- The node never orders, prunes or expires anything by the sensor's clock. It adds its own received time, as today.
- A sensor clock outside the skew bound raises the skew alarm. While it is outside, a tie between an observation and one of the node's own sessions (AP-35) is not made: the flow is judged untied, which alerts. Skew must never suppress. Every scheduled session then alerts for as long as the skew lasts, so those alerts are aggregated, with the skew alarm naming the cause, and they do not fill the alert class (D5 on #624; how is P4-4-L3's).
- A backlog after an outage may delay an alert, and never suppresses one. The hold for the node's own sessions stays bounded while it waits for a backlog, as AP-35 requires today.
- The node does not serve time to the sensor. That would be an inbound port on the node (SL-18) and a second channel to the sensor (SL-19).
- **How C13 0.2 and the node's design meet these** (CH-22, CH-23 and CH-39 to CH-41; #628 §1.5 and §1.6; D1's ruling 1 on #627 and its ruling on round two):
  - **The alarm** is judged on E, the least offset of the last six ticks, against a bound of 2,000 ms. **The tie reads the latest sample too:** no tie is made while the alarm stands, or while the latest sample is outside the bound.
  - **A tie on a backlog record fails closed.** The node bounds a backlog record's clock error only by what it measured itself, the length of the break on its own clock. After a break longer than `backlog_tie_s` (60 s, at most 120 s), a record numbered while no connection was open takes no tie, and the own-session alerts of that outage are aggregated into one alert that names its assets up to a cap. After a shorter break, such a record ties only when the time the agent numbered it, brought to the node's clock, falls inside the break.
  - **The sign.** The offset is the node's time minus the sensor's, so a sensor time is brought to the node's clock by adding E. D3's first text on #627 said "less E", which was wrong by twice the offset (D4 found it; D4-87).
  - **"Late" is the sensor's own word** and carries no trust. The node's own measure is the break.
  - **What stays** is in AP-35: a step made and undone between two ticks, and a clock moved and restored inside a short break.
- *Answers:* AP-35. A sensor whose clock is wrong, by fault or on purpose, moves observations into or out of a session's window.
- *Tests:* none in this note. They are named in the two documents: C13 0.2's T-2, T-7 and T-8 (§15 there), and the node's `TestSkewStepBackTiesNothing` and `TestSkewCorrectionAddsE` (#628 §1.5), with the gate's skew-alarm line.

## 6. Revocation

**SL-R1. `node.sensor_revoke` is admin-signed and names the `sensor_id`, its generation and pin, a reason, and optionally `suspect_from`:** the time from which the administrator no longer trusts what the sensor sent. Absent, it means from enrolment.

**SL-R2. It closes the link at once, before the node's own record.** D1 kept this order as the fail-closed one (ruling on #624). Once the collector has accepted the request, the node saves the revoked state, closes the connection and stops dialling, and then writes C8 `sensor.revoked`. For every other admin decision the node's record comes first, and a failed write stops the decision (D4-68 ruling 9). Here that order would keep a revoked sensor trusted, which is failing open.

- **Audit before act still holds.** D1-11 (`docs/phase1/A1-decisions.md`) is the rule that collection which uses a credential stops when its audit record cannot be written. SL-R2 does not break it: a revocation uses no credential, and the collector's decision is in the audit chain, as `collector.request`, before the node acts on it (D5 on #624).
- **If the node's own write fails,** the link stays closed, status shows the record as owed, and the node writes it once when the chain accepts writes again.
- **If the revoked state cannot be saved,** the dialer for that sensor stays off for the rest of the run, and at its next start the node derives the state again from the decision in the chain.
- **What a revocation still needs.** It waits for the collector, and it cannot be recorded while the audit store is full. The protective path that needs neither is the local one: an edited or removed `network_sensor` entry stops the dial (SL-9). That revokes nothing and marks nothing, and the signed revocation follows when it can be made.
- **How soon "at once" is** (D1's rulings 2 and 3 on #628; #628 §1.3). From the node's fold of the collector's acceptance to the close: within one second. From the signature to the close: about 15 s when no run is in progress, about 615 s at worst when the collector answers, and **open while the collector holds requests.** The relay stays where it is: a second client on the collector's pipe is a change to the privileged process that this gain does not justify. Every record committed in that window is at or below `through_seq` and after `suspect_from`, so it is marked (SL-R3).
- **Because that bound can be open, a pending request stops the dial.** Every 15 s the node reads its admin directory. While a `node.sensor_revoke` request that names a live sensor is undecided, the node stops dialling that sensor and closes its connection, with an alarm. It reads the request for its `sensor_id` and pin only, before any signature is checked, so this path can only stop a link. It lifts if the collector refuses the request, if the file goes away, or when the request's own expiry passes. **What it costs:** whoever can write the node's admin directory can hold a sensor's link down, with the alarm standing. That directory is under the protected-file rule, and writing it is already a compromise of the node (SL-5).

**SL-R3. Records already stored are kept, and marked.** Nothing is deleted: they are evidence. The store is append-only, so the mark is not written into them, and it needs no rewrite: a reader applies it from each record's commit time and the `through_seq` (D5 on #624). `sensor.revoked` carries, for each of the sensor's streams, the last committed `seq` (`through_seq`), with `suspect_from`. Every reader (status, an export, a screen later) shows that sensor's records at or below `through_seq` and committed at or after `suspect_from` as coming from a revoked sensor. The node also commits a health event to the health stream, not to the sensor's alert stream (D5 on #624), so an upstream collector sees the revocation in a stream it already receives. **Records held at intake when the revocation lands are committed before `through_seq` is taken,** or they would land above it unmarked. None is dropped silently.

- **The order at the node** (#628 §1.3; D3's L3 on #628). `through_seq` is taken only after the connection's read loop has returned, so no record is in commit. The alert stream's `through_seq` is taken once the detector has judged every observation at or below the observation stream's, so that no alert raised later from the sensor's earlier observations lands above it unmarked. `sensor.revoked` is owed until then, and may be written late (§11.2, C8-3).
- **A discarded buffer is declared.** After a revocation the sensor's old key no longer passes the handshake, so what its buffer held cannot be sent. The next enrolment's first hello declares it, with its count and its spans (CH-12; D1's ruling 5 on #627).

**SL-R4. Later records are refused.** The node never dials a revoked pin again. A revoked pin can never be enrolled again, under any `sensor_id`. The next enrolment of that `sensor_id` carries a higher generation and another key.

**SL-R5. The network baseline is acknowledged again.** From `sensor.revoked`, the acknowledgement of that sensor's baseline is void. After a new enrolment, the rules that need an acknowledged baseline do not run for that sensor until a person signs `node.network_baseline_ack` again. Whether they sign the old document or learn a new one is their judgement, and the administrator's client must show whether the learning period overlaps the suspect period. While the acknowledgement is void and the sensor is feeding, the node shows a standing alarm, so the weaker detection is never silent. No administrator's client exists yet, so the overlap view is a requirement on one (as HR-14 is). **This rule also rests on something that is not built:** the node does not yet apply `node.network_baseline_ack` (D5 on #624; at `1f5b307f` no file under `platform/` or `cmd/` outside the tests names `netack`).

**SL-R6. A re-key with no compromise is not a revocation.** A new enrolment of the same `sensor_id`, with reason `rekey` and a new key, replaces the old pin at once (SL-6), and the acknowledgement stands. That gives the enrolment grant nothing new: a sensor can lie about traffic under any baseline, and a baseline can only be widened by `node.network_baseline_ack`, which is another grant (SL-7).

- **The reason is checked against the pin** (§11.1, C7-4; D3's condition on D1's ruling 5 on #627). `renew` keeps the key, and `rekey` and `replace` change it; any other pairing is `denied`. The node decides what carries over from the pin being unchanged **and** the reason `renew`, never from the reason alone.
- **A `renew` loses nothing.** The sensor's buffer, its run counter and the node's position carry over to the new generation, so an expired enrolment, renewed, flushes what it held. Any other reason starts run 1 of the new generation, and what the sensor discards is declared (CH-12).
- **Applying any enrolment closes that sensor's open connection first,** so the old pin is replaced at once (SL-6; #628 §1.3).

**SL-R7. Nothing is sent to the sensor.** The link carries no revoke command (SL-19). The node stops trusting, which is all that safety needs. What is done with the machine is a site procedure (O-4). The close for a revocation or a replaced enrolment is a TLS close with no C13 message, and after the decision the node takes no further record of that connection and sends no acknowledgement (CH-37).

**SL-R8. If the node's own link key is lost or replaced,** every sensor of that node is enrolled again at its console, at the next generation.

- *Answers:* a compromised or stolen sensor host (AP-34 (a), HR-21); a baseline learned through a sensor that was already false (AP-36 (a)).
- *Tests:* SL-T10; SL-T12 for SL-R7; and SL-T20 for SL-R8.

## 7. Direction, and what the link carries

**SL-18. The node opens the link and gains no inbound port.** It dials each sensor as it dials its forward targets, and its firewall allows that one destination. The link agent's listener is bound to the sensor host's management address only: never a wildcard address, and never the monitoring interface, which has no address. It is closed until the sensor is enrolled (SL-4).

- *Answers:* AP-34 (1). Nothing on the station LAN can reach the channel, and enabling a sensor adds no way into the node.
- *Tests:* SL-T11, SL-T7.

**SL-19. The link carries the sensor's C13 records and the node's acknowledgements, and nothing else.**

- Sensor to node: the hello, ticks, heartbeats and observations.
- **`tick` is new in C13 0.2, and D3 accepts it as a fourth type from the sensor** (CH-8; D3 on #627, note 1). It is decoded strictly, carries no text and no frame bytes, is never stored, and is made when it is sent, so it is the node's one live reading of the sensor's clock (SL-17). What reaches the sensor is unchanged: two types. A tick under another `sensor_id` counts as SL-10's refusal does, and one that comes faster than the interval is counted and does no further work.
- Node to sensor: the hello and acknowledgements.
- Each end decodes strictly from a closed set, and treats the other as hostile input. The node's messages to the sensor are small and bounded, and carry no text.
- **An acknowledgement's only effect is to move the agent's trim cursor,** as TB5 limits a RELP response to moving the forwarding cursor. An acknowledgement for another run, or above the highest `seq` sent, is counted and closes the connection. C13 0.2 states the bound as the larger of the hello's first `seq` less one and the highest `seq` sent on the connection (CH-9).
- **The position in the node's hello is bounded the same way.** One that names a run the agent does not hold, or a `seq` above that run's newest, is not applied and is counted, and the agent sends its true hello for the node to judge (CH-6; D3's B2 on #627).
- **No command and no configuration reaches the sensor over the link:** no rule or baseline, no capture filter, no time, no update, no restart, no request for logs or ring files. The link agent has no code path from a link message to anything but the trim cursor.
- *Answers:* AP-7's shape, one hop down. A compromised node that could configure its sensors could switch off redaction, load a rule that transmits (AP-32), or use them as a foothold beside the station LAN. With this rule a compromised node gains nothing on the sensor host, and a compromised sensor gains nothing on the node beyond lying (AP-34 (b)).
- *Consequence.* The sensor's settings change only through the signed update (SL-25) or at the console (SL-23). The node learns them from the coverage statement, and `sensor-coverage-mismatch` is its check.
- *The configuration digest.* It was asked of C13 0.2 on #624, and C13 0.2 gives it as `config_digest`, in the hello and in the coverage statement (CH-32): a digest over each program's hash, every configuration file the programs read at start, the settings, and the state of each redaction slot. A local edit, such as an allow-list widened, then shows at the node as a digest it does not expect. A redaction slot can be off only in a test build (SL-22). Like the rest of the coverage statement it is the sensor's own word, so it shows an edit and not a compromise (AP-36). The agent hashes the files on disk at the run's start, and not what each program loaded (D3 on #627, note 12). What SL-3's new shape asks of its list is in §13.
- *Test:* SL-T12.

**SL-20. A sensor that is cut, blind or flooding must never stop SER or Syslog collection.** Nor may any fault in a sensor's start, sizing or paperwork fail the node's start (SL-9). The separate store classes and quotas exist (C5 0.9). No flood over a network link has run (D3 on #618). Under option (b) the dialer and the reader add their own bounds: the frame cap (64 KiB, C13), a read deadline, bounded memory for each link, a redial back-off, and a floor between immediate redials (10 s; CH-38), so that a sensor which closes cleanly after every hello cannot drive the dial rate (D3's B1 on #627). P4-4-L3 item 8 names the test.

What the node's design must keep (D5 on #624, and the reviews of #628):

- a missing or mismatched enrolment is an alarm, never a failure at start (SL-9), and so is every other fault of a sensor's start: its intake, its database and its sizing;
- sensor work stays off the scheduler's tick, or is bounded there, so a slow link cannot delay collection;
- `sensor.link_refused` stays capped by time (§11.2), because a full audit store stops credentialed collection (D1-11, V-S9, `TestAuditFullSendsNothing`);
- **the platform class keeps collection's own need.** A sensor's health events go to the class that holds `collection.missed`, and that class refuses new records when it is full. So they are capped by time, and written only while collection's reserve is left (#628 §1.9 item 5);
- a cap that protects collection must not quietly switch off the own-session check: a session whose tie could not be made is kept, marked and judged, with an alarm (#628 §1.9 item 4; AP-36 (2));
- a sensor's faults stay inside the sensor's own database.

**The couplings found on `main`** (D5 and D6 on #628; `docs/phase4/D5-sensor-node.md` §1.0). There are ten paths, F1 to F10, by which a sensor's work on the node can reach SER collection, Syslog receive, forwarding or the node's start. **Each is `desk`:** read from the code on `main` at `551b03dd` by D5 and D6, checked by `records-auditor`, and **not reproduced by a run.** D3's reviews of #628 read the code for them and agreed. D3 did not derive them again for this change.

| | What it does | What it needs |
| --- | --- | --- |
| F1 | A full `platform` class holds collection runs, and a sensor's health events are written to that class | A feeding sensor |
| F2 | A fault in the intake's start fails the node's start | **The section alone** |
| F3 | The sensor's work, with a detector drive that has no bound, runs inside the node's tick | A feeding sensor |
| F4 | The scheduler's run path waits on the link's lock | A feeding sensor |
| F5 | The tick holds the state lock across a database's resume, and every store call of collection waits on that lock | **The section alone** |
| F6 | One prune mutex covers every database, and collection takes it on the run path | **The section alone** |
| F7 | A database that opens and then fails a read fails the node's start | **The section alone** |
| F8 | A required audit consumer whose cursor stops holds the audit stream. It is a property of the design in #628's first text, and not of `main` | That design |
| F9 | A mode change of any database writes an audit record and a health event, with no cap | **The section alone** |
| F10 | One forwarder session carries every stream, so a sensor database that is not open ends a target's forwarding of SER and Syslog events too | **The section alone** |

- **No record can arrive from a sensor today:** no product code calls `ServeSensor` or `sensorlink.Link.Serve`. **But F2, F5 to F7, F9 and F10 need only a `network_sensor` section in the node's configuration, and no sensor at all.** `main` accepts that section, with `evidence_class` `simulated`. D3's review of `a50ee61c` said that none could be reached today. That was wrong, and this is the corrected statement (D6 on #629; D3 on #628 at `9cc92358`).
- **D1's gate** (comment 6803782160 on #628; D4-87):
  1. until F1 to F10 are closed, no configuration outside the tests carries a `network_sensor` section;
  2. it is a release blocker;
  3. closing them is the first brief of the third part, to D5, each with its test and its control (#628 §1.9), reviewed by D6 and D3;
  4. no caller of `ServeSensor` or `sensorlink.Link.Serve` merges before then.
- **Point 1 is a rule on people.** The binary still accepts the section. So until the couplings are closed the control is procedural, and the finding stays open as a release blocker.
- HR-13 is the precedent that one link's fault must not stop the node. The threat model records the couplings in AP-19 and AP-34 (5).

- *Answers:* AP-19, AP-34 (5).
- *Test:* SL-T13, whose legs and controls are #628 §1.9 item 8's.

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
| **Temporary files** | A private, memory-backed directory for each of the four programs. |
| **Swap** | None. No swap device or file, and no hibernation. |
| **Core dumps** | Off for the socket holder, the frame stage, the engine and the link agent, and no kernel crash dump. A crash is counted, and is never written out. |
| **The system log** | The link agent never logs record bytes. The engine's standard output and error can hold text from packets, so they go to a bounded, memory-backed log. |
| **The link** | C13 records only (SL-19), whose cited frames are already redacted. |

- **A slot that cannot be placed fails closed and is counted,** as D4-67 rules: the bytes of the side that carries it are not written anywhere, and C13's `logins_not_placed` counter shows it in the heartbeat.
- **Redaction cannot be switched off in anything a site could run** (D1's ruling on #624). SL-T15's control for frames switches redaction off for one named slot. That switch exists only in a test-only build of the frame stage, which is the program that redacts (SL-3), and it is set in the rig's own configuration. The site's binary does not contain it: its strict configuration reader refuses, at start, a configuration that names the switch, and a build check shows that the switch is absent from the site binary. SL-T15 shows the refusal. **What this does not stop:** root on the sensor host can still run a test build. That is an edit of the host, and what shows it is the configuration digest seen at the node (SL-19; D4 on #624 at `ca96b813`).
- **What this does not cover.** Live packets in memory hold every cleartext secret on the mirrored segment, the two pipes of SL-3 among them, which carry unredacted frames and are never files. Root on the sensor host reads the wire in any case. That is HR-21, and no rule here closes it.
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

- **AP-31 (1), pinned and never fetched,** applies in full and to more than a driver: the engine, each engine package (ICSNPP) and the project's sensor programs are at pinned versions, carried by a signed release, listed in an SBOM, and never fetched at install or at run time. **Nothing is fetched at run time** means the sensor host has no route to the internet and no name resolver, and the engine's own fetchers are absent or off: its package manager (`zkg`, ADR-0009), any feed download, and any version check. D7 raised this on #618. **Assumption:** that the engine runs with no route and no resolver, reading a pipe. Under SL-3 it has neither by construction, in an empty network namespace. **E-D4-03 as built does not show the whole of it** (D7 on #625). It runs the engines over capture files in a container with no network, so it can show that an engine completes with no route. It reads no pipe, and it records no attempted lookup or connection. The pipe case is D4's follow-up to #625 (D4-87), and SL-T18 is the test on the real sensor.
- **AP-31 (2), capture rights for the sensor's account only,** becomes: `CAP_NET_RAW` is granted to the socket holder's unit alone, never to the frame stage or the engine, with no `CAP_NET_ADMIN`, and it is dropped once the capture socket is open. The drop keeps a second packet socket from being opened and, with `no_new_privs`, keeps a capability from coming back. It is not a measure against sending.
- **AP-31 (3), receive only,** is AP-32's subject. **An open packet socket can still send after `CAP_NET_RAW` is dropped.** This note took that as an assumption, and the rig has measured it as true: a stand-in that had dropped every capability sent on the socket it held, and set `PACKET_QDISC_BYPASS` on it (`simulated`: run 43077596916, one kernel, on a veth pair). So the capability drop is no barrier to sending, and SL-3 no longer counts it as one. What stands against sending is SL-3's list: a socket holder that parses nothing, its call filter, the egress rule below, and the attachment (AP-32 (1)).
- **The egress rule, in its tested form.** The requirement is named by its test and not by its kind: **on each monitoring interface, a rule that the rig's `PACKET_QDISC_BYPASS` sender does not pass, shown on the sensor image's own kernel, loaded by root before the interface comes up, and one that neither capture account can change.** "An egress filter" is too loose a requirement.
  - **A `tc` filter or a queue rule does not count.** Both sit at the queueing layer, which the bypass option skips by design. Run 43077596916 measured it. Behind a `tc` clsact egress filter that dropped everything, the bypass sender's frame arrived, from root and from the process that had dropped every capability. Behind a queue that dropped everything, root's did.
  - **One mechanism has met the test so far:** an nftables `netdev` chain on the `egress` hook with policy drop. In that run it stopped the host's own stack, an ordinary packet socket and a packet socket with the bypass option, from root and from the process with no capability.
  - **The limits of that measurement:** one kernel (7.0.0-1017-azure), on a veth pair. It shows nothing for another kernel, or for one built without the hook; for a real NIC's driver, offload or firmware (H-18); for any other send path, such as a `write` on the socket, `sendmsg`, a transmit ring, an XDP socket, an XDP program that transmits or the kernel's packet generator, none of which was sent; or against root, who removes the rule. Whether a capture account can change the rule was not measured.
  - **It is a second measure and never the only one.** It is software on the host that is assumed compromised. Against a compromised sensor host only a TAP holds (O-1).
- **The Windows driver text** of AP-31 applies only if option (a) or (c) is reopened.
- *Tests:* SL-T18 for what is fetched, SL-T21 for the egress rule, and R1's `CAP_NET_RAW` case for the drop.

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
| O-1 | **How the sensor attaches at each site,** and with a TAP, which model | **A TAP:** it keeps the sensor host from sending onto the monitored link only if its model gives the monitor port no transmit path into that link. **That is a property of a TAP model, and not of TAPs.** This note as merged in #624 said "receive-only by construction" and did not mark it as an assumption (D6 on #624). It is an **assumption** until two things hold for the model a site uses: its maker's documentation says so, and an H-row shows it. D6 writes that row, and nobody runs it without the owner's authorization. D3 read no TAP's documentation for this note. D3's understanding, not read from a source, is that some devices sold as TAPs can pass frames in from the monitor side: an aggregating TAP built on a switch, a TAP with an injection or bypass function, and a "TAP port" that is a switch's mirror port under another name. **A TAP of a model shown to be receive-only is the only option that holds against a compromised sensor host,** until an H-row shows otherwise for a switch model. It costs hardware for each monitored link, and one for each LAN on PRP. **A mirror port:** it **counts as one that accepts ingress until an H-row shows, for that switch model, that it refuses it** (D6 on #624). C-11 then rests on the sensor host's software alone, and a compromised host can send onto the station LAN (AP-32). D2 reads the SEL switches' mirror port as taking no ingress during a mirror session (`desk`, D2 on #618; not shown on hardware), and nothing relies on that reading. A mirror port needs a change to the switch's configuration, and the H-row needs a switch: each needs the owner's authorization. **A mirror port shown by its H-row to refuse ingress:** holds against a compromised host as far as that switch model does. |
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

**P4-4-L4 wrote them out as clauses:** C7-1 to C7-7 in §11.1 and C8-1 to C8-9 in §11.2, each with the test that would show it. §11.5 lists every denial, reason and record that C13 0.2 (#627) and the node's design (#628) ask of C7 and C8, against the section that asks and the clause that carries it. **Nothing here is built, and every test is a plan.** "Contract test" means a test in `contracts/authz` or `contracts/audit` that D6 writes from this text. A clause marked **new** was not in this section as merged in #624.

### 11.1 C7 0.11 (`otsec.authz/0.11`)

**C7-1. Two admin-signed kinds, each a grant of its own.** `node.sensor_enrol` and `node.sensor_revoke` are gated at minor 11 in `kindSince`, added to `adminKinds`, and **not** added to `DefaultAdminKinds` (SL-7). The payload format stays `otsec.authz.admin-request/0.4`, as for every kind since 0.5: an older reader refuses the new body as a payload error.

- *Test:* contract tests. A key pinned without a list is refused both kinds (`authority`), and so is a key whose list holds only `node.network_baseline_ack`. A key whose list names one of the two signs that one and not the other. A request of either kind stamped 0.10 is refused. *Control:* the kind added to `DefaultAdminKinds` makes the first case pass (SL-T4).

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
	NotAfter      string `json:"not_after"`      // RFC 3339, UTC; at most 366 days after issued_at (the node checks it, C8-2)
	Reason        string `json:"reason"`         // "new", "renew", "rekey" or "replace" (C7-4)
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

**C7-2. The enrolment body's shape.** The collector checks the shape only, as it does for `node.network_baseline_ack`: it does not know the node's sensors. The body is decoded strictly, so an unknown field is refused.

- `sensor_id` is a lowercase UUID.
- `generation` is a decimal from 1 in C13's `seq` form (`^[1-9][0-9]{0,19}$`).
- `sensor_spki` and `node_spki` are each `sha256:` and 64 lowercase hex digits, and the two differ.
- `sensor_address` is an IP literal and a port from 1 to 65535. C13 sets no default port, so the enrolment names it (CH-1). `node_address` is an IP literal. Neither is ever a hostname.
- `not_after` is RFC 3339 in UTC.
- `reason` is one of `new`, `renew`, `rekey` and `replace`. `new` comes with generation 1, and only with it.
- *Test:* contract tests. One golden body is accepted. Each of these is refused as a payload error: a hostname, port 0, an uppercase hex digit, equal pins, generation `0` or `01`, an unknown reason, `new` at generation 2, `renew` at generation 1, and an unknown field. *Control:* a decoder that is not strict accepts the unknown field.

**C7-3. The revocation body's shape.** `sensor_id`, `generation` and `sensor_spki` are as in C7-2. `reason` is one of `compromised`, `lost` and `retired`. `suspect_from` is optional: RFC 3339 in UTC, and **new: not after the request's `issued_at`**. A later value would leave unmarked the records committed before it, which is less than the administrator meant.

- *Test:* contract tests. One golden is accepted, with and without `suspect_from`. An unknown reason, and a `suspect_from` after `issued_at`, are each refused. *Control:* the comparison with `issued_at` removed accepts the second.

**C7-4. The reason agrees with the pin (new).** This is D3's condition on D1's ruling 5 on #627, which C13 0.2 (CH-12) and the node's design (#628 §1.3) both cite. The collector cannot check it, because it does not know the node's sensors. **The node checks it when it applies the request** (SL-6), and the link agent applies the same table to what it holds (SL-5 step 6).

| Reason | The node holds, for that `sensor_id` | The sensor's pin | What it means | What carries over |
| --- | --- | --- | --- | --- |
| `new` | No enrolment of any state | Any | The first enrolment of a sensor | Nothing: run 1 of generation 1 |
| `renew` | An enrolment that is live or expired | **The same** as that enrolment's | The same host and key, with a new `not_after` | The sensor's buffer and run counter, and the node's position (CH-12) |
| `rekey` | An enrolment of any state | **A different one** | The same host made a new key | Nothing: run 1 of the new generation, and the discarded records declared |
| `replace` | An enrolment of any state | **A different one** | Another host, or a re-imaged one, takes the `sensor_id` | Nothing, and the node writes its own count of the old generation's unsent tail, because the old host may never declare it (CH-12) |

- Any other pairing is `denied`, with reason code `reason` (C8-2), and changes nothing.
- **The node decides what carries over from the pin being unchanged and the reason `renew`, never from the reason alone.** `rekey` and `replace` differ only in what the administrator states. The node cannot tell which is true, and it records which was signed.
- **With the previous state unknown** (SL-6's limit), the node cannot show that the pin is unchanged. A `renew` is then `denied` (`reason`), and nothing carries over. A `rekey` or a `replace` is applied without the pin comparison, and the record says that the previous state was unknown (C8-2).
- **At the link agent:** it accepts a `renew` only when it holds the previous generation under the same key, and it then keeps its run counter and its buffer. On any other reason it starts run 1 and declares what it discards. It refuses a `rekey` or a `replace` that names the key of the generation it already holds.
- *Test:* a node test and, for the agent, a rig leg of SL-T4. Each of these is `denied` (`reason`) with nothing changed: a `renew` with another pin; a `rekey` and a `replace` with the same pin; a `new` for a `sensor_id` that has an enrolment; a `renew` with the previous state unknown. A `renew` with the same pin resumes the old runs (#628's `TestRenewCarriesPosition`). *Control:* a node that decides the carry-over from the reason alone resumes the old runs under a new key.

**C7-5. What the collector does, and does not do.** Signature, the key's kinds, the nonce, the window, the binding to this node and the numbering are as for every admin kind (`VerifyAdminRequest`). A refusal names no target. An acceptance is the reply's `admin` object, as for every admin kind, and it carries no sensor field: the node reads the body it relayed once the acceptance names that body's hash. The collector opens no connection to a sensor host and keeps nothing about sensors.

- **Not proposed:** a check at the collector that the sensor's address is no asset's. The check is the node's, which makes the dial and repeats the check at each one (SL-9), and it needs no second copy in the privileged process.
- *Test:* contract tests, as for `node.network_baseline_ack`: a wrong signature, a kind that is not in the key's list, a spent nonce, an expired window and another node's binding are each refused, and no refusal names a target.

**C7-6. A verification without a collector, for the sensor's end only.** The link agent checks an enrolment's signature (SL-5 step 6) with none of the collector's state. That needs an exported function that makes the envelope, key, signature and payload checks and returns the decoded request, without the binding, window and replay checks. Its documentation must say that it is for the sensor's end only. **An import test must show that neither of today's product binaries, `cmd/otsec` and `cmd/otsec-collector`, can reach it** (D1's ruling on #624), so it belongs in a package that only the sensor's program imports. A sensor whose end was pinned this way states `pinned_by: signature` (CH-33).

- *Test:* the import test (SL-T4). On the rig, the agent refuses an enrolment with a bad signature, one that names another key, and one whose generation is not above the one it holds. *Control:* an import of the verifier added to the node fails the import test.

**C7-7. Schema and goldens.** `schema/admin-request.json` gains the two kinds and bodies, with one golden of each.

- *Test:* the schema test that pins the goldens.

### 11.2 C8 0.13 (`otsec.audit/0.13`)

**C8-1. Three actions, written by the node,** gated at minor 13 in `actionSince`: `sensor.enrolled`, `sensor.revoked` and `sensor.link_refused`. The target is the sensor (`Target.sensor_id`, since 0.12), and no asset. Readers go before writers, as #532 §7 set: the 0.13 reader ships in a build before the first build that writes a 0.13 record.

- *Test:* contract tests. Each action stamped 0.12 is refused. Each is refused without a `sensor_id` target, and with an asset target. A 0.12 reader refuses a 0.13 record.

| Action | When | Carries | Outcome |
| --- | --- | --- | --- |
| `sensor.enrolled` | Before the node records an enrolment (SL-5 step 5) | `decision_seq` and `payload_sha256`, as the acknowledgement records carry them; a `sensor` object with the body's fields; what it replaces (C8-2) | `succeeded`, or `denied` with one reason code (C8-2) |
| `sensor.revoked` | After the link is closed (SL-R2). It may be written late (C8-3) | `decision_seq`, `payload_sha256`, generation, pin, reason, `suspect_from` when given; `applied_at`; `streams`, each stream of the sensor with its `through_seq`; `baseline_digest`, the acknowledgement it voids, when there is one | `succeeded`, or `denied` (`no-enrolment`) |
| `sensor.link_refused` | A peer failed authentication or binding (C8-4) | generation; one reason from a closed set of six; `count`, the refusals of that reason since its last record | `denied` |

**C8-2. `sensor.enrolled`.** It is written before the node applies an enrolment, and if the write fails nothing is applied (SL-5 step 5). It carries `decision_seq` and `payload_sha256`; a `sensor` object with the body's fields (`generation`, `sensor_spki`, `sensor_address`, `node_spki`, `node_address`, `not_after`, `reason`); and what it replaces:

- `previous_generation` and `previous_spki`, when the node holds an earlier enrolment of that `sensor_id`;
- **new:** `previous_state` with the one value `unknown`, when the node's sensor state was unknown (SL-6's limit; #628 §1.3). It never comes with the other two;
- none of the three for a first enrolment.

The outcome is `succeeded`, or `denied` with one reason code. **The checks run in this order, so that one request has one reason:**

| | Reason code | When |
| --- | --- | --- |
| 1 | `node-key` | `node_spki` is not the pin of the node's own link key |
| 2 | `generation` | The generation is not one above the last enrolment of that `sensor_id`, or not 1 for a new one. With the previous state unknown: it is not above every generation of that `sensor_id` still in the chain |
| 3 | `revoked-key` | The sensor's pin is one the node has revoked, under any `sensor_id` |
| 4 | `forked-key` | The sensor's pin is one the node holds for a fork (SL-16) |
| 5 | `reason` (**new**) | The reason does not agree with the pin (C7-4) |
| 6 | `not-after` | `not_after` is more than 366 days after the request's `issued_at`, or not after it |
| 7 | `asset-address` (**new**) | The sensor's address is the address of an asset in the node's configuration, compared on the IP alone (SL-9; D1's ruling 5 on #628) |

- *Test:* the node's `TestSensorEnrolDenied` for each code, and `TestSensorEnrolAuditFirst` (#628 §1.3), with `reason` added to the first. A request that fails two checks carries the earlier one's code. Contract tests: a `denied` record whose code is outside the set is refused; so is a record that carries `previous_state` with `previous_generation`. *Control:* a node that applies before the audit write applies an enrolment whose record failed.

**C8-3. `sensor.revoked`.** It is written **after** the link is closed (SL-R2), and **it may be written late.** It is owed from the close until the node holds both `through_seq` values and the chain takes the write, and then it is written once.

- `streams` names each stream of the sensor with its `through_seq`. The observation stream's is taken after the connection's read loop has returned and the held records are committed. The alert stream's is taken once the detector has judged every observation at or below it (SL-R3; #628 §1.3).
- **New:** `applied_at`, the node's time when it marked the pin revoked and closed the link. A record written hours later then still says when trust ended. It is never after the record's own time.
- `denied` (`no-enrolment`) when the node holds no enrolment with that `sensor_id`, generation and pin that is not already revoked. A fork-held or an expired enrolment can be revoked.
- *Test:* SL-T10, with its legs for a failed audit write and for a node killed between the close and the write. The node's `TestSensorRevokeClosesFirst`, `TestSensorRevokeAfterReadLoop` and `TestSensorRevokeAlertThrough` (#628 §1.3). Contract tests: a succeeded `sensor.revoked` without `applied_at` or `streams` is refused, and so is an `applied_at` after the record's time. *Control:* a node that applies the revocation only after the audit write keeps the link open when the write fails.

**C8-4. `sensor.link_refused`, and its six reasons.** It carries the generation, one reason and `count`. The set is closed, and C13 0.2 relies on its being six (CH-11).

| Reason | What it covers in C13 0.2 |
| --- | --- |
| `peer-key` | A handshake whose key's pin is not the enrolment's (CH-1) |
| `expired` | A dial that would be due after `not_after`. The node does not make it (CH-1; #628 §1.3) |
| `binding` | A hello whose `sensor_id` or generation differ from the enrolment of the key that authenticated; or a `pinned_by` that differs from the first value of the generation (CH-11, CH-13 rows 2 and 7, CH-33). The record does not say which of the three it was. Status and the alarm do |
| `run-regressed` | A run counter below the highest accepted, or a resume whose newest `seq` is below the `seq` the node took (CH-13 rows 3 and 5a) |
| `run-forked` | The highest counter under another `run_id` (CH-13 row 4). The link is held (SL-16), and the node's fold derives the hold from this record when the held state could not be written (#628 §1.3) |
| `sensor-id` | A record, or a tick, under another `sensor_id` (CH-14, CH-8; SL-10) |

- *Test:* SL-T3 (c) for `peer-key`, SL-T5 for `expired`, SL-T6 for `sensor-id`, SL-T9 (b) and (e) for the two run reasons, and C13 0.2's G-4 for `binding` by `pinned_by`. A contract test pins the six, and refuses a seventh.

**C8-5. `sensor.link_refused` is capped twice: by stretch and by time.** It is written at most once for each sensor and reason in a stretch, and a stretch ends at the next accepted hello. That alone is not a bound, because an enrolled sensor produces accepted hellos at will (D6 on #624). So it is also written **at most once an hour for each sensor and reason,** on the node's monotonic clock: with six reasons, at most six records an hour for each enrolled sensor, whatever the sensor or anyone at its address does. Refusals past the cap are counted in health and status, and the next record's `count` carries them.

- **A restart does not start the hour again** (D5 on #624 at `ca96b813`). A sensor cannot restart the node. But if it could make the node crash, the service manager would start it again after 60 s, and a cap that began afresh at each start would allow about 8,600 records a day for each sensor.
- **Where the cap is kept across a restart.** The node keeps each sensor's and reason's last record time in a state file of its own, written with each record, and holds the cap from that time (`sensorrun.json`; #628 §1.9 item 6). **This replaces the audit read at start** that this section as merged in #624 relied on: that read runs only when the node has event baselines (D6's note on #624; D5 on #628). An unreadable file, or a fold that fails, holds the cap from the start and never fails the start. A time after now is taken as now. That one comparison is on the wall clock, because a record's time is all that survives a restart; within a run the monotonic clock holds.
- **Why the cap is a safety matter.** A full audit store stops credentialed collection (D1-11, V-S9, `TestAuditFullSendsNothing`). Without the time cap, a compromised sensor could fill the audit class and stop SER collection, against SL-20 and the gate.
- **A limit that D3 found while writing this out, and that neither document has.** The cap's key is the sensor and the reason. If one sensor forks, is enrolled again with a new key, and forks again inside the same hour, the second `run-forked` writes no record. The hold is then in the node's state file alone. If that write also fails, the next start has nothing to derive the hold from, and the node dials a sensor it should hold. It takes three faults in an hour, one of them a site visit. **The remedy D3 proposes, for D5 and D1 to take or refuse:** the cap's hour starts again for a sensor at each succeeded `sensor.enrolled` of it. A sensor cannot cause one, so the bound on what a sensor can drive is unchanged. Until it is ruled, it is a stated limit and not a clause.
- *Test:* SL-T13's audit leg, which is leg (d) of #628 §1.9 item 8. *Control:* that item's control (3): the time cap removed, or started afresh at each start.

**C8-6. The relayed `collector.request` names the sensor target, as fields (new).** The node's design asks for it (#628 §1.3, §1.11). On the node's `collector.request` record of a relayed `node.sensor_enrol` or `node.sensor_revoke`, **only when the outcome is `allowed` and the record carries `verified`,** the record also carries `Target.sensor_id` and a `sensor` object with the verified body's `generation` and `sensor_spki`, and for a revocation its `reason` and `suspect_from`.

- They are fields, and never text in `detail`, so that the node's fold never parses prose.
- The `info` record, whose claims nothing has checked, and a `denied` record name no target, as today.
- Today `sensor_id` is refused on any record but the network ones (`validateNetwork`, `contracts/audit/network.go`). 0.13 admits it on `collector.request` under exactly these conditions.
- **Why.** The node acts on a revocation before it writes `sensor.revoked` (SL-R2). If its state file cannot be written and the node then restarts, the collector's decision is the only durable trace. The fold must be able to derive the revocation from it, and to write the `sensor.revoked` that is owed.
- *Test:* contract tests. A `collector.request` with a sensor target is refused when its outcome is `info` or `denied`, when it has no `verified`, and when `verified.kind` is neither of the two kinds. One that is allowed and verified for either kind, stamped 0.13, is refused without the target. On the node: `TestSensorUnreadAtStartDialsNothing` (#628 §1.3). *Control:* with the target in `detail` only, the fold derives nothing and the node dials the revoked sensor.

**C8-7. What is not an audit record.** A link that opens or closes is not one. Only the six reasons of C8-4 write `sensor.link_refused` (CH-11). A close for an enrolment decision writes none of its own: the decision's records are `sensor.enrolled` or `sensor.revoked` (CH-37). The node's `sensor.coverage-gap` health events record a link's stretches, under their own cap (#628 §1.9 item 5), and a reconnect loop would otherwise write to the chain at will.

- **`sensor.enrolled` and `sensor.revoked` cannot be driven by a sensor.** Each follows an admin-signed request that the collector accepted, and its nonce is spent once.
- *Test:* SL-T13's legs (b) and (h) of #628 §1.9 item 8: a connection killed every 5 s, and a clean close after every hello, add no audit record. *Control:* a record for each close fills the small audit class and stops credentialed collection.

**C8-8. Chain checks** (`VerifyChain`), as far as a view shows:

- a succeeded `sensor.enrolled` carries a generation one above that sensor's last succeeded enrolment, unless it carries `previous_state`;
- after a succeeded `sensor.revoked`, no later `sensor.enrolled` succeeds with that pin, under any `sensor_id`;
- **new:** a succeeded `sensor.enrolled` or `sensor.revoked` follows an allowed, verified `collector.request` whose `collector_seq` is the record's `decision_seq`, with the same `sensor_id` and payload hash (C8-6), and there is at most one succeeded `sensor.revoked` for one `decision_seq`;
- **new:** where `previous_spki` is present, a `renew` carries a pin equal to it, and a `rekey` or a `replace` a different one (C7-4);
- C8 0.12's rule for `admin_keys` covers both kinds as it stands: a decision is applied only under a `policy.apply` that shows the signing key holds the kind.
- *Test:* contract tests, one chain that breaks each rule. *Control:* each rule removed in turn accepts its chain.

**C8-9. A reader's rule, and the schema.** A `config.baseline_acknowledged` of kind `network` that precedes the latest `sensor.revoked` for its sensor is not in force (SL-R5). That is a reader's rule, and not a chain break. `schema/record.json` gains the three actions, the `sensor` object, `streams`, `applied_at`, `previous_state` and the reason codes, with a golden of each record.

- *Test:* the schema's goldens; and SL-T10's baseline legs, which wait until the node applies `node.network_baseline_ack` (#628 §1.12).

### 11.3 Not a contract: the alarms

The node's alarm codes are D5's to name. This note as merged in #624 used draft names, and they give way to the names in the node's design and in C13 0.2's CH-45: `sensor-not-enrolled`, `sensor-identity` (SL-10), `sensor-gap-undeclared` (SL-14), `sensor-baseline-void` (SL-R5), `sensor-enrolment-expiring` and `sensor-enrolment-expired` (SL-8), `sensor-revoke-pending` (SL-R2), `sensor-address-is-asset` (SL-9), `sensor-pinned-by-console` (SL-5), `sensor-state-unknown` and `sensor-state-unread` (SL-6), `sensor-clock-skew` (SL-17), `sensor-blind` and `sensor-unreachable`. None is in the C6 or C8 enumerations.

### 11.4 Not a contract: the link-key kind in the node key register

`modules/security/nodekey` is D3's own module. The node's design asks it for the link key (#628 §1.1, §1.11), and D1 puts the change in a brief of the third part (ruling 15 on #628). It is written out here so that the set can be read as one. **None of it is built.**

- **NK-1. A kind of its own,** `link-key`, beside `tls-key` and `trust-anchors`. It is not a mark on `tls-key`, so every existing reader refuses it by default and no key gains a use silently (D4-68 rulings 8 and 9). **`LoadCertificate` refuses it:** today that function loads an active entry of kind `tls-key` only (`register.go`, `desk`), and it stays so. A listener or a forward target therefore cannot use the link key.
- **NK-2. No other key can serve a sensor link.** One accessor returns the signer and the pin of a `link-key` entry, and refuses every other kind. It sits in a package that only `platform/sensorlink` imports, shown by an import test.
- **NK-3. No certificate chain and no pending state.** A `tls-key` stays `pending` until a CA chain is installed. A link key has no CA (SL-2), so its entry is active once it is made: an ECDSA P-256 key, under the same non-exportable providers. The self-signed certificate of the handshake is made in memory at each node start and is never stored (#628 §1.1).
- **NK-4. The pin is in status,** for the administrator to read at enrolment (SL-5 step 2).
- **NK-5. A fault in a `link-key` entry holds back the sensor links only (new).** Today one entry that fails its checks fails the whole register, and the node's start with it (`Entry.validate`, `desk`; HR-13: every register fault but a certificate's period stops the node at start). Left so, a damaged link-key entry would stop SER and Syslog collection, against SL-20. The other entries must load, the node must start, and an alarm must stand.
- **NK-6. The reader ships before the writer (new).** A build that does not know the kind refuses a register that holds one (`Entry.validate` ends in `kind %q`, `desk`), so a node rolled back to such a build would not start. The build that first reads `link-key` ships before the first build that makes one, and D7 records that build as a release floor, as it does for the checkpoint reader.
- **Limit.** A local administrator can use the key (D3-7). Replacing it is SL-R8: every sensor is enrolled again.
- *Tests:* `LoadCertificate` on a `link-key` reference is refused, and the accessor on a `tls-key` reference is refused. The import test. A register whose only fault is in its `link-key` entry: the node starts, stores a run and raises the alarm, and no sensor is dialled. *Controls:* a kind check removed from `LoadCertificate` loads the link key for a listener; and today's whole-register refusal fails the node's start.

### 11.5 What the two documents ask of C7 and C8

Read from `docs/phase4/D4-c13-0.2-proposal.md` (#627) and Part 1 of `docs/phase4/D5-sensor-node.md` (#628) on `main` at `8ecdecc6`, by searching both for every mention of C7, C8, the two kinds, the three actions, `collector.request`, `policy.apply`, `denied` and each reason code. "No clause" means that the contract as it stands already carries it, and the row says why.

| | What is asked | Asked by | Carried by |
| --- | --- | --- | --- |
| 1 | The two kinds, as §11.1 proposes them, relayed and applied by the node | #628 §1.3 ("Enrolment"), §1.11 | C7-1, C7-2, C7-3 |
| 2 | The enrolment names the sensor's address and its port, the two pins and `not_after` | #627 CH-1; #628 §1.2 | C7-2 |
| 3 | A signed `reason` that the node and the agent can read: `new`, `renew`, `rekey`, `replace` | #627 CH-12, CH-18; #628 §1.3 | C7-2 |
| 4 | `renew` needs the same pin, and `rekey` and `replace` a different one, each `denied` otherwise | #627 CH-12; #628 §1.3 ("What a new enrolment does to the position") | C7-4; the code `reason` in C8-2 |
| 5 | An enrolment with a new key after a fork, and when a run counter reaches its ceiling | #627 CH-13 row 4, CH-5 | C7-4 (`rekey`); `forked-key` in C8-2 |
| 6 | The agent verifies the enrolment's signature, and says so (`pinned_by: signature`) | #627 CH-33 | C7-6 |
| 7 | A pending `node.sensor_revoke` request is read for its `sensor_id` and pin before any signature check | #628 §1.3 (the fast path) | C7-3's fields. No change to C7: the read is the node's own, and it can only stop a link |
| 8 | A request's own expiry lifts the fast path | #628 §1.3 | No clause: the envelope's `expires_at`, as C7 0.4 has it |
| 9 | `policy.apply` with `admin_keys` before a key's first use of either kind | #628 §1.3 step 1 | No clause: C8 0.12's rule, which C8-8 keeps |
| 10 | `sensor.enrolled`, written before the node applies, and nothing applied if the write fails | #628 §1.3 steps 2 and 3 | C8-1, C8-2 |
| 11 | The denial reasons `generation`, `revoked-key`, `forked-key`, `node-key` and `not-after` | #628 §1.3 step 2 and its tests | C8-2 |
| 12 | The denial reason `asset-address` | #628 §1.1, §1.3, §1.11 (D1's ruling 5) | C8-2 |
| 13 | `sensor.enrolled` records the previous state as unknown | #628 §1.3 ("With the file lost") | C8-2 (`previous_state`) |
| 14 | Each enrolment's `decision_seq` and payload hash, shown in status for comparison with a copy of the chain | #628 §1.3 (`sensors.json`; the limit) | C8-2 |
| 15 | `sensor.revoked` after the close, with both `through_seq` values, owed until the alert stream's is taken, and written late | #627 CH-37 step 4; #628 §1.3 ("Revocation", steps 4 and 5), §1.11 | C8-3 |
| 16 | The relayed `collector.request` names the sensor target as fields, only for an accepted, verified request | #628 §1.3, §1.11 | C8-6 |
| 17 | `sensor.link_refused` for `peer-key` and `expired` | #627 CH-1; #628 §1.3 ("Expiry") | C8-4 |
| 18 | `binding`, for a hello's `sensor_id` or generation, and for a changed `pinned_by` | #627 CH-11, CH-13 rows 2 and 7, CH-33 | C8-4 |
| 19 | `run-regressed`, for a lower counter and for a resume below what the node took | #627 CH-11, CH-13 rows 3 and 5a; #628 §1.4 | C8-4 |
| 20 | `run-forked`, and the hold derived from its record at the next start | #627 CH-11, CH-13 row 4; #628 §1.3 (a failed write of `fork-held`) | C8-4 |
| 21 | `sensor-id`, for a record and for a tick under another `sensor_id` | #627 CH-11, CH-14, CH-8; #628 §1.9 item 6 | C8-4 |
| 22 | Only six reasons write `sensor.link_refused` | #627 CH-11 | C8-4 |
| 23 | The cap of one record an hour for each sensor and reason, kept across a restart; an unreadable state holds it; a later time is read as now | #627 CH-1, CH-45; #628 §1.9 item 6, §1.10 | C8-5 |
| 24 | `count` carries the refusals past the cap | #628 §1.10 | C8-4, C8-5 |
| 25 | No audit record for a link that opens or closes, nor for an `enrolment` or a `shutdown` close | #627 CH-11, CH-37, CH-38 | C8-7 |
| 26 | The other audit records of a sensor's work are caused by an administrator | #628 §1.9 item 6 | C8-7 |
| 27 | An acknowledgement made before the latest `sensor.revoked` of its sensor is not in force | #628 §1.12 item 5 | C8-9 |
| 28 | `config.baseline_acknowledged` of kind `network`, `denied` with the adoption's reason | #628 §1.12 item 3 | No clause: C8 0.12 as it stands |
| 29 | A sensor database's `store.mode_change` at most once an hour, the rest counted in the next record's detail | #628 §1.9 item 1 (F9) | No clause: C8 names the action and its reason code, and has no rule that every mode change is recorded (`contracts/audit`, `desk`). The count rides in `detail`, which no fold reads. A reader of the chain then cannot rebuild every mode of a sensor's database, which D3 accepts for those databases only |
| 30 | A health event named `sensor.revoked` on the health stream | #628 §1.3 ("Revocation", step 6) | Not C8's: it is a health event that shares the action's name. D3 asks D5 for a name that differs, as `store.mode-changed` differs from `store.mode_change` |
| 31 | A link-key kind in the node key register that `LoadCertificate` refuses | #628 §1.1, §1.11 (D1's ruling 15) | Not a contract: §11.4, NK-1 to NK-6 |

## 12. The tests

Each is a case for D6's rig (P4-4-R1) or a contract test. "Control" is the change that must make the test fail. Where a row says H-row, only a machine can show it, and nobody runs it without the owner's authorization.

**The sensor needs a root file system of its own in the rig** (D6 on #624). Without one, SL-T1, SL-T14, SL-T15 and SL-T16 search the runner's file system and mean nothing.

**What the rig can host as built** (D6's note `docs/phase4/D6-sensor-rig.md`, in PR #626 at `554e065b`): one monitoring interface on a veth pair, and a process on it. It cannot yet host SL-T19, which needs three namespaces, or SL-T1, SL-T14, SL-T15 and SL-T16, which need the sensor's own root file system. Its self-tests are results about the rig. None is a result about a sensor, because no sensor exists.

| Test | Shows | How | Control | Where |
| --- | --- | --- | --- | --- |
| SL-T1 | SL-1 | Install the link agent twice from one image in two namespaces: the two pins differ. Search the image for a private key: none. | An image with a key baked in is found by the search. | Rig |
| SL-T2 | SL-3 | From the engine's account, the frame stage's and the socket holder's, opening the key file fails. The frame stage and the engine hold no socket: each one's descriptor list shows none, and each one's network namespace has the loopback interface only and no route. A build check finds no send or inject call linked into the socket holder. The call filter and the split are SL-T22. | Run the engine under the agent's account: the open succeeds. Start the engine in the host's namespace: the interface check fails. **For the build check** (D6 on #624): a test build of the socket holder that links a send call is found by it. | Rig |
| SL-T3 | SL-2, SL-4, SL-5 | (a) A sensor with no enrolment has no open port. (b) A node with a `network_sensor` entry and no enrolment sends no SYN and raises its alarm. (c) A peer with another key at the enrolled address fails the handshake, no record is accepted, and `sensor.link_refused` (`peer-key`) is written. | A node that takes the first key it sees accepts (c). | Rig, over the real link |
| SL-T4 | SL-5 to SL-7 | A key without `node.sensor_enrol` in its list is refused (`authority`), and so is a key that holds only `node.network_baseline_ack`. An enrolment with a skipped or repeated generation, a revoked pin, or another node's pin is `denied`. The agent refuses an enrolment that names another key, a lower generation, or a bad signature. An import test: neither `cmd/otsec` nor `cmd/otsec-collector` can reach the verifier for the sensor's end. | The kind added to `DefaultAdminKinds` makes the first case pass. An import of the verifier added to the node fails the import test. | Contract tests; rig for the agent |
| SL-T5 | SL-8, SL-9 | Change the address, the pin or the `sensor_id` in the configuration after enrolment, one at a time: no SYN leaves and the alarm is raised; restored, the node dials. A node started with a missing or mismatched enrolment, **or with an expired, a revoked or a fork-held one** (D6 on #624), starts, collects SER and Syslog, sends no SYN to that sensor and raises the alarm. So does a node whose sensor entry names an asset's address: the simulator's device address sees no SYN (SL-9). On the test clock: the expiry alarm 30 days before, a running link kept past `not_after`, and a new dial after it refused. | A node that dials from its configuration alone passes none of the first part. A node that fails its start on a sensor's enrolment fails every start leg. | Rig; node tests on the test clock |
| SL-T6 | SL-10 | Two enrolled sensors, A and B. The test-only C13 source, with A's key, sends a record under B's `sensor_id` on A's link: B's streams do not change, A's refusal count rises by one, and the alarm and `sensor.link_refused` (`sensor-id`) follow. | A node that files a record by its own `sensor_id` field stores it in B's stream. | Rig, over the real link (gate) |
| SL-T7 | SL-11, SL-18 | A client with another key, from the node's address: the handshake fails at the sensor and no record byte is sent. From a third address: the firewall refuses. The listener is not bound to a wildcard address, and nothing listens on the monitoring side. | A listener on a wildcard address is found by the bind check. | Rig |
| SL-T8 | SL-12 | A peer that offers TLS 1.2 is refused. A second connection that offers resumption makes a full handshake or fails, and is never resumed. After a re-key, the old key is refused on its next handshake. | Session tickets on: the resumption case passes with the old key. | Rig |
| SL-T9 | SL-13 to SL-16 | (a) A link cut in a run and resumed: every record is in the store once, in order. (b) An earlier run's stream replayed by the test source: `run-regressed`, nothing stored. (c) Records of the current run sent again: dropped as duplicates. (d) A re-ordered stream: the earlier `seq` refused. (e) A second source with the same key and counter and another `run_id`: `run-forked`, and the link is held. (f) A gap the sensor does not declare: the alarm. (g) After a node restart, (b) and (c) still hold, **and after (e) the held link is still not dialled** (D6 on #624; D3's B4 on #627). (h) A connection's recorded bytes replayed at the node's next dial: the handshake fails. (i) After (e), an enrolment with the same key is `denied` (`forked-key`), and one with a new key is dialled. (j) The agent killed just after its hello and started again: a new run, and no fork. (k) The engine restarted alone: the run counter rises. | A node that keeps no run counter accepts (b) and (e). An agent that sends its hello before it syncs the counter turns (j) into a fork. A node that keeps the fork hold in memory only dials again after the restart in (g). | Rig, over the real link (gate: "a replayed stream is refused") |
| SL-T10 | SL-R1 to SL-R6 | Revoke over the real link: the connection closes within the rig's bound and no SYN follows. `sensor.revoked` is in the chain with each stream's `through_seq`. The earlier records are still stored, and the reader reports them marked. The same pin enrolled again is `denied`. A new key at the next generation is dialled. The baseline's rules stay off and the standing alarm is up until a new acknowledgement. With the audit write made to fail, the link still closes and the record is written later. **With the node killed between the close and the write:** after the restart the link stays closed, the record shows as owed, and it is written once. With records held at intake when the revocation lands: each is at or below `through_seq`. A re-key keeps the acknowledgement. The legs on the baseline wait until the node applies `node.network_baseline_ack`. | A node that applies the revocation only after the audit write keeps the link open when the write fails. | Rig (gate: "a revoked one") |
| SL-T11 | SL-18 | The node's listening ports are the same set with sensors configured and without. From the sensor's namespace, no port on the node answers beyond that set. | A node built with a listener for sensors shows a new port. | Rig (gate: "no inbound port") |
| SL-T12 | SL-19, SL-R7 | Messages from the node's side that are of an unknown type, oversized, shaped like a setting, or an acknowledgement above the highest `seq` sent: the sensor's configuration, its rule set and its interface state are unchanged, the message is counted, and the connection closes. A contract test pins the closed set of message types in each direction: two from the node, and four from the sensor. **After a revocation (SL-R7):** the sensor's end reads a TLS close and no message, and its configuration, rule set and interface state are unchanged. **The digest, on the site build:** an allow-list widened by a local edit changes the configuration digest, and the node raises `sensor-coverage-mismatch`. **The digest, on the test-only build:** a redaction slot switched off changes it too. That leg cannot run on the site build, which refuses such a configuration at start (SL-T15; D6 on #624; C13 0.2's G-2). | An agent that accepts a setting changes its configuration. A node that sends a message at a revocation is seen at the sensor's end. On the test-only build, a digest that leaves the redaction slots out does not change. | Rig; contract test |
| SL-T13 | SL-20, §11.2 | P4-4-L3 item 8's test, whose legs (a) to (h) and controls (1) to (5) are in #628 §1.9 item 8: a flood, a cut and a blind sensor over the real link while SER and Syslog run, with no loss and no drop in their throughput. **The audit leg:** with a small audit class, a sensor that alternates accepted hellos with refused ones for longer than the cap's hour, under every reason it can cause: the `sensor.link_refused` records stay within the cap, the audit store does not fill, and SER collection goes on. **With the node restarted repeatedly under the same flood,** the count still holds. | For the audit leg: with the time cap removed, the audit class fills and credentialed collection stops; and with a cap that begins afresh at each start, the restart leg exceeds the count. For the flood: D3 proposes the observation class's quota check removed, so that the flood takes the volume; D5 may name a better one with P4-4-L3. | Rig (gate) |
| SL-T14 | SL-21 | A search of the sensor host's whole file system for every test secret of the platform's run finds none: the device passwords, the USM keys and the administrators' private test keys. | A test credential planted on the sensor host is found. | Rig |
| SL-T15 | SL-22 | Replay the GT-PCAP cases that hold third-party test secrets in every slot through the real sensor. Then search its file system, its memory-backed directories, the ring, the agent's buffer, the system log and the link's bytes as the node reads them. The image's configuration names no swap and no dump target. After a forced crash of each of the four programs, no dump file exists and the search is still clean. A secret planted in the ring's directory is found in every run, which shows that the search sees the ring at all. **The refusal:** the build a site would run, started on the rig's configuration with a redaction slot off, refuses to start, and a build check finds the switch absent from that binary. | **Two controls, one for each half of the search** (D1's ruling on #624), and two more for the build check and the crash leg. **(1) The engine-output half:** the allow-list is widened to pass a stream that is not listed. That stream must then carry the planted secret to where the search finds it, which shows that the allow-list is what kept it out (D4). **(2) The frame half, the ring and the link's bytes:** redaction is switched off for one named slot, in the rig's own configuration and never in a build a site could run. The search must then find the secret in the ring and on the link, which shows that redaction is what kept it out (D6). **(3) The build check** (D6 on #624): a build with the switch compiled in is found by the check. **(4) The crash leg** (D6 on #624): with core dumps switched on for one program in the rig's image, its forced crash leaves a dump, and the search finds the secret in it. For the refusal: a build that honours the switch outside the rig starts, and the leg fails. | Rig (gate: AP-33's key search); an H-row for swap and the kernel crash dump on a running machine |
| SL-T16 | SL-23 | On the built image: no account has a password that a network login accepts, no account is shared, and nothing listens on the management interface but the link's port and whatever O-5 allows. | An image with a password login is found. | Rig for the image; an H-row for the machine |
| SL-T17 | SL-25 | The updater refuses a tampered package, one below the floor and an unsigned one, and installs a good one. | Each refusal removed in turn. | Not possible until an updater exists |
| SL-T18 | SL-26 | With no route out of the sensor's namespace, a full replay runs, and the capture of the management interface shows the link's traffic only: no name lookup and no other connection. The installed versions equal the pins. | A sensor set to fetch a package shows the attempt. | Rig |
| SL-T19 | SL-28 | With two monitoring interfaces and the management interface in three namespaces, a frame sent into one never appears on another, and forwarding is off. | Forwarding switched on shows the frame. | Rig; O-1 decides what holds on a machine |
| SL-T20 | SL-R8 | The node's link key is replaced. **At the sensor:** it refuses the node's handshake and sends no record. **At the node** (D6 on #624): it starts and collects SER and Syslog, no hello is accepted from a sensor that is enrolled under the old node pin, and an enrolment that names the old node pin is `denied` (`node-key`). After a new enrolment at the next generation, taken at the sensor's console, the link comes up. | An agent that accepts any client key from the node's address keeps the link up after the key change. A node that does not compare the node pin applies the old enrolment. | Rig |
| SL-T21 | SL-26 | **The egress rule in its tested form,** on the sensor image's own kernel, with the rule loaded before the monitoring interface comes up. A stand-in under the socket holder's account, with no call filter, holds a packet socket opened before it dropped every capability. It tries each send path in turn: an ordinary send, a send with `PACKET_QDISC_BYPASS`, a `write`, `sendmsg` and a transmit ring. No frame reaches the rig's far end. From either capture account, changing or removing the rule fails. | The rule removed: the frames arrive. A `tc` egress filter in its place: the bypass sender's frame arrives, as run 43077596916 measured on one kernel, on a veth pair. | Rig; H-18 (d) for a real NIC |
| SL-T22 | SL-3 | **The socket holder's call filter, and the split,** with the egress rule removed so that the filter alone is tested. A stand-in under the socket holder's profile tries each send path of SL-T21, a `setsockopt`, a new socket, a copy of a descriptor and the set-up of the asynchronous interface. Each is refused, no frame reaches the rig's far end, and the stand-in still receives every replayed frame. The frames reach the frame stage complete and in order, by hash. With the frame stage stopped, the pipe fills and the loss is counted. | The same stand-in with no profile sends, as run 43077596916 shows on one kernel, on a veth pair. A frame stage started with a socket is found by the descriptor check of SL-T2. | Rig |

**H-rows that D6 has yet to name** (D6 on #624), each written and not run:

- whether a mirror port refuses ingress, for each switch model (O-1, AP-32 (1));
- **whether a TAP's monitor port can send into the monitored link, for each TAP model** (O-1; D6 on #624). H-18 as PR #626 writes it sends a control frame from the monitoring NIC on a TAP and says that the frame goes nowhere. That is the assumption this row has to test, so it has to look for the frame on the monitored link;
- the egress rule and the call filter on the sensor image's own kernel and on a real NIC, with the frame sent by a process that dropped every capability (H-18 (d); SL-T21, SL-T22);
- a TPM-held key cannot be copied off the machine (O-2);
- no swap and no kernel crash dump on the running machine, which SL-T15 cannot show on a hosted runner;
- SL-24's custody and SL-27's out-of-band controller.

**The one rule with no test in this note** is SL-17, whose tests C13 0.2 and the node's design name (SL-17). SL-29 is covered by the C-11 rig once a time client runs in it, which D6 adds (D4-87). SL-R7 is covered by SL-T12, and SL-R8 by SL-T20.

## 13. What D5 and D4 are asked to confirm

D5 and D4 reviewed `2935220a` and passed it with notes. Their notes are in the rules above, and the lists below are as revised.

**P4-4-L4 added items 9 to 12 for D5, items 8 and 9 for D4, and the table of requests to D4.** The brief asks D5 to confirm that the node can do what the additions ask, D4 that the channel carries them, and D6 that each has a test.

**D5, for the node:**

1. A link key in the key register used for sensor links only, and a dialer that checks a pin at every handshake with resumption off (SL-2, SL-12).
2. Saving, with the commit, the highest run counter, its `run_id` and the last committed `seq` for each sensor and generation (SL-14).
3. Dialling only when the configuration equals the live enrolment (SL-9), and choosing the stream from the authenticated key (SL-10).
4. Closing the link before the node's own audit write on a revocation, with the dialer off for the run when the state cannot be saved (SL-R2), and the mark by `through_seq`, taken after the held records are committed (SL-R3).
5. Holding the link on `run-forked` (SL-16), and the standing alarm while an acknowledgement is void (SL-R5).
6. No new listener (SL-18).
7. The live enrolments and the revoked pins in durable state that does not depend on the audit stream (SL-6).
8. The failure rules of SL-20, and the time cap on `sensor.link_refused` (§11.2).
9. The reason-and-pin rule when the node applies an enrolment, a `renew` denied while the previous state is unknown, and the order of the seven denial checks (C7-4, C8-2).
10. `applied_at` on `sensor.revoked`, and the sensor's fields on the relayed `collector.request` (C8-3, C8-6).
11. A health event at a revocation whose name differs from the audit action's (§11.5, row 30).
12. For the link key: a fault in its entry holds back the sensor links only, and the build that reads the kind ships before the one that makes it (§11.4, NK-5 and NK-6). And D5's view of the limit stated under C8-5.

**D4, for the sensor:**

1. Four programs under four accounts: a socket holder that parses nothing; a frame stage and an engine that hold no socket, each in an empty network namespace; and the link agent with the key (SL-3).
2. Making the key at install, and checking an Ed25519 signature and a strictly decoded enrolment on the host (SL-1, SL-5).
3. A run counter kept on disk, raised at each start of any of the four programs and synced before the hello; a hello; a buffer trimmed only by acknowledgements; and a counter of the numbered records evicted from it (SL-13 to SL-15).
4. A closed set of two message types from the node, with no path to a setting (SL-19).
5. The engine's output held to an allow-list of streams and fields that the agent enforces, in memory-backed storage, with no swap and no core dump (SL-22).
6. Nothing fetched at run time (SL-26).
7. A digest of the effective configuration in the coverage statement, and how the sensor's end was pinned (SL-19, SL-5).
8. The link agent applies C7-4's table to an enrolment it is given: a `renew` only under the key it holds, and no `rekey` or `replace` that names that key (SL-5 step 6).
9. The requests in the table below.

**What SL-3's new shape asks of C13 0.2.** These are requests to D4. D3 changed nothing in `docs/phase4/D4-c13-0.2-proposal.md`. Every rule of this note that it cites keeps its number and its meaning, with "the capture stage" read as the socket holder and the frame stage together.

| | Clause of C13 0.2 | What is asked |
| --- | --- | --- |
| a | CH-12, CH-26, CH-42 | A run begins at the start of any of the four programs. CH-12 says "the three programs", and CH-26 "the three-process sensor". Whether `started_by` keeps `capture` for both halves of the capture stage, or names each, is D4's to choose |
| b | CH-26 | `packets`, `bytes` and `drops_driver` are the socket holder's counts, and its one output is the pipe. Say how those counts reach the heartbeat with no second descriptor. And give a count for the frames it could not write into the frame stage's pipe: a counter of its own, or a stated place in an existing one. `drops_decoder` stays the engine's pipe |
| c | CH-27 | Say which program reads the monitoring interfaces for `interface_check`. It cannot be the socket holder, whose filter allows no such call, nor the frame stage, which is in an empty network namespace. And say whether the check also reads that the egress rule is loaded on each monitoring interface, with `unknown` when it cannot be read |
| d | CH-28, CH-29 | The discard runs in the frame stage. Each frame crosses the pipe with the interface it came from (SL-3, item 1), for `interfaces[].packets` and for the wrong-LAN count |
| e | CH-32 | The manifest names four programs, and gains `file` lines for the socket holder's call-filter profile and for the egress rule set, so that an edit of either shows at the node as a digest it does not expect. The program that refuses a redaction switch is the frame stage |
| f | CH-26, §14 item 3 | The pipe the engine reads is the frame stage's. The **[S2]** marker on `drops_decoder` waits for E-D4-03's pipe case, because the run as built reads files (D7 on #625) |

## 14. Limits

- **Everything here is `desk` and nothing is built.** No rule has a test yet. The tests of §12 are plans for P4-4-R1.
- **A compromised sensor host is not contained by this design.** It can read the mirrored traffic of the site, cleartext credentials included (HR-21), and it can lie to the node as itself (AP-34 (b), AP-36). The design stops it from becoming the node, another sensor, or a way into either, and makes it revocable.
- **Assumptions that are not verified,** each marked where a rule rests on it:
  - that a TAP's monitor port cannot send into the monitored link, which is a property of a TAP model and not of TAPs (O-1, AP-32 (1));
  - that a system-call filter can tell the socket's descriptor from the pipe's, that the asynchronous I/O interface must be refused at its set-up, and that neither capture account can change an nftables rule set (SL-3);
  - that the engine's output can be closed to a list, and that its logs and temporary files can be kept memory-backed (SL-22, and AP-33 (5));
  - that the engine can run with no route and no resolver, reading a pipe (SL-26 on AP-31 (1), SL-3);
  - and that a TPM-held key cannot be copied by root (SL-3, O-2).
  - P4-4-R1 and P4-4-S2 decide all but the first and the last, which need H-rows.
- **One assumption is decided, on one kernel:** an open packet socket can still send after `CAP_NET_RAW` is dropped. It is true on kernel 7.0.0-1017-azure, on a veth pair (`simulated`, run 43077596916). Nothing else in this note has been measured.
- **The four processes of SL-3 are a design to be shown.** No experiment has run an engine from a pipe in an empty network namespace, a socket holder under a call filter, or a frame stage with no socket.
- **C13 0.2 and the node's design are merged as documents and are not approved.** This note follows them as they stood at `624beb58` and `d06fdb86`. A change to either after that is not followed here.
- **The couplings F1 to F10 are open,** and they gate everything that feeds the node's intake (SL-20).
- **The limit under C8-5** is not ruled: a second fork of one sensor inside an hour writes no audit record.
- **SL-R5 rests on the node applying `node.network_baseline_ack`,** which it does not do yet.
- **No administrator's client exists,** so SL-5 step 3 and SL-R5's overlap view are requirements on one, as HR-14 is.
- **Not decided here:** the sensor host's hardware and operating system, every choice in §10, the bounds for skew, late records and the sensor's buffer (P4-4-L2 and P4-4-L3), and whether a node has one sensor or several (P4-4-L3).
