# The network baseline and its rules (P4-4-A4)

D4, 2026-11-07. This is the design note for P4-4-A4, deliverable 3 (`docs/agent-handoffs.md`, item 4 Stage A, D4-66), written beside C13 ([D4-c13-netobs.md](D4-c13-netobs.md)). It is reviewed with C13 by:

- D6, for testability;
- D2, for protocol reading;
- D3, for the platform's own traffic and the boundary;
- D5, for the consumer and its checkpoint.

Everything here is `desk`. No learner or detector exists, and nothing has run.

The note covers six things:

- what the baseline holds and how it is learned;
- how the detector judges observations;
- the nine rules, each with the malicious sample and the benign near-miss that GT-PCAP gives it (D6 plan §4);
- the platform's own traffic;
- the insecure-list rule;
- how R6.7 reaches C12's matcher.

## 1. Principles

- **Deterministic.** The same observations give the same baseline bytes, and the same baseline and observations give the same alerts. Every value is an integer or a sorted list, the document is in C13 §8's canonical encoding, and time comes only from the observations and an injected clock, as in C10 (V-M4's rule, D6 plan §7).
- **Inputs a person owns are inputs.** The authorized writers are never learned from the traffic they judge (D6 plan §7, A4 §3). The baseline is acknowledged by a signed digest before it is used (AP-36 (1)).
- **No ML** (brief). Every rule is a lookup against the acknowledged baseline or the node's own records.
- **The detector trusts nothing the sensor says about novelty.** `first_sight` decides only which observations carry bytes (C13 §4.2). Whether something is new is decided against the baseline.

## 2. The baseline

### 2.1 What it holds

The baseline is one document per sensor, stored as C13 §8 gives it. Each entry is keyed by **endpoint**, which is the C1 asset ID when the address resolves, and the address itself when it doesn't (`addr:<ip>`). An unresolved talker can still be in the baseline, which matters for non-SEL devices that have only vendor-neutral coverage (ADR-0006).

| Part | Entry | Learned from |
| --- | --- | --- |
| `pairs` | (client endpoint, server endpoint, `l4`, server port, `protocol`) | TCP `flow` `start` observations with `direction: client-server`, once the flow shows it was not only a dial, and UDP `flow` `start` observations at once (§2.2, D1 in D4-71). Midstream flows are learned only if the orientation is already known from a client-server flow on the same pair, never guessed. |
| `services` | (server endpoint, `l4`, port, `protocol`) | `service` observations with `basis: content`. A port-only basis is kept apart and marked as such. |
| `functions` | (pair, function code, `sub` where present, sorted object set) | `function` observations. `sub` is C13's field for Modbus 8's sub-function and 43's MEI type (C13 §4.3, §14) |
| `addresses` | every endpoint seen | all observations |
| `authorized_writers` | (client endpoint, server endpoint, class `write` or `control`) | **a person**, never the traffic (§2.3) |
| `period` | start and end of learning, observation counts by kind, the counts left out, and `overflow`: the observations that carried an entry the full draft couldn't hold (C13 §14 item 13, D4-71) | the learner |
| `params` | the rules' parameters (§4) | configuration, recorded in the baseline as C10 records its parameters |

Two kinds of observation are left out of learning:

- **Those tied to the platform's own sessions** (`node.platform_session` set). These are judged by the tie rule (§5), not by the baseline, so a session the node ran during learning can't make a later untied one normal.
- **Those made while the coverage was `degraded`.** They are counted in `period`, so the operator sees how much of the learning period was degraded.

### 2.2 Learning

The operator starts learning for a period (the default is 7 days, a parameter). The learner folds observations into the draft as the stream's required local consumer (D5 §3, #532 §3). It checkpoints the draft in `netcheckpoint.learner` (C13 §8) at least every `fold_batch` observations, and its cursor is confirmed only after that checkpoint commits. An observation is either learned or left out whole: one tied to the node's own session counts in `period.platform_session` first, then one seen while degraded counts in `period.degraded`. The draft stays within `MaxBaselineBytes`. Once it is full, a new entry is refused, the held ones are kept, and the observation counts in `period.overflow` (C13 §14 item 13).

**A TCP start is held until its flow proves it** (D1 in D4-71, from D6's A2 on #561). A `start` is emitted at the client's SYN, so a SYN probe during learning would otherwise make its pair known, and a later real session on it would raise no `unknown-pair`. So the learner holds a client-server start's pair, keyed by its flow (client address and port, server address and port), and learns it only when the flow shows it was not only a dial: an `end` with `syn_only: false`, or a decoded `function` on the flow, whichever comes first. An `end` with `syn_only: true` drops the hold. The proof must itself be learned: an `end` or `function` left out as the node's own or as degraded proves nothing. At most `MaxHeldStarts` (512) starts are held. A start that can't be held is refused and counts in `period.overflow`, so it fails closed. The held starts are in the learner's checkpoint (C13 §8). A start still unproven when learning ends is not learned. **The accepted cost:** a long-lived session that neither decoded a function nor ended during learning, such as an SSH or TLS session open throughout, alerts once as `unknown-pair` when it reconnects after acknowledgement (D1). **A UDP start learns its pair at once** (D1 in D4-71). UDP has no handshake to wait for and no `syn_only` to prove a flow, so a single datagram, decoded or not, learns its pair, and its services and functions are learned on a single probe too. That is AP-36 (a)'s residual (D1, D3 writes it). A UDP flow has no direction (C13 §4.1), so its client is the first datagram's sender and its server port the receiver's. **A stated limit:** when the capture begins on a reply, or a flow cut by `idle` resumes with one, the learner learns the reversed pair, usually from the server to the client's ephemeral port. That entry takes draft room and is never seen again, and the real orientation is learned only if a request starts a flow during learning. **So the detector judges a UDP start both ways** (D1 on the 2a plan): it raises `unknown-pair` only if neither orientation is in `pairs`. The reversed match holds only between the same two pair ends, with the learned port at the end that sent from it, so a reply-first entry never covers a third host or another port (§4). A UDP start, like any entry, is learned only when both its addresses are held.

So the observation class keeps draining during learning (D5). When learning ends, the draft is frozen. The learner folds nothing more, and its cursor follows the detector's until acknowledgement, so pruning isn't held while the draft waits for a person. The person signs the accepted document's digest together with the frozen draft's (HR-14, §2.3). When a person acknowledges the baseline, the node retires the learner consumer with an audit record, and it never holds pruning again. Relearning starts a new learner consumer (D1, D4-68). Tests check two things: observations stay prunable during learning as each learner checkpoint commits, and after acknowledgement the retired learner holds nothing back. At the end it records the draft as `baseline.network`, version n + 1, and the detector keeps using version n until a person acknowledges n + 1. With no acknowledged baseline, the detector runs only the rules that don't need one: `own-session-outside-record`, `node-address-spoofed`, `own-session-unseen` and `sa-failed` (D1). Status says that the other five are off. D6's test: a failed SA exchange on a node with no acknowledged baseline raises `sa-failed` and nothing else.

### 2.3 Acknowledgement and the authorized writers

The admin client shows the frozen draft: pairs, services and functions grouped by server asset, with every write-class or control-class function the learner saw marked, and each pair end named only through an inbound (Syslog sender) address marked too, derived from `addresses` and the current C1 (C13 §14 item 9). It also shows the authorized-writer list, which starts empty, and the person adds each authorized writer explicitly. Then the signed path is D3's (C7 0.10 and C8 0.12, for D4-68):

1. **The client builds the accepted document.** It is the frozen draft with the person's `authorized_writers` filled in, in C13 §8's canonical encoding. The client shows it, and writes its exact bytes to the node's admin folder as `network-baseline-<sensor_id>.json` (D5). Those bytes are unsigned and have no effect on their own.
2. **The client signs `node.network_baseline_ack`**, a separate admin kind (D1, D4-68). The body names the sensor and the accepted document's digest (`baseline_digest`). It also names the frozen draft it was built from (`draft_digest`), so the signature binds both. The client computes both digests over the bytes it shows (HR-14). The two digests are equal when the person adds no writers.
3. **The node adopts the document only when all of these hold** (D3's C7 0.10 §1). Otherwise it writes `config.baseline_acknowledged` with outcome `denied`, and takes nothing.
   - The collector has accepted the signed request.
   - `sensor_id` is the sensor in the node's `network_sensor` section.
   - `draft_digest` is the latest `baseline.network` draft the node recorded for that sensor.
   - The file is at most `MaxBaselineBytes`, and its SHA-256 equals `baseline_digest`. The node reads the file once, and hashes, checks and stores those same bytes. When the two digests are equal, the node already holds the bytes and ignores any file in the folder.
   - The file is canonical (C13 §8): decoded strictly and encoded again, it gives the same bytes. It passes the baseline document's own checks, so each writer is a (client, server, class) entry with class `write` or `control`, and the list is sorted without duplicates.
   - The file with `authorized_writers` set to `[]`, encoded again, is byte for byte that draft.

   It then stores the file as `baseline.network`, as accepted. So a person can add writers and change nothing else, and a document re-encoded with other whitespace or key order is denied. A file in the admin folder that no signature names is never read as a baseline. The writer list doesn't have to fit the 8 KiB signed request, because the request carries only digests. If the configuration ceiling refuses the store, the acknowledgement is `denied` with a storage reason, and `network-baseline-no-room` is raised (D5).

A write the learner saw from a client the person did not authorize stays in `functions`, so the pair is not new. But it alerts as `unauthorized-write` the next time it happens. That is how an attacker who was present during learning is still caught writing (AP-36 (a)), and how the person sees the poisoning before acknowledging.

## 3. The detector

- It reads the observation stream in order, as a C5 consumer that reads ahead of its confirmed cursor. It raises an alert as soon as it reads the observation, so latency is not held to the checkpoint interval (R6.4). Its cursor is confirmed only when a `netcheckpoint.detector` checkpoint that covers the observation has committed (D5 §3).
- The checkpoint holds the open coalescing windows (C13 §7.3), at most `MaxDetectorWindows` (96), and the own-session state: the sessions pending, the invocation IDs tied before their session record, the coverage record and the degraded intervals (§5, C13 §14 item 17). The held flows are intake's, not the detector's (D1 in D4-72). Its form is C13 §8. When 96 windows are open, a new key still alerts at once, and the window that started earliest closes early with its summary (D1 in D4-72). The detector counts each early close, and the node shows the count in status (D3's C1 on #569).
- **Its time is the capture clock:** the latest `first_utc` it has taken. A window closes when that clock reaches its start plus `coalesce_window_s`, and the summaries of the windows an observation closes come before that observation's own alerts, in (rule, asset) order. The detector reads no wall clock, so the same observations in the same order give the same alerts.
- **No duplicate alerts after a crash (D5).** An alert commits in the `network` database, and the checkpoint commits later in the configuration database. There is no transaction across the two. So the checkpoint records the last alert seq the detector knew of on its alert stream. On restore, the detector takes the alert records after that seq and replays the observations after `through`. The alerts it raises again come out in the order they were committed, so each one is compared with the next committed record: an exact match, byte for byte as a health body but for the capture the node filled in, is held back. A departure is a fault, and the regenerated alert is still returned and committed, and counted in `Mismatches` for the node to alarm. A committed record still unmatched once the replay reaches the stream's head as of the restore counts as a mismatch too (D1 on the 2a plan). It goes by seq, not by time: the store stamps a commit with the later of now and the stream's last commit time, so after a backward clock step an alert committed after the checkpoint can carry an earlier time (D5). An alert already committed is then never raised again, and a summary counts its hits once. With that, a restore gives the same alerts as an uninterrupted run. Where the tests go (D6):
  - **The exhaustive form** is in the detector's unit tests, on a recorded observation stream on the test clock. They cut at every checkpoint and compare the alert records byte for byte. They also crash the node between an alert's commit and the next checkpoint, with and without a backward clock step, and check that no alert record is duplicated and that the summaries' `hits` equal the uninterrupted run's.
  - **GT-PCAP** runs one end-to-end kill and restart on the offline file path. It compares the alert set by (rule, key, cited hashes, hits), not by bytes, because IDs and receive times differ.
- **Determinism runs offline.** The same-capture-same-baseline test reads GT files offline (`file:<sha256>`), because on a live replay the drop counts vary. It also checks that splitting the same observations into different fold batches gives the same baseline bytes (D6).
- A fold batch is at most `fold_batch` observations (default 256). That bounds D5's observation floor: two batches at the observation record cap (#532 §4).

## 4. The rules

Function classes come from one versioned table, `fc-classes/1`, kept in `modules/detection` and named in every baseline. The classes are `read`, `write`, `control`, `time-sync`, `session-setup` and `other`. D2 checked every row against the project-held SEL manuals (D2's review of this note, part C). IEEE 1815 and the Modbus Application Protocol specification are not held, so no row is confirmed from them. Each row carries one of three statuses, and the table in code keeps the status and the citation beside the row:

- **confirmed:** a held manual gives the code's number and its meaning (`documented-untested`);
- **number only:** a held manual shows the code in use on named objects, but no held source pairs the number with its name;
- **unknown:** no held source has the code. The class is D4's choice, made so that the code can't slip past `unauthorized-write`.

The class each code goes in is D4's call. D2 flagged only the codes where the manuals show a routine use the rule would alert on, or a control the rule would miss.

**DNP3** (requests only, C13 §4.3):

| Code | Class | Status | Source |
| --- | --- | --- | --- |
| 1 | `read` | confirmed: Read | S33 Table F.2 p. F.2 |
| 2 with only g50v1 or g50v3 objects | `time-sync` | confirmed: Write | S33 Table F.2 p. F.2; g50v1 and g50v3 in S22 Table D.9 pp. D.17 to D.18. Any other group 50 variation is not a held time write, so it falls to the next row but one (D2, D1 on #549) |
| 2 with only g80v1 objects | `session-setup` | confirmed: Write | S22 p. D.18 (index 7); S23 Table 2.30 p. 82 (indexes 4 and 7) |
| 2 with any other object, or a mix, including any group 50 variation other than 1 and 3 | `write` | confirmed: Write | S33 Table F.2 p. F.2; g34 deadbands in S22 Table D.9 |
| 3, 4 | `control` | confirmed: Select, Operate | S33 Table F.2 p. F.2 |
| 5, 6 | `control` | confirmed: Direct operate, and its no-reply form | S33 Table F.2 p. F.3; g12 and g41 in S22 p. D.15 and S23 pp. 80 to 82 |
| 7 to 10 | `write` | number only: counter freezes | S22 Table D.9 p. D.15; S23 Table 2.30 p. 80 |
| 11, 12 | `write` | unknown | none held |
| 13, 14 | `control` | confirmed: cold and warm start | S22 Table D.9 p. D.19; S23 Table 2.30 p. 83 |
| 15 to 18 | `control` | unknown | none held |
| 19 | `write` | unknown | none held |
| 20, 21 | `session-setup` | number only: used on g60 class objects | S22 Table D.9 p. D.18; S23 Table 2.30 p. 82 |
| 22 | `session-setup` | number only: used on g60 and the "all variations" headers | S23 Table 2.30 pp. 79 to 82 |
| 23 | `time-sync` | confirmed: delay measurement | S22 Table D.9 p. D.19 |
| 24 | `time-sync` | number only: a no-object function | S23 Table 2.30 p. 83 |
| 27 | `write` | unknown | S22 p. D.18 lists the g70 file objects without codes |
| 31 | `control` | unknown | as 27 |
| 32, 33 | `other` | confirmed: authentication | S23 Table 2.30 pp. 82 to 83 |
| any other request code | `other` | unknown | none held |

DNP3 0 (confirm) and the responses 129, 130 and 131 are never `function` observations (C13 §4.3), so they are not in the table. 0's number is `unknown` from the held sources.

**Modbus** (client to server only, because a response echoes the request's code, S22 Table E.3 p. E.3):

| Code | Class | Status | Source |
| --- | --- | --- | --- |
| 1 to 4 | `read` | confirmed | S22 Table E.2 p. E.2; S34 Table E.2 p. E.2; S32 Table 10.31 p. 10.64; S23 p. 274 |
| 5, 6 (06h) | `write` | confirmed | the same tables. 06h also operates outputs on SEL relays, through LOGIC COMMAND 2000h and RESET COMMAND 2001h (S22 p. E.17) |
| 15 (0Fh) | `write` | confirmed | S32 Table 10.31 p. 10.64; S23 p. 274 |
| 16 (10h) | `write` | confirmed | as 1 to 4; operates outputs as 06h does |
| 22, 23 | `write` | unknown | none held |
| 43 with MEI type 14 (`sub` 14) | `read` | unknown | no held SEL device lists 2Bh |
| 8 with sub-function 0 (`sub` 0) | `other` | confirmed: loopback | S22 Table E.18 p. E.11 |
| 8 with sub-function 1 or 4 | `control` | unknown | none held. D4 puts them in `control` because restarting communications or forcing listen-only mode can silence a device |
| 8 with any other sub-function | `other` | unknown | none held |
| 8 with no `sub` (a request too short to hold it) | `control` | D1's ruling | the most restrictive row for 8, so it fails closed against `authorized_writers` (D1 on #543) |
| 43 with MEI type 13 (`sub` 13), CANopen General Reference | `write` | unknown | none held. It can write a CANopen object dictionary (D3 on #543) |
| 43 with no `sub` (a request too short to hold it) | `write` | D1's ruling | the most restrictive row for 43, so it fails closed against `authorized_writers` (D1 on #543) |
| 43 with any other MEI type | `other` | unknown | none held |
| 60h, 61h, 62h | `read` | confirmed: parameter information and text reads | S22 Table E.2 p. E.2 and p. E.17; S34 Table E.2 p. E.2 |
| 7Dh | `control` | confirmed: encapsulated packet with a control command | S22 Table E.30 pp. E.15 to E.16; S34 p. E.14 |
| 7Eh | `other` | confirmed: no-operation, used only inside 7Dh | S22 Table E.2 p. E.2 |
| any other code | `other` | unknown | none held. The RTAC's Report Server ID is a read (S23 p. 275), but its number is unknown from the held source, so it falls here |

**Alert text follows the class, not the code.** A `write` alert says "wrote to the device", never "a settings write", because 06h and 10h also operate outputs. A `session-setup` alert says "changed event reporting".

Time-sync gets its own class because "write = bad" otherwise alerts on every routine time sync (A4 §3). It is judged as a function, not as a write: a time-sync from a pair that never sent one is `new-function`.

Every rule's alert form is C13 §7. Its key for coalescing is rule × destination asset, or the unresolved bucket (C13 §7.3).

| Rule | Raised when | Parameters | Malicious sample (D6 plan §4) | Benign near-miss |
| --- | --- | --- | --- | --- |
| `unknown-pair` | A `flow` `start` whose (client, server, `l4`, server port, `protocol`) is not in `pairs`. A midstream flow, and a UDP flow, alert only if neither orientation is in `pairs`: the reversed one takes `sport` as its server port (§2.2) | none | A new master polls the outstation | The known master on a new TCP source port: the source port is not in the key |
| `new-service` | A `service` whose (server, `l4`, port, `protocol`) is not in `services` | none | A port opened on the relay that the baseline never saw | A known service on a new client port |
| `new-function` | A `function` (a request, C13 §4.3) on a known pair whose (code, objects) is not in `functions` for that pair, and whose class is not `write` or `control`. So it judges `read`, `time-sync`, `session-setup` and `other` | none | A pair that only read starts sending a time-sync; a pair that never did the reconnect sequence disables unsolicited reporting (21) | A time-sync from a pair that time-synced during learning; a reconnect sequence from a master that did it during learning; an outstation response carrying an object group not seen in learning, which is not a function and raises nothing (D6) |
| `unauthorized-write` | A `function` of class `write` or `control` whose (client, server, class) is not in `authorized_writers` | none | A DNP3 direct operate, or Modbus 6, 16 or 7Dh, from a master authorized only to read; the same DNP3 operate with its response removed, which is emitted at `sa_reply_timeout_ms` with `sa` absent (C13 §4.3, D3) | The same function from the authorized master; a DNP3 time-sync from the authorized master (class `time-sync`, not `write`); a reading master's reconnect sequence (class `session-setup`) |
| `own-session-outside-record` | A `flow` `start` from a node address to an asset, or to an enrolled run endpoint, with no `platform_session` tie (§5), and not to an exact destination the node excludes. Intake holds a flow to a dispatched run's endpoint until the run's result commits or the hold's deadline passes, so a failed dial raises nothing and a spoofed flow alerts late, never not at all (§5, D1 in D4-72) | `tie_grace_s` (default 30) | A Telnet session to the relay from the node's address outside any window | The node's own scheduled session inside its window |
| `node-address-spoofed` | A `flow` `start` from a node address whose source MAC is not one of the node's MACs, taken from the install configuration (`network_sensor.node_macs`). A flow's first frame is its sender's, so its MAC is the sender's (C13 §4.1). It judges tied flows too. It runs only on the segments or VLANs the install configuration names as the node's own layer-2 segment, because across a router the node's frames carry the router's MAC (D3, D6) | none | A session from the node's IP with another MAC, on the node's segment | The node's real session; the node's real session seen beyond a router, with no alert |
| `own-session-unseen` | A session record whose collector-to-device flow has not been observed by the window's end plus `tie_grace_s`, while the coverage covers that device (AP-36's canary). It runs for a connected session only: a C2 0.9 result that is not connected expects no connection, so it never fires for one. **Covers** means: the asset's address is in the baseline's `addresses` on a VLAN in `vlans_seen`, its PRP LAN is in `lans_seen`, and no observation in the window has a non-empty `degraded`; the detector reads observations, not heartbeats (D6, D4-73). **Before acknowledgement** it reads the detector's own coverage record in place of the baseline: the VLANs and PRP LANs each enrolled run endpoint's address was seen on, in observations neither tied nor degraded, with the same VLAN, LAN and `degraded` conditions. It never reads the learner's draft, so a restore stays byte-equal (D1 in D4-72). An enrolled endpoint the record holds nothing for shows in status as "not yet seen", so the gap is visible (D6, D4-68). Only observations count as degraded: the detector doesn't read heartbeats (D4-73) | `tie_grace_s` | The SEL-751 capture with the node's own session removed, while the sensor reports full coverage (D6 plan §2C) | The same removed session while the sensor reports `degraded`, or with that VLAN unseen, with no alert; before acknowledgement, the same removed session to an enrolled asset the draft has never seen, which shows in status as "not yet seen" and raises no alert (D6) |
| `unresolved-address` | A `flow` `start` with an end that resolves to no asset, at an address not in `addresses` | none | A spoofed source address polls an enrolled relay | A known unresolved address (in `addresses`) talking as before |
| `sa-failed` | A DNP3 `function` with `sa: failed`: SA was in use, and the exchange carried g120v7 "Authentication -- Error" in function 33 or 131, whichever end sent it (C13 §4.3). It judges every class, because a failed authentication is worth seeing on any function (D1, D4-68) | none | A challenged direct operate whose reply to the challenge fails, ending in g120v7 | The same operate challenged and passed (`sa: challenged`), with no alert; an operate with no SA at all, which sets `dnp3_no_sa` and raises no `sa-failed` |

Every rule has a malicious sample and a near-miss, so none of them blocks the gate for lack of a pair (D6 plan §4).

**Rules that fire together (D6).** Some samples raise more than one rule by design, and GT-PCAP's `case` rows list every rule expected. An alert from a rule not listed is a false positive for that rule.
- A new master that resolves to no asset raises `unknown-pair` and `unresolved-address`.
- A new service raises `new-service` and `unknown-pair`, because the pair's key holds the server port.
- A new master polling an enrolled relay raises `unknown-pair` only.
- A failed SA authentication raises `sa-failed`, and also `unauthorized-write` if the master is not an authorized writer for that class. From an authorized master it raises `sa-failed` only.
- An unauthorized write on a known pair raises `unauthorized-write`, and also `new-function` only if that (code, objects) was never seen on the pair. It isn't, because write and control are judged only by the writer list.
- A session from the node's address outside its window raises `own-session-outside-record`, and `node-address-spoofed` too if its MAC is not the node's.

**A reading master's reconnect sequence is `session-setup` (D2, D6).** After it connects, or after an outstation restart, a master enables unsolicited reporting (20), sometimes assigns classes (22), and clears the restart indication by writing g80v1. SEL outstations expect this (S22 p. D.7, settings UNSOL and PUNSOL in Table D.7 p. D.11). As `write`, every enrolled reading master would alert `unauthorized-write` after each relay restart. As `read` or `other`, a master that disables unsolicited reporting (21) or reassigns classes could hide events unseen. So `session-setup` is judged by `new-function`: a pair that did it during learning raises nothing, and a pair that never did it alerts. D6 labels the reconnect of a master that did it in learning as a near-miss with no alert, and the same sequence from a pair that never did it as a malicious `new-function` sample. The row stays narrow: a write of g80v1 together with any other object is `write`.

**What the rules don't do in 0.1.** There are no rate or volume rules. There are also no rules on GOOSE, SV, IEC 104 or MMS, which are not decoded (C13 §3.3, `decodes`).

## 5. The platform's own traffic (AP-35)

The node's own SEL Telnet and SNMPv3 sessions are known flows, not alerts. They are still recorded as an insecure service where they are one: SEL Telnet is, SNMPv3 is not (D2 §1).

**Who does what (D1 in D4-72).** The node's intake ties each flow from the node's own address before it commits the observation, and sets `node.platform_session`. Intake owns the tie, the window tie, the failed-dial hold and the flow still open from an earlier session, below. The detector stays pure: it judges `platform_session`'s absence (`own-session-outside-record`), the node's address from another MAC (`node-address-spoofed`), and a connected session whose flow no observation was tied to (`own-session-unseen`). The node hands each session to the detector with `Session(record, after_seq)`, after the hold's release, the released flows and the `collection.run` record carrying `after_seq` have committed, in that order, on the same path live and on restore.

- **The tie.** Intake ties a `flow` from a node address to a session record from the collector. The record gives the asset, the run's endpoint (address, port and transport) and the window `[started_at, ended_at]`. Addresses are compared as parsed values after `Unmap().WithZone("")`, never as strings (C13 §14 item 9). Every time comparison allows `tie_grace_s`, written *g* below, because `connected_at`, `started_at` and `ended_at` are the collector host's clock and a flow's time is the sensor's (C2 0.9 §1.5).
  - **A `connection` tie** is used for a C2 0.9 result that is connected, which carries `local_addr` and `connected_at` (#547). The session's 5-tuple is `local_addr`, the endpoint's address and port, and the endpoint's transport. A flow with exactly that 5-tuple ties to the session in two cases:
    1. **Its `start` falls in `[started_at − g, ended_at + g]`** (D1 in D4-73, on D6's F1 on #576). That covers three things: the handshake, whose `start` is near `connected_at`; a flow the sensor joins midstream after it restarts inside the session; and a flow that `idle` splits into several `start` and `end` pairs with one key (C13 §4.3). Every such `start` ties. A `start` inside two sessions' intervals, which needs one 5-tuple reused by two runs less than 2*g* apart, ties to the session with the latest `connected_at` not after the `start` plus *g*. With the lower bound at `started_at − g`, a `start` taken from the sensor's clock ahead of the collector's `connected_at` still ties.
    2. **It is still open from an earlier session** (D5, D4 on #541; refined by D1 in D4-73). The flow has a `start` tied to an earlier session of the same asset and is still in intake's open table. This is an SNMPv3 run whose kernel gave it the last run's port while the sensor still holds that UDP conversation open, so no new `start` comes. The session counts as seen, and the flow's later records tie to it. A `start` never ties through the open table: it removes the old entry, counted, and is judged fresh. An open entry expires at its last record plus `flow_idle_s` plus *g*, and the expiry survives a restart. A new sensor `run_id` clears the table; a seq gap or degraded coverage does not. Injection into a live open flow stays an AP-35 residual. Such a session may give no new observation at all, because an observation is emitted once per key per flow (C13 §4.2). So intake re-points the open entry to the new session, reports it, and the node writes `open_flow: true` on its `collection.run`. The detector counts that session as seen, under its own status count (`OpenFlowSeen`) apart from the sessions seen by a tie (D1 in D4-73, on D4's finding 3 on #576).

    The exact 5-tuple, the collector's ephemeral port included, is what makes a wide interval safe. Any other connection from the node's address to the asset has another client port and doesn't tie. Inside the window, it alerts as `own-session-outside-record` (AP-35, D6 on #523), unless it is a failed dial (below). A frame forged with the node's own address and port is spoofing, which `node-address-spoofed` covers on the node's segment.
  - **A `window` tie** is used for a 0.8 result, which carries neither field. The flow must start inside the window, and its destination must be the record's address and port. Only the **first** established connection from the node's address to that destination inside the window is tied. D2's facts make that safe: the SEL-751 adapter opens at most one established connection per run, and retries the dial only when it fails before any byte is sent (`modules/ied/sel751/run.go` `connect`), and the collector never runs two sessions to one asset at once (`Pipeline.claim` in `modules/security/collector/pipeline.go`). So a second established connection to that destination inside the window is never the platform's, and it alerts as `own-session-outside-record`. For SNMP, the run is one UDP conversation, so "connection" means that conversation. AP-35's **residual** is narrower than an untied window: an attacker's connection that starts inside the window before the platform's own is tied in its place, and the platform's then alerts. Two assets on one host and port are flagged at enrollment (C13 §5).
  - **A failed dial takes the `window` tie** (D3, D1 on #547). A dial that fails has no `local_addr`. When a dial is retried, its earlier attempts go out from ports that no result names. So a TCP flow takes the `window` tie when all of these hold:
    - it runs from the node's address to the run's endpoint address and port;
    - its client port is not the session's, or the result is not connected;
    - its `start` falls in `[started_at − g, ended_at + g]`;
    - its `end` says `syn_only: true` (C13 §4.3, §14 item 10);
    - the run has not used up its failed-dial ties (below).

    Such a flow carried only SYNs, so it carried no payload to the device. It is not "the first established connection" for a 0.8 result either. "Established" in the window tie means a flow whose `end` says `syn_only: false`, or that carries any other observation.

    **Holding** (D1 in D4-70, moved to intake in D4-72). At its `start`, a dial attempt can't yet be told from an attacker's connection. So intake holds a flow from the node's address to a dispatched run's endpoint, and commits it only once it can tie it or not. It fails closed: a held flow that doesn't tie commits untied and alerts.
    - **Its `end` says `syn_only: true`.** It takes the `window` tie, with no alert.
    - **Its `end` says `syn_only: false`, or any other observation with the flow's key arrives.** The flow carried data, so it commits untied and alerts.
    - **The deadline.** The hold lasts until the run's result commits, or until dispatch plus `MaxDeadlineMS` (600 s) plus *g*, since the node can't see the run's own `deadline_ms`. A failed dial still open after the result waits for its `end` until its arrival plus `MaxConnectTimeoutMS`, `flow_idle_s` and *g*. A backward clock step can't stretch a hold. So a spoofed flow to a run's endpoint during the run alerts late, at most about 750 s at the defaults, and never not at all (AP-35).
    - **The sensor restarts, or degrades (D6).** A held flow is released at once on a record from a new sensor `run_id`, or on a heartbeat whose `degraded` is not empty, because its `end` may never come.
    - **The node restarts.** Held flows are in intake's working-state series `netcheckpoint.intake` (C5 0.9), written before each hold or release takes effect.
    - **The cap (D3's H3, D6, D5).** A run makes at most `connect_retries` + 1 dial attempts (C2 limits). A flow past that commits untied at once and is counted, and never evicts a held one. A run's record holds at most 23 records; past that the whole hold releases untied, counted.

    The details and their tests are D5's (D4-72).

    **For UDP, no failed-dial rule is needed.** An SNMPv3 run uses one socket, so its retries reuse its own 5-tuple (D2 on #547).
- **The node's addresses, MACs and segments** come from the install configuration, never from traffic: `network_sensor.node_addresses` (1 to 8 IP literals, compared parsed), `node_macs` (1 to 8, lowercase) and `node_vlans` (VLAN IDs 1 to 4094, or `untagged`), all required (D1 in D4-72).
- **Flows to the node's forward targets** are not judged by `own-session-outside-record`. Each exclusion is an exact (destination address, `l4`, port) entry that the node derives from its forward targets, never an address alone, a wildcard or an operator-entered list. With `network_sensor` present, a forward target whose host isn't an IP literal is refused at load. The sensor link gets its exclusion with ADR-0009 (D1 in D4-72). `node-address-spoofed` still applies to those flows (D3).
- **The canary** (`own-session-unseen`) is the independent check on a blind sensor (AP-36 residual, D1 on #525 §3). It runs only for sessions to an asset whose LAN the coverage statement claims, so a sensor that honestly reports partial coverage is not alarmed for traffic it said it couldn't see. It judges a session once the detector has read past the session's `after_seq` and its capture clock has passed the session's end plus *g*. A session counts as seen when any observation is tied to its invocation ID, before or after the handover. It fires even when the node dropped the session's own observation (class full or record cap), because that is a real gap; the node shows the asset's drop count beside the alert in status, never in the alert (D1 in D4-72).

## 6. R6.7 to C12, with no C12 change (D4-53)

R6.7 asks for exposed services, protocol versions and insecure protocols per asset, recorded as evidence for R9. They reach the matcher as stored observations, cited by event ID with source `passive`, as the matcher note already allows (C4-matcher §4, §5 and §9):

- **`service` observations** for C11 preconditions of kind `service` with `present` or `in`. Unseen traffic never shows `absent` or `not-in` (C4-matcher §4).
- **`identity` observations** for a passive identity. A passive identity never confirms (V-M7), and never outranks the collector's read (AP-34 (4)).
- **Currency** is C4-matcher §6's rule for passive observations. An observation is current until a configuration change is retrieved after it, or a device-read setting contradicts it.
- **No double counting (D2, #522).** The node passes the matcher only observations with no `platform_session`. A FID or engine ID read passively from the platform's own `ID` or SNMPv3 exchange is the same evidence as the collector's read. It never reaches the matcher as passive evidence, so it can't corroborate that read or count twice. GT-PCAP's two rows check it: the asset's C12 findings are byte-identical with and without the passive capture (D6 plan §2C).
- **The insecure services per asset** are the asset's `insecure` and `service` observations, grouped by `reason` and port, and shown in status and the R9 view. The platform's own Telnet is listed.

**The trigger.** The node runs evaluation after it commits a `service` or `identity` observation for an asset, as C4-matcher §7 already provides. Only first sights and changed values do that, so the matcher doesn't run on every repeat.

## 7. The insecure-list rule

Every use of a protocol on V-M6's list gives an `insecure` observation (C13 §4.3). In 0.1 that is evidence, not an alert. An alert per use would fire on the platform's own Telnet at every poll, and on every SCADA master's DNP3 poll where SA isn't used, which describes every SEL family but the RTAC (D2 §1). Those are standing findings, which the R9 view shows per asset. The view counts connections that carried a use, not operations, because an observation is emitted once per key per flow (C13 §4.2, D6). A *new* insecure use does alert, through `unknown-pair` or `new-service`, because it is a new pair or a new service. If the owner wants an alert on every insecure use, that is a rule a later minor adds. It is not hidden in 0.1.

## 8. Limits

- **The `window` tie's residual** on a 0.8 result: an attacker's connection that starts inside the window before the platform's is tied in its place (§5).
- **An attacker's half-open flows from the node's address to the run's endpoint, inside the run's window, are tied too,** up to the run's cap (§5). They carry only SYNs, so no payload reaches the device. A SYN to any other port, or past the cap, alerts as before (D3).
- **The node's own address seen from another MAC** is `node-address-spoofed` only where the sensor sees the node's segment. Elsewhere, a frame forged with the node's address and the session's port ties like the platform's own (§5).
- **A baseline learned while an attacker writes** still catches the writes, through the authorized-writer list (§2.3). A read-only attacker present throughout learning is in `pairs`, and is caught only if the person spots the pair in the draft.
- **A UDP flow whose capture begins on a reply** learns the reversed pair, usually to the client's ephemeral port (§2.2).
- **A session that neither ended nor decoded a function during learning** is not learned, and alerts once as `unknown-pair` when it reconnects after acknowledgement (§2.2, D1 in D4-71).
- **Midstream flows** of an orientation never seen with a handshake are judged both ways, and alert only if neither way is known (§4). So are UDP flows, because a reply-first capture learns the reversed pair (§2.2). A UDP request from a known server to a known client's port, in the reverse of the learned direction, raises no `unknown-pair`.
- **A summary's `sources` stops at 32.** The detector holds each window's distinct source addresses to tell a new one from a repeat, and it holds at most 32. Past 32, `sources` stays 32 while `hits` keeps counting, so a scan from hundreds of addresses reads as "32 or more" sources.
- **Past 96 open keys, coalescing is weaker** (D1 in D4-72). The window that started earliest closes early, so a key can give a first alert and a summary per early close, up to one record per hit, instead of two per window. A summary needs a repeat, so records never outnumber hits (D4 on #572). Every hit is still counted once. The per-key drop count shows it if the alert class fills (C13 §7.3).
- **The class table is only as good as the held manuals.** Rows marked `number only` or `unknown` in §4 rest on D4's choice, not a source. IEEE 1815 and the Modbus specification would settle them, and neither is held. A code missing from the table is `other`, which `unauthorized-write` never judges.
- **A spoofed authorized-master address passes `unauthorized-write`.** A passive IDS can't tell a forged source address on another segment from the real master. This is stated, not tested (D6).
- **A flood that mimics a known pair** has a resolved end, so the unresolved budget doesn't apply, and it raises no alert. It can fill the observation class, so a real write to another asset is dropped before the detector reads it. The node counts refused observations by destination asset, with one bucket for unresolved destinations, as it counts alerts (#532 §4). D6's spoofing-flood test includes this flood beside the unresolved one. If the test shows starvation, a budget per destination asset on observations follows. Otherwise it is AP-36's residual (D3).
- **`sa-failed` can't tell a forgery from a wrong key** (D2, D6, D1). The sensor sees that the outstation refused the request's authentication, but it can't check the authentication codes, because it holds no keys. So the alert says "SA authentication failed" and never "forged": an attacker's forged operate and an authorized master with a stale key look the same. `sa: failed` never sets `dnp3_no_sa`, because SA is in use (C13 §5). The rule keys on g120v7's presence, not its error code, because the project holds no SA specification and the code's offset and values are `unknown` (D2). It can't tell a key mismatch from any other error, and its `hits` are a lower bound, because the outstation caps the errors it sends (S23 §12.4.8, p. 89).
- **The canary needs the sensor to send.** The detector's time is the capture clock, so a sensor that sends nothing doesn't move it, and a pending session waits until the sensor sends again. Meanwhile the node's `sensor-unreachable` alarm (no heartbeat for 60 s) is the signal (D4-73). A sensor that keeps sending but misses the session fires the canary, unless an observation in the session's window carries a non-empty `degraded`.
- **The canary's state is bounded, and fails loud** (C13 §14 item 17). Past 128 pending sessions, or 256 IDs tied before their record, the extra session isn't judged, and the node raises the alarm. Past 64 degraded intervals the oldest is dropped, so a session in it may alert. Past 256 enrolled endpoint addresses the rest are never recorded, so until acknowledgement their sessions are never judged; they show as not yet seen, and status shows the count (`EndpointsNotTracked`, D1's C1 on #575).
- **Visibility limits** are C13's coverage statement and R6.6: HSR, encrypted payloads, unsupported protocols, and sensor placement.

## 9. Open questions

1. **Owner, through D1:** whether an insecure use should alert on its own (§7), and the 7-day default learning period.
