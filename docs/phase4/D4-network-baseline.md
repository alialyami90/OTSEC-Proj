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
| `pairs` | (client endpoint, server endpoint, `l4`, server port, `protocol`) | `flow` `start` observations with `direction: client-server`. Midstream flows are learned only if the orientation is already known from a client-server flow on the same pair, never guessed. |
| `services` | (server endpoint, `l4`, port, `protocol`) | `service` observations with `basis: content`. A port-only basis is kept apart and marked as such. |
| `functions` | (pair, function code, sorted object set) | `function` observations |
| `addresses` | every endpoint seen | all observations |
| `authorized_writers` | (client endpoint, server endpoint, class `write` or `control`) | **a person**, never the traffic (§2.3) |
| `period` | start and end of learning, and observation counts by kind | the learner |
| `params` | the rules' parameters (§4) | configuration, recorded in the baseline as C10 records its parameters |

Two kinds of observation are left out of learning:

- **Those tied to the platform's own sessions** (`node.platform_session` set). These are judged by the tie rule (§5), not by the baseline, so a session the node ran during learning can't make a later untied one normal.
- **Those made while the coverage was `degraded`.** They are counted in `period`, so the operator sees how much of the learning period was degraded.

### 2.2 Learning

The operator starts learning for a period (the default is 7 days, a parameter). The learner folds observations into the draft as the stream's required local consumer (D5 §3, #532 §3). It checkpoints the draft in `netcheckpoint.learner` (C13 §8) at least every `fold_batch` observations, and its cursor is confirmed only after that checkpoint commits. So the observation class keeps draining during learning (D5). When learning ends, the draft is frozen. The learner folds nothing more, and its cursor follows the detector's until acknowledgement, so pruning isn't held while the draft waits for a person. The person signs the accepted document's digest together with the frozen draft's (HR-14, §2.3). When a person acknowledges the baseline, the node retires the learner consumer with an audit record, and it never holds pruning again. Relearning starts a new learner consumer (D1, D4-68). Tests check two things: observations stay prunable during learning as each learner checkpoint commits, and after acknowledgement the retired learner holds nothing back. At the end it records the draft as `baseline.network`, version n + 1, and the detector keeps using version n until a person acknowledges n + 1. With no acknowledged baseline, the detector runs only the rules that don't need one: `own-session-outside-record`, `node-address-spoofed`, `own-session-unseen` and `sa-failed` (D1). Status says that the other five are off. D6's test: a failed SA exchange on a node with no acknowledged baseline raises `sa-failed` and nothing else.

### 2.3 Acknowledgement and the authorized writers

The admin client shows the frozen draft: pairs, services and functions grouped by server asset, with every write-class or control-class function the learner saw marked. It also shows the authorized-writer list, which starts empty, and the person adds each authorized writer explicitly. Then the signed path is D3's (C7 0.10 and C8 0.12, for D4-68):

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
- The checkpoint holds the open coalescing windows (C13 §7.3) and the session-tie state (§5).
- **No duplicate alerts after a crash (D5).** An alert commits in the `network` database, and the checkpoint commits later in the configuration database. There is no transaction across the two. So the checkpoint records the last alert seq the detector knew of on its alert stream. On restore, the detector first reads the alert records after that seq and seeds its coalescing windows from them. It goes by seq, not by time: the store stamps a commit with the later of now and the stream's last commit time, so after a backward clock step an alert committed after the checkpoint can carry an earlier time (D5). An alert already committed is then never raised again, and a summary counts its hits once. With that, a restore gives the same alerts as an uninterrupted run. Where the tests go (D6):
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
| 2 with only group 50 objects | `time-sync` | confirmed: Write | S33 Table F.2 p. F.2; g50v1 and g50v3 in S22 Table D.9 pp. D.17 to D.18 |
| 2 with only g80v1 objects | `session-setup` | confirmed: Write | S22 p. D.18 (index 7); S23 Table 2.30 p. 82 (indexes 4 and 7) |
| 2 with any other object, or a mix | `write` | confirmed: Write | S33 Table F.2 p. F.2; g34 deadbands in S22 Table D.9 |
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
| 43 with MEI type 14 | `read` | unknown | no held SEL device lists 2Bh |
| 8 with sub-function 0 | `other` | confirmed: loopback | S22 Table E.18 p. E.11 |
| 8 with sub-function 1 or 4 | `control` | unknown | none held. D4 puts them in `control` because restarting communications or forcing listen-only mode can silence a device |
| 8 with any other sub-function | `other` | unknown | none held |
| 60h, 61h, 62h | `read` | confirmed: parameter information and text reads | S22 Table E.2 p. E.2 and p. E.17; S34 Table E.2 p. E.2 |
| 7Dh | `control` | confirmed: encapsulated packet with a control command | S22 Table E.30 pp. E.15 to E.16; S34 p. E.14 |
| 7Eh | `other` | confirmed: no-operation, used only inside 7Dh | S22 Table E.2 p. E.2 |
| any other code | `other` | unknown | none held. The RTAC's Report Server ID is a read (S23 p. 275), but its number is unknown from the held source, so it falls here |

**Alert text follows the class, not the code.** A `write` alert says "wrote to the device", never "a settings write", because 06h and 10h also operate outputs. A `session-setup` alert says "changed event reporting".

Time-sync gets its own class because "write = bad" otherwise alerts on every routine time sync (A4 §3). It is judged as a function, not as a write: a time-sync from a pair that never sent one is `new-function`.

Every rule's alert form is C13 §7. Its key for coalescing is rule × destination asset, or the unresolved bucket (C13 §7.3).

| Rule | Raised when | Parameters | Malicious sample (D6 plan §4) | Benign near-miss |
| --- | --- | --- | --- | --- |
| `unknown-pair` | A `flow` `start` whose (client, server, `l4`, server port, `protocol`) is not in `pairs`. A midstream flow alerts only if neither orientation is in `pairs`. | none | A new master polls the outstation | The known master on a new TCP source port: the source port is not in the key |
| `new-service` | A `service` whose (server, `l4`, port, `protocol`) is not in `services` | none | A port opened on the relay that the baseline never saw | A known service on a new client port |
| `new-function` | A `function` (a request, C13 §4.3) on a known pair whose (code, objects) is not in `functions` for that pair, and whose class is not `write` or `control`. So it judges `read`, `time-sync`, `session-setup` and `other` | none | A pair that only read starts sending a time-sync; a pair that never did the reconnect sequence disables unsolicited reporting (21) | A time-sync from a pair that time-synced during learning; a reconnect sequence from a master that did it during learning; an outstation response carrying an object group not seen in learning, which is not a function and raises nothing (D6) |
| `unauthorized-write` | A `function` of class `write` or `control` whose (client, server, class) is not in `authorized_writers` | none | A DNP3 direct operate, or Modbus 6, 16 or 7Dh, from a master authorized only to read; the same DNP3 operate with its response removed, which is emitted at `sa_reply_timeout_ms` with `sa` absent (C13 §4.3, D3) | The same function from the authorized master; a DNP3 time-sync from the authorized master (class `time-sync`, not `write`); a reading master's reconnect sequence (class `session-setup`) |
| `own-session-outside-record` | A `flow` from a node address to an asset, or to an asset's session port, with no `platform_session` tie (§5) | `tie_grace_s` (default 30) | A Telnet session to the relay from the node's address outside any window | The node's own scheduled session inside its window |
| `node-address-spoofed` | A frame from a node address whose source MAC is not one of the node's MACs, taken from the install configuration. It runs only on the segments or VLANs the install configuration names as the node's own layer-2 segment, because across a router the node's frames carry the router's MAC (D3, D6) | none | A session from the node's IP with another MAC, on the node's segment | The node's real session; the node's real session seen beyond a router, with no alert |
| `own-session-unseen` | A session record whose collector-to-device flow has not been observed by the window's end plus `tie_grace_s`, while the coverage covers that device (AP-36's canary). **Covers** means: the asset's address is in the baseline's `addresses` on a VLAN in `vlans_seen`, its PRP LAN is in `lans_seen`, and no observation or heartbeat in the window has a non-empty `degraded` (D6). **Before acknowledgement** it reads the learner's draft in place of the baseline: the check covers an asset once the draft holds any observation of that asset's address, with the same VLAN, LAN and `degraded` conditions. An enrolled asset that the draft has never seen shows in status as "not yet seen", so the gap is visible (D6, D4-68) | `tie_grace_s` | The SEL-751 capture with the node's own session removed, while the sensor reports full coverage (D6 plan §2C) | The same removed session while the sensor reports `degraded`, or with that VLAN unseen, with no alert; before acknowledgement, the same removed session to an enrolled asset the draft has never seen, which shows in status as "not yet seen" and raises no alert (D6) |
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

- **The tie.** The detector ties a `flow` from a node address to a session record from the collector. The record gives the asset, the destination address and port, and the window `[started_at, ended_at]`.
  - **A `connection` tie** is used once C2 `SessionFacts` carries `local_addr` and `connected_at` (D2's proposal). The flow must match the local port and start within `tie_grace_s` of `connected_at`. A second connection from the node's address to the same asset inside the window then alerts as `own-session-outside-record` (AP-35, D6 on #523).
  - **A `window` tie** is used until then. The flow must start inside the window, and its destination must be the record's address and port. Only the **first** established connection from the node's address to that destination inside the window is tied. D2's facts make that safe: the SEL-751 adapter opens at most one established connection per run, and retries the dial only when it fails before any byte is sent (`modules/ied/sel751/run.go` `connect`), and the collector never runs two sessions to one asset at once (`Pipeline.claim` in `modules/security/collector/pipeline.go`). So a second established connection to that destination inside the window is never the platform's, and it alerts as `own-session-outside-record`. A connection attempt that never completed the handshake is not counted. For SNMP, the run is one UDP conversation, so "connection" means that conversation. AP-35's **residual** is now narrower: an attacker's connection that starts inside the window before the platform's own is tied in its place, and the platform's then alerts. Two assets on one host and port are flagged at enrollment (C13 §5).
- **The node's addresses and MACs** come from the install configuration, never from traffic.
- **Flows to the node's forward targets and the sensor link** are not judged by this rule, because their destinations aren't assets. Each exclusion is an exact (destination address, `l4`, port) entry in the configuration, never an address alone or a wildcard. `node-address-spoofed` still applies to those flows (D3).
- **The canary** (`own-session-unseen`) is the independent check on a blind sensor (AP-36 residual, D1 on #525 §3). It runs only for sessions to an asset whose LAN the coverage statement claims, so a sensor that honestly reports partial coverage is not alarmed for traffic it said it couldn't see.

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

- **The `window` tie's residual** until C2 carries the connection: an attacker's connection that starts inside the window before the platform's is tied in its place (§5).
- **A baseline learned while an attacker writes** still catches the writes, through the authorized-writer list (§2.3). A read-only attacker present throughout learning is in `pairs`, and is caught only if the person spots the pair in the draft.
- **Midstream flows** of an orientation never seen with a handshake are judged both ways, and alert only if neither way is known (§4).
- **The class table is only as good as the held manuals.** Rows marked `number only` or `unknown` in §4 rest on D4's choice, not a source. IEEE 1815 and the Modbus specification would settle them, and neither is held. A code missing from the table is `other`, which `unauthorized-write` never judges.
- **A spoofed authorized-master address passes `unauthorized-write`.** A passive IDS can't tell a forged source address on another segment from the real master. This is stated, not tested (D6).
- **A flood that mimics a known pair** has a resolved end, so the unresolved budget doesn't apply, and it raises no alert. It can fill the observation class, so a real write to another asset is dropped before the detector reads it. The node counts refused observations by destination asset, with one bucket for unresolved destinations, as it counts alerts (#532 §4). D6's spoofing-flood test includes this flood beside the unresolved one. If the test shows starvation, a budget per destination asset on observations follows. Otherwise it is AP-36's residual (D3).
- **`sa-failed` can't tell a forgery from a wrong key** (D2, D6, D1). The sensor sees that the outstation refused the request's authentication, but it can't check the authentication codes, because it holds no keys. So the alert says "SA authentication failed" and never "forged": an attacker's forged operate and an authorized master with a stale key look the same. `sa: failed` never sets `dnp3_no_sa`, because SA is in use (C13 §5). The rule keys on g120v7's presence, not its error code, because the project holds no SA specification and the code's offset and values are `unknown` (D2). It can't tell a key mismatch from any other error, and its `hits` are a lower bound, because the outstation caps the errors it sends (S23 §12.4.8, p. 89).
- **Visibility limits** are C13's coverage statement and R6.6: HSR, encrypted payloads, unsupported protocols, and sensor placement.

## 9. Open questions

1. **Owner, through D1:** whether an insecure use should alert on its own (§7), and the 7-day default learning period.
