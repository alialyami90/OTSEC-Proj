# D5: the node's side of the passive network sensor (P4-4-A5)

D5, 2026-11-07. This is the design note for brief P4-4-A5 (`docs/agent-handoffs.md`, item 4, Stage A, D4-66). Everything in it is `desk`. Nothing here has run, and no code is proposed for merging in this stage.

The note covers six topics:

1. how the sensor process is supervised;
2. the channel to the node;
3. how C13 records reach the store, and how much room they get;
4. where the cited packet bytes live;
5. switching the sensor on and off;
6. what status shows.

It also covers the install side of C-11 on Windows and where the tests go.

ADR-0009 has not named an option yet. So each section gives the node's side for options (a) and (c), a sensor process on the site node, and separately for option (b), a sensor on its own Linux host. Where a section depends on C13's shape, it says so. The C5 changes that this note asks for are drafted beside C13 once the ADR names the option (Order step 2). They are not drafted here.

## 1. Supervision

### Options (a) and (c): a sensor process on the site node

The brief asks for a comparison of two ways to run the sensor: as its own SCM service, like the collector, or as a child process of the node.

| | Its own SCM service | A child of the node |
| --- | --- | --- |
| **Account** | Its own virtual account, `NT SERVICE\otsec-sensor`, with its own service SID. The installer already creates the node and the collector this way (`platform/winsvc/install_windows.go`, `createService`). | The node's account. Running the child under another account needs `CreateProcessAsUser` and a token, which in turn needs privileges the node is denied (W-2, no `SeImpersonatePrivilege`). On Linux the node isn't root, so it can't drop the child into another user either. |
| **What a decoder exploit reaches** | Only what the sensor's account can open. The store directory's protected DACL (W-4) and the node keys don't grant it anything. | Everything the node's account can open: the store, the node keys and the collector pipe. This defeats D3's hostile-input row, which requires that a decoder crash or exploit cannot reach the store or keys. |
| **Restart** | The SCM restarts it, with the recovery action the installer gives the node and the collector: restart after 60 s, failure count reset after a day. | The node has to restart it. That means a supervisor loop inside the node, which ADR-0002 item 5 rules out ("no orchestrator"). |
| **Firewall and pipe ACLs** | Rules per service SID, as HR-9 does for the collector. | The child shares the node's SID, so no rule can tell the two apart. |
| **Crash dumps** | The sensor can be excluded from WER on its own, like the collector (T-5). Its memory holds packets, which may include Telnet and FTP passwords and SNMP community strings. | The exclusion would have to cover the node too. |
| **Enable and disable** | Two switches: the installer installs or removes the service, and the node's configuration has a section (§5). | One switch, the node's configuration. |

**Recommendation: its own SCM service** on Windows, and a systemd unit with its own user on Linux. This is ADR-0002 item 2: each separate process runs as its own principal and names the boundary it enforces. The only cost is the second switch in §5, and the node turns that into a check.

Under this choice the node doesn't start, stop or restart the sensor. It doesn't have the SCM rights to, and it shouldn't get them. The node watches the sensor over the channel instead (§2):

- **The heartbeat.** The sensor sends one every 10 s. The node raises `sensor-unreachable` after 60 s with no heartbeat accepted, as it does for `forward-unreachable`. It times this on its own monotonic clock from the later of the last accepted heartbeat and its start; a reconnect never resets it (D4-73). It is raised once per quiet stretch, status shows `unreachable` until the next accepted heartbeat clears it, and a step of the wall clock moves nothing. `sensor-unreachable` is raised at the first Tick at or after 60 s of quiet, so at most 60 s + `TickInterval` (≤ 120 s today) (D1 on #581).
- **Restarts are counted.** Each time the channel reconnects after a gap, the node counts a sensor restart and shows the count in status. A decoder that crashes on the same packet every time restarts every 60 s indefinitely, and status shows that loop.
- **Coverage gaps are records.** While the sensor isn't capturing, the network isn't watched. The node commits a `sensor.coverage-gap` health event when the channel drops, and closes it with the end time when the channel returns. The gap is forwarded like any other health event. A quiet alert stream therefore can't be read as a quiet network over a period when nothing was capturing (R6.1). It also holds at a node start: a gap is open until the first heartbeat arrives.

### Option (b): a sensor on its own Linux host

The node supervises nothing. Restarting the sensor is that host's job: a systemd unit with its own user. The node sees only the link, which uses mutual TLS. **The node opens it, and the node never listens for it** (AP-34, "never a listener open to the station LAN"; settled with D3 on #526):

- **Enrollment.** The sensor is enrolled with a revocable credential like a node's (SC-11). The node accepts only that sensor's certificate, and the sensor accepts only the node's.
- **The listener is on the sensor host.** It is bound to that host's management interface only, never its monitoring interface, and its host firewall allows only the node's address. The node dials out to it, as it dials out to its forward targets, and its own firewall allows that one destination. The node gains no inbound port.
- **Records still flow from the sensor to the node** over the connection the node opened. The node reads them, as in §2.
- **Health.** The heartbeat, `sensor-unreachable` and the coverage-gap records work as above. A link outage is also a coverage gap, unless the sensor buffers its records and the gap is in the records it sends. A disk buffer on the sensor host is the sensor's design, so it belongs to D4.
- **Attack surface.** The sensor host's own management interface and update path count as attack surface (D3's ADR row). Nothing on the node's side reduces that.

## 2. The channel to the node

**Options (a) and (c): a local named pipe, using the collector's pattern** (`deploy/README.md`, Windows host rules: "a named pipe IPC on which each end checks the other's service SID").

- The node creates the pipe. Its DACL grants connect only to `NT SERVICE\otsec-sensor`, and the node checks the client's service SID on every connection. The sensor checks that the server is the node.
- On Linux, the channel is a Unix socket in a directory that only the two users can reach, with `SO_PEERCRED` checked.

**Every record that arrives is hostile input.** The sensor parses attacker-controlled packets, so what it sends is only as trustworthy as its decoders. The node therefore does the following:

- caps each frame's length;
- decodes and validates each record against C13 before it commits anything, as `ConfigDocuments` does for configuration records;
- bounds and quotes any device text, as C2's record values are (D3, `contracts/adapter/doc.go`);
- never writes a record's text raw into status or a Syslog forward.

A record that fails these checks is dropped and counted, and the node raises `sensor-record-refused` once per condition. The connection stays up, so one malformed record doesn't stop capture.

**Only the node writes the store.** The sensor never opens the store or a node key, and the store directory's DACL doesn't grant it access. This keeps C5's single writer per database (`Database.Writer`) as it is, and keeps the store outside the decoder's boundary.

**Back-pressure.** A passive sensor can't slow the network. When the node isn't reading, because the database is drain-only or a class is full, the sensor's in-memory queue fills, and the sensor drops and counts. Each heartbeat carries the sensor's counts: drops in the capture driver, in the decoder queue, and on the channel. The node persists them as health events, so every loss at every stage is recorded once.

**What option (b) changes:** the transport is TLS over the site LAN instead of the pipe, on a connection the node opens (§1). The validation, the counting and the single writer stay the same.

## 3. C13 records in the store: database, classes and quotas

**A database of its own, `network`.** It follows the precedent of `syslog` and `configuration`: received Syslog has its own database "so a Syslog storm cannot hold the evidence database's lock" (`platform/node/layout.go`). A flood of observations must not hold the lock of the SER, Syslog or audit databases either. The database exists only when the sensor section is in the configuration (§5).

**Separate classes, because a quota is per class.** C5's class set is closed (`contracts/store/class.go`), so each class below is a C5 change, drafted at Order step 2:

| Class (draft name) | Holds | Full action | Why |
| --- | --- | --- | --- |
| `network-observation` | C13 observations: flows and services seen | `drop-and-count` | The sender is the monitored network, which can't be slowed. At its quota, new observations are dropped and counted, and the alarm says so. |
| `network-alert` | C13 alerts, with their cited packets as the record's capture | `drop-and-count`, on a quota of its own | An attacker can produce observations at will, from new flows or spoofed addresses. Without a separate quota, a flood of observations would push out the alerts it should trigger. A separate class keeps that room for alerts. |

This is the HR-11 lesson. A flood of unknown senders once had a rate budget only (A3's option (b)), and the absolute bound was a class of its own (`syslog-unknown`, C5 0.4).

**Unresolved observations.** An observation whose addresses resolve to no asset (`asset-unresolved`) is the cheapest thing for an attacker to forge. The node gives unresolved observations a rate budget, sized like a listener's unknown share: they may take at most a quarter of the observation quota over the planned outage, with drops counted and status showing the share. That is a rate bound, not an absolute one.

The absolute bound would be a third class, `network-unresolved`. I recommend starting with the rate budget, for two reasons:

- the local consumer below keeps the observation class draining;
- the first unresolved address is itself an alert, which goes to the alert class, aggregated as below.

D1 ruled a rate budget for 0.1, with D3's agreement, once the ring redaction (§4) and the aggregation below are in. A third class is the fix only if D6's flood test shows starvation (§9). If the ruling is a third class, the cost is one more quota in the volume sizing.

**Alerts an attacker can forge cheaply are aggregated (D3).** The alert class is meant to be the safe one. An attacker who spoofs many source addresses could still fill it with forged first-seen alerts, pushing out the real ones. So an alert whose trigger costs an attacker nothing is aggregated:

- This covers a new unresolved address, and a new pair from an unresolved source.
- There is one alert per kind per window. It carries a count and a bounded sample of the cited frames, not one alert per address.
- The window and the sample size are C13's, with D4's baseline note. The class's `MaxRecordBytes` bounds the sample's bytes.

The node enforces this bound where alerts enter the store, whichever side raises them. If the sensor raises them, the node does not trust it to aggregate. A record of an aggregated kind beyond one per window is refused and counted (`sensor-record-refused`), so a compromised sensor cannot use those kinds to fill the class either. An alert of any other kind is unaffected.

**Pruning needs a consumer.** C5 never prunes a stream with no consumer, and never evicts unconfirmed records (ADR-0004 item 9). Observations are not forwarded as they arrive: whether they are C4 events is C13's choice, and the configuration documents set the precedent that typed documents are not. So with no consumer the observation stream would fill once and then drop everything new, forever.

The node's detection module, the network baseline and its detector (D4's note), is therefore a **required local C5 consumer** of the observation stream:

- Its cursor moves once an observation is folded into a checkpoint that is committed, as `node-suspensions` and `node-holds` do for the audit stream.
- What is folded becomes prunable.
- The alert stream is consumed by the forward targets, like any event stream that is forwarded, if C13 makes alerts C4 events.

**Sizing.** Each class gets a floor that the node checks at load, like the configuration floor (D4-20 rule 5):

- the alert floor holds a number of the largest alerts, each alert plus its packets at the alert's `MaxRecordBytes`;
- the observation floor holds the consumer's lag at its slowest checkpoint interval.

Both numbers wait for C13's record sizes. The volume rule in `deploy/README.md` gains both quotas, times `DiskBytesPerQuotaByte` (2.5), plus the `network` database's reserves.

## 4. Where the cited packet bytes live

R6.5 needs every alert's packets to be retrievable. C13 has every observation and alert cite its packets as a capture ID, frame numbers and the SHA-256 of the cited bytes. The proposal splits by record kind:

- **An alert carries its cited packets as its C5 capture.** The store already keeps each capture once, keyed by its SHA-256, and deletes it only in the prune step that removes the last record referring to it (EP-6). So an alert's packets live exactly as long as the alert does. The alert class's `MaxRecordBytes` bounds the bytes per alert (C13 sets how many frames an alert may cite).
- **An observation carries only its citation.** The bytes stay in the sensor's capture ring: a fixed set of capture files in the sensor's own data directory, with a fixed total size set in the sensor's configuration and counted in the volume rule. An observation's packets can be retrieved while the ring holds them, and its hash and frame numbers last for as long as the observation does. Keeping every observation's bytes in the store would let an attacker turn traffic straight into used storage.
- **The ring is written redacted (D3, D4-67 on #524).** Raw capture files would hold every cleartext credential on the segment at rest, the platform's own SEL Level 1 password included. That covers Telnet and FTP passwords, SNMPv1 and v2c communities, and HTTP Basic headers. So the sensor applies D4-67's positional redaction before it writes a frame to the ring, never after. Two rules follow:
  - **It fails closed.** Where a slot can't be placed, the client-sent bytes of that login are not written. This is D4-67's rule for the store, applied to the ring.
  - **Ring frames carry the same markers as a citation.** A cited SHA-256 is over the redacted bytes, so it checks against what the ring keeps, and an alert's stored capture and the ring agree byte for byte.

  This protects the disk at rest, a stolen node and other local readers. It does not protect against a compromised sensor, which still sees live traffic (AP-33's scope). GT-PCAP's key search searches the ring's directory as well as the store (D6). The WER exclusion in §1 is still needed for the packets the sensor holds in memory.
- **Nothing leaves the site, by construction.** The forwarder reads events only. `modules/telemetry/forward` never calls `Outbox.ReadCapture` (grep, at `7e09898`). On the node, only quarantine export, identity and the event-baseline feeder read captures. So cited bytes are never forwarded upstream; their hash and frame numbers are (D3's stored-captures row).
- **Retention.** An alert's bytes go when the alert is pruned, which needs every required consumer to have confirmed it. The ring's retention is its size divided by the traffic rate, and status shows the age of the oldest file in the ring. A fixed retention in days would need deletion that C5 doesn't do, so I don't propose one. If the owner needs one, it is D3's row and a C5 question.
- **Who may read them.** The ring's directory gets a protected DACL: the sensor's account, plus whatever D3's row names for the security role. The node's account doesn't read the ring, and status never shows packet bytes. Reading an alert's packets from the store goes through a security-role export, like quarantine export. D3's row decides the role.

## 5. Switching the sensor on and off

**On means two things:** the installer has installed the sensor service, and the node's configuration has a `network_sensor` section. The section holds:

- the class quotas;
- the unresolved budget's outage hours;
- the expected coverage: interfaces, SPAN or TAP, and the protocols to decode.

The node then checks the sensor against it. If the coverage statement in the first heartbeat doesn't match the configuration, the node raises `sensor-coverage-mismatch`. That catches, for example, a monitoring interface that is missing or renamed.

**Off is the section being absent.** The node behaves as it does today:

- The layout has no `network` database, and C5 opens only the databases its layout names. A `network` database left from an earlier enabled period stays on disk unopened and is never deleted, as with every store file.
- The node creates no pipe, so an installed sensor service has nothing to connect to. It logs that to its own event log source and retries. The node raises nothing.
- Status has no sensor section, the node raises no sensor alarms, and the volume rule has no network terms.

**Nothing else changes.** I propose D6 test this the way the brief words it. A node configuration without the section, run with the sensor installed and with it absent, gives these results:

- the same layout;
- the same start line, except for its timings;
- the same status apart from times;
- no alarm that mentions the sensor.

A node with the section and no sensor running starts and collects normally. It shows `sensor-unreachable` and an open coverage gap, and nothing else changes.

**What option (b) changes:** "installed" is the remote host's enrollment instead of a service on the node.

## 6. Status

Status gets a `sensor` section, written as the other sections are, and `otsec health` prints a line for each item:

- whether it is enabled and connected, and the time of the last heartbeat;
- the sensor's version and its coverage statement (§5);
- packets and bytes seen, and drops by stage: capture driver, decoder queue, channel, and node, split into full class and unresolved budget;
- observations and alerts stored;
- the restart count since the node started, and the open coverage gap, if any;
- the oldest file in the capture ring;
- the C-11 interface check (§7): `ok`, or what is bound;
- the intake hold's counts (`hold`: held records and runs, ties, the caps' releases, the open table's counts and checkpoint failures), the start repair's runs (`runs_repaired`, `runs_repair_refused`), and the runs whose `collection.run` has no session (`runs_session_missing`) (D4-72, `D5-c5-0.9.md` §8).

Status never shows packet bytes or device text, and banners are shown bounded and quoted (D3).

The alarm codes in this note are `sensor-unreachable`, `sensor-record-refused`, `sensor-coverage-mismatch` and `sensor-interface-bound`, and the intake hold's `intake-checkpoint-failed`, `intake-record-not-removed` and `intake-repair-refused`. They are draft names. The node's alarm codes and C6's health events are named with the C5 draft.

## 7. C-11 on Windows: the install side

C-11 says the sensor never transmits on its monitoring interface. A TAP guarantees that by construction. On a SPAN port with a host NIC, it rests on host settings, which the installer under `deploy/` makes and the sensor checks at each start:

1. **Unbind every protocol from the monitoring NIC except the capture driver's filter**, using `Disable-NetAdapterBinding`. That covers IPv4 and IPv6, the Microsoft client and server, LLDP, and the link-layer topology discovery drivers. Without an IP stack the interface sends no ARP, DHCP, IPv6 router solicitation, LLMNR or NetBIOS. Without the LLDP and LLTD drivers it sends no discovery frames. Those are the frames C-11's threat row names.
2. **Firewall rules for the sensor's service SID**, HR-9 style: block all outbound and all inbound for `otsec-sensor` on every interface. Those rules act on IP traffic only, so they back up step 1 if the IP stack is ever bound again. They don't replace it. The sensor's channel to the node is a local pipe, so these rules don't affect it.
3. **No out-of-band controller on the monitoring NIC.** On the SEL-3355-2, Intel AMT sits on ETH1 and transmits regardless of what the OS binds (ADR-0007 item 8). The monitoring NIC must not be ETH1 unless AMT is checked as disabled at commissioning.
4. **A check at each sensor start:** read the NIC's bindings back. If anything other than the capture filter is bound, for example after a Windows update or a technician's change, the sensor raises `sensor-interface-bound` and the node shows it. The sensor keeps capturing, because stopping capture wouldn't stop the OS from transmitting. The alarm is what gets the binding fixed.

The capture driver can itself send frames, as Npcap's `pcap_sendpacket` can. Nothing in steps 1 to 4 prevents that. It rests on the sensor's code never calling a send path, and on D6's C-11 test: zero frames over the GT-PCAP replay and the sensor's start and stop.

Which accounts may open the driver is part of the driver choice in ADR-0009. The sensor must not run as LocalSystem or in Administrators. I understand Npcap's installer can restrict the driver to Administrators, which would force exactly that. I haven't verified this, and D4 records it in the ADR.

On Linux, for CI and for option (b)'s host, the same steps are:

- the interface up, with no address, ARP off and IPv6 disabled on it;
- no DHCP client on it;
- the sensor's user holding `CAP_NET_RAW` only.

`CAP_NET_RAW` also allows sending, so the same caveat applies. An nftables `netdev` egress drop on the interface would add enforcement in the kernel. Whether it also catches every `AF_PACKET` send path is unverified, so the ADR marks it `unknown` until a test shows it. D6's C-11 rig can settle this: a veth pair in its own network namespace, the rule in place, and a deliberate `AF_PACKET` send from the sensor's end that must not reach the peer. D6 adds it as a rig case once ADR-0009 needs it.

## 8. Tests and where they go

On Windows, the `platform/node` test step already runs 530 to 648 s against its 720 s budget (#520's runs). So:

- The node's side of the channel goes in a package of its own: the pipe or socket, record validation, the heartbeat, coverage gaps, status and the on/off check. A draft name is `platform/sensorlink`.
- The node gains only the wiring and one start test.
- The installer's NIC steps go in `platform/winsvc`, tested in the dispatched Windows workflow. A hosted runner may not allow its adapters to be rebound, so a step that can't run there is reported `unknown`, not skipped silently.

Three rules for these tests, from D6's testability review:

- **The test clock.** The 10 s heartbeat and the 60 s `sensor-unreachable` run on the test clock, as GT-INJ's tests do. A 60 s wait on the wall clock against a deadline that moves is the H11 kind of race.
- **Forced drops are asserted exactly.** Decoder-queue and channel drops are forced with a small queue or a seam, and their counts are asserted exactly. Capture-driver drops can't be forced on a hosted runner, so they are read and reported, never asserted.
- **Status comparisons name what they ignore.** §5's "the same status apart from times" strips a listed set of field names. The list is committed with the test, so the normalizer can't hide a difference.

These tests would show the design holds:

| Property | Test |
| --- | --- |
| Off changes nothing | §5's comparison, with and without the sensor installed. |
| Only the sensor's SID connects | A client under another service SID is refused, as in the collector's pipe tests. |
| Hostile records are refused | Oversized frames, malformed C13, and banners with control characters are each dropped and counted, and the connection stays up. |
| A flood of observations doesn't take the alerts' room | Fill `network-observation` to its quota; alerts still store, and observations are counted as dropped. |
| A flood of unresolved addresses doesn't take resolved assets' room | Spend the unresolved budget; resolved observations still store. |
| Spoofed addresses can't fill the alert class (D3) | Spoof N source addresses in one window. The alert class grows by a bound that doesn't depend on N, and a real alert in the same window still stores. Do the same with the sensor sending one first-seen alert per address: the node refuses all but one per window, and counts them. |
| The ring holds no cleartext credential (D3, D4-67) | Replay GT-PCAP's Telnet, FTP, SNMPv1 and v2c, and HTTP Basic sessions, including a midstream login. The ring's files contain none of the known test secrets, in any of V-M1 M3's four forms: raw, hex in either case, and base64. The cases include GT-PCAP's §2D ones: one byte per frame, a retransmitted segment, PRP duplicates and a server that echoes. The midstream login's client bytes are absent, and every cited hash matches the ring's bytes (D6). |
| Observations are pruned once consumed | The consumer's cursor moves after a checkpoint, and a prune frees the space. |
| Gaps are recorded | Kill the sensor: `sensor-unreachable` is raised after 60 s, and the gap record is closed when the sensor returns. |
| A gap is open at start (D6) | A node start opens a coverage gap, and the first heartbeat closes it. |
| Restarts are counted (D6) | Each reconnect after a gap adds one to the restart count. |
| Coverage is checked (D6) | A heartbeat whose coverage statement doesn't match the configuration raises `sensor-coverage-mismatch`. |
| The sensor's account reaches nothing of the node's (D6, D3's AP-30) | From the sensor's account, opening the store directory, the node keys or the credential store fails. |
| The ring's DACL holds (D6) | The node's account and the monitoring role are refused when they open the ring. |
| A re-bound NIC is caught (D6, §7 step 4) | Re-bind IPv4 on the monitoring NIC and start the sensor: `sensor-interface-bound` is raised. Where a hosted runner can't re-bind, the step reports `unknown`. |
| Packets stay at the site | A forwarded alert carries the hash and frame numbers and no packet bytes. |

## 9. Open points

- **The class names, full actions, floors and alarm codes** are drafts for the C5 change at Order step 2. They depend on C13's record shapes.
- **A third class for unresolved observations, or a rate budget** (§3). D1 ruled a rate budget for 0.1, on condition that the ring redaction and the alert aggregation are in. D6's spoofing-flood test decides: if alerts or SER and Syslog are starved, `network-unresolved` becomes a C5 class before the gate. D1 records this with the decision that approves C13 and the C5 draft.
- **The aggregation window and sample size** (§3): C13's and D4's.
- **Retention of the capture ring by size only** (§4): if the owner needs a retention in days, that is D3's row and a C5 question.
- **Driver access on Windows, and egress enforcement on Linux** (§7): `unknown` until ADR-0009's runs show them.
- **Option (b)'s buffering on the sensor host:** D4's design.
