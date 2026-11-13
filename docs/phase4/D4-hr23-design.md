# D4: HR-23's fix, the design (P4-4-HR23, stage 1)

D4, 2026-11-13. Brief P4-4-HR23 (`docs/agent-handoffs.md`, "After D4-100"), under D4-100 items 1 to 3. Documents only: nothing is built or run here.

- **Evidence class: `desk`.** Every statement about Zeek's code below comes from reading its source, and stage 3's counted run measures it. The results this note cites from earlier runs (section 1 item 5, and section 4.2's Basis column) are measured, `CI-Linux`, `simulated`, each named with its run.
- **What was read.** The release tarball `https://github.com/zeek/zeek/releases/download/v9.0.1/zeek-9.0.1.tar.gz`, fetched over HTTPS on 2026-11-13, SHA-256 `fbee2eb5ee6ebd64ef0db830fbb9fa1d702d58807643c719e8338a59329197f2`. It was unpacked in D4's scratch folder, outside the repository. Its signature file `zeek-9.0.1.tar.gz.asc` (SHA-256 `269e266a0b473b4621448034b98a9f8aafe39f0e53f026ad03bff5312e5bffce`) was fetched and **not checked**, because D4 holds no Zeek signing key. The tarball matches the pin of `docs/phase4/D4-engine-linux-eval.md` §3 (tag `v9.0.1`): its `DNP3.cc`, `dnp3-protocol.pac`, `dnp3-objects.pac`, `events.bif`, `base/protocols/dnp3/main.zeek` and `dpd.sig` have the SHA-256s §3 records.
- **Files cited**, with their SHA-256 in the tarball. Code is cited by function, never by line.

  | File | SHA-256 |
  | --- | --- |
  | `src/analyzer/protocol/dnp3/DNP3.cc` | `8a6fb005cc7b52cbd7a3846a733a3be017ee248af3966d12eae366c1c28c7e6e` |
  | `src/analyzer/protocol/dnp3/DNP3.h` | `f459be85ee1389de9e05de33665925f5bafa2a330f1d84b82ec04cfe9ec223c9` |
  | `src/analyzer/protocol/dnp3/dnp3-protocol.pac` | `497eeac4504d8d925d4b35ec9e5c8950b7d3309d2b7a96b644e1c500312279b1` |
  | `src/analyzer/protocol/dnp3/dnp3-analyzer.pac` | `fb6465597444e14db17c38dabd685e47812d50480ec93c719732562eb1bf7ee2` |
  | `src/analyzer/Analyzer.cc` | `f2a3ede9ec30c32a8601327ece4885317743e7bda69460b7b88746caa776180b` |
  | `src/analyzer/Analyzer.h` | `5e8adf8cd9e78884e19bcba8aa8541c877289044cb2ac4d5ffaab8af8dfe32f1` |
  | `src/packet_analysis/protocol/udp/UDP.cc` | `7f1248aeb871040a3a72162061d6ba02813d5b26149babb713b1b1d656ea24d9` |
  | `src/packet_analysis/protocol/ip/IPBasedAnalyzer.cc` | `24e6b81f6d916514c02ef0532639e69540556cb1059e9b8efcc98922812024ea` |
  | `src/analyzer/analyzer.bif` | `ed3da4584fdbc6544d490147ef8ac87955798a2afee0e9f164f036cbbd8c293c` |
  | `src/zeek.bif` | `b30d00ed40a3b71814dc88ca92a8c77136e17dc90d467c9b6bfc730c5a9c6ad9` |
  | `scripts/base/frameworks/analyzer/dpd.zeek` | `c24fe9d4ab5d12aa260b7a7d0b84a1cbf776cfcd67776c64faee2e7e904833eb` |
  | `scripts/base/frameworks/analyzer/main.zeek` | `55e4809d1ae27353a3a9e3f2bfbc8a14a46cef97864f4354d0a213fd09f5465b` |
  | `scripts/base/protocols/dnp3/main.zeek` | `37f51eab720db2d744ef229c0a10b0fbcd90a131b859f5500f4665a51258d2cd` |
  | `scripts/base/protocols/dnp3/dpd.sig` | `b2067b53fca4dff949c837928e94af647318cc4937d8a37fac3be5d62488a402` |
  | `src/fuzzers/CMakeLists.txt` | `eaefb55fb3c8cb35cad7f2c9aaa368a9c8fbbc75d11d4b6eff2bc00d9113ecb7` |
  | `src/analyzer/protocol/dnp3/dnp3-objects.pac` | `0ba3df0cab28933f6729d6cab06d9b5c0d88bb9554c9b4a89caeb5b6b24dc493` |
  | `src/analyzer/protocol/dnp3/events.bif` (DNP3's events) | `c3c3107870fb0347e0aaa7f3e004d35fb369b9e7908e88862889b970e2de7100` |
  | `src/packet_analysis/protocol/udp/events.bif` (UDP's events) | `d9d7f5a2fec8a32a789add0bcee07957fdabe51f35c464dec0e632fc10ef52c2` |
  | `src/analyzer/protocol/dns/DNS.cc` | `e7c7de92ce075551d5d15d76f4e86d3319463168e6abbc49cb7c547fcd3e5876` |
  | `src/analyzer/protocol/tcp/TCP_Endpoint.cc` | `6a935b5b13f855d792ea671bd08269d3f851991ae70488047f254cd5554bf2a7` |

- **Inputs:** HR-23 in `docs/threat-model.md`; D4-98 and D4-100; D4's reading 6852704517 on #657; `docs/phase4/D4-engine-linux-eval.md` §3 and 5.8; D6's E2 note §3 (`docs/phase4/D6-modbus-signature-conditions.md`); the project's script, `modules/telemetry/experiments/engine-linux/probe.zeek`; GT-PCAP's `dnp3-udp-temp-port` and `dnp3-udp-unsolicited` labels.

## 1. How Zeek picks the DNP3 parser by direction

1. **Which end is the originator.** A UDP connection's originator is the sender of the first datagram the sensor sees. At creation, Zeek swaps the two roles only when the source port is in `likely_server_ports` and the destination port is not, and the responder is not a broadcast address (`UDPAnalyzer::WantConnection`, `IPBasedAnalyzer::NewConn`). It never swaps them later for DNP3. Only the DNS analyzer and TCP's own code call `FlipRoles` (`DNS.cc`, `TCP_Endpoint.cc`), and no script function swaps them (`zeek.bif`, `analyzer.bif`).
2. **20000/udp is in `likely_server_ports`.** `base/protocols/dnp3/main.zeek` registers `DNP3_TCP` for `{ 20000/tcp, 20000/udp }` through `Analyzer::register_for_ports`, and that function adds every server port to `likely_server_ports` (`base/frameworks/analyzer/main.zeek`).
   - **This moves HR-23 item (3)'s `inference` on `likely_server_ports` (also D6's on #666) to `desk`, not yet checked against a run:** a flow that the relay starts from 20000 to a master's port that is not in the set is swapped at creation, and is parsed the right way round. The record that confirms the set's contents is the UDP line that `ports.zeek` printed on run 43373373987 ("likely_server_ports at …: … udp …"). Stage 2 or 3 cites that line, and the control case of section 4.1 measures the swap itself.
   - **HR-23's trigger is therefore a 5-tuple that the relay starts, where both ports or neither port is in `likely_server_ports`.** Both ends on 20000, the arrangement GT-PCAP's two failing cases use, is one such case. Two moved ports are another.
3. **What attaches `DNP3_UDP`.** The signature `dpd_dnp3_server_udp` (`dpd.sig`) does, on a UDP payload that starts `05 64`, sent by either end.
4. **Each datagram.** `DNP3_Base::ProcessData(len, data, orig)` keeps a buffer for each end, chosen by `orig`. It then checks the following, in order:
   - the magic `05 64`;
   - the link header's CRC. **`AnalyzerConfirmation` comes only after the CRC passes;**
   - the link's direction bit (DIR, `ctrl & 0x80`) against `orig`. **A mismatch raises only the weird `dnp3_unexpected_flow_direction`, and parsing goes on by `orig`.**

   The header is handed to binpac's `upflow` when `orig` is true and to its `downflow` otherwise (`DNP3_Base::ParseAppLayer`). The unit is `DNP3_PDU(is_orig)` (`dnp3-analyzer.pac`): `DNP3_Request` for the originator and `DNP3_Response` for the responder (`dnp3-protocol.pac`). `DNP3_Application_Request_Header` is 2 octets. `DNP3_Application_Response_Header` is 4 octets (control, function code, IIN).
5. **What happens to a master's message on the responder's side of a flow the relay started.** It is parsed with the response header.
   - **Shorter than 4 application octets** (a confirm, code 0; a cold or warm restart, codes 13 and 14; any request with no object header): binpac throws `out_of_bound` (measured as `DNP3_Application_Response_Header: 4 > 2` on #657). **HR-23's `inference` that any message of the master shorter than 4 octets stops the analyzer is now `desk`.**
   - **4 octets or more:** the header parses. `dnp3_application_response_header` carries the right function code with `is_orig` false, and the first two octets of the object headers are read as IIN. Every code except 129, 130 and 131 takes the response's `default` arm (`Debug_Byte`), so **no object header is parsed and no `dnp3_object_header` event is raised.** This is HR-23 item (1), now `desk`: the code is seen and the objects, a control block among them, are not.
6. **How the analyzer stops, and why it stays stopped.** `DNP3_UDP_Analyzer::DeliverPacket` calls `SetSkip(true)` in two cases: when `ProcessData` returns false (a lost magic, a bad header or chunk CRC, a missing first chunk, a length error, or the fragment-size limit), and when it catches a `binpac::Exception`, which it then rethrows. `Analyzer::NextPacket` returns at once while `skip` is set. `skip` is set false only in `Analyzer`'s constructor. So from that datagram on, the analyzer parses nothing on the connection, in either direction. The rethrown exception reaches `Analyzer::NextPacket`'s `catch`, which calls `AnalyzerViolation`, and that raises `analyzer_violation_info`.

## 2. Part (b) cannot be done from the script

- **The `DPD::ignore_violations` redef does not keep the analyzer.** D6's E2 note §3 is right about what the redef removes. `dpd.zeek`'s `analyzer_violation_info` handler returns before `disable_analyzer`, and so before `analyzer_failed`, which would delete the service from `conn.log`. But the analyzer has already called `SetSkip(true)` on itself, inside `DeliverPacket`, before any script handler runs (section 1, item 6). With the redef, a flow like `dnp3-udp-unsolicited`'s keeps `dnp3_udp` in `conn.log`'s `service` and parses nothing after the confirm.
  - **That is worse than the control.** The flow reads as named DNP3. So it is not `undecoded` (D4-90's signal for an unidentified server), and the write after the confirm is still unseen. **D4 proposes that the redef is not adopted for `DNP3_UDP`, alone or with part (a).** Stage 2 may still measure it as a configuration, to show this.
- **No other script mechanism re-attaches or re-orients the analyzer.**
  - `disable_analyzer` exists. Nothing adds an analyzer to an existing connection: `Analyzer::__enable_analyzer` enables a tag globally, and `Analyzer::__schedule_analyzer` is for a connection still to come (`analyzer.bif`).
  - No script function swaps roles (section 1, item 1). `likely_server_ports` acts only at creation, and it cannot tell apart two ends that are both on 20000.
- **One script-level route exists that D4-100 does not list: (s), the project's own decoder in Zeek's script language.** The script would read each UDP payload through `udp_contents` (`udp_content_deliver_all_orig` and `_resp`, or `udp_content_ports`; `UDP.cc`, `UDPAnalyzer::DeliverPacket`), and decode the link header, the transport octet, the application header and the object headers by DIR. That keeps the engine's binary unchanged.
  - Its costs: a DNP3 decoder that the project keeps, as with (iii); every UDP payload copied into a script event, which Zeek's own documentation of `udp_contents` warns against for volume (`events.bif` for UDP); and content read beyond today's script, which the brief's exclusions rule out unless D1 admits it.
  - It is a new mechanism, so D4 lists it in the options comment, and D1 rules whether it is admitted (D4-99).

**So part (b) needs a change outside the script, or (s).** The options and the fuzz question are proposed in comment 6862045681 on #675, for D1 to pick (D4-99). They are summarised here only:

| Option | What it is | Rough size (`inference`) |
| --- | --- | --- |
| (i) | Patch Zeek's DNP3 analyzer to pick the request or response parser by DIR rather than by `is_orig`. Events keep `is_orig` as the connection's side. Offered upstream. | Tens of lines of binpac in `dnp3-protocol.pac` and `dnp3-analyzer.pac`; the whole binary is rebuilt |
| (ii) | A Zeek plugin with an analyzer of its own: a renamed copy of the DNP3 analyzer, or a Spicy grammar, enabled in place of `DNP3_UDP`. | About 3,650 lines if copied (the analyzer's folder today); a few hundred in Spicy |
| (iii) | The project's own decoder for DNP3 over UDP, in Go, on the sensor, outside Zeek. | Several hundred lines of Go, and a new pipe from the frame stage |
| (s) | The project's own decoder in the script, from `udp_contents`. | A few hundred lines of Zeek script |

## 3. Part (a): the server taken from DIR

The rule, in the project's script. It is CH-49 (C13 0.2), for DNP3 over UDP and TCP alike:

1. **Read DIR from `dnp3_header_block(c, is_orig, len, ctrl, dest_addr, src_addr)`, as `ctrl & 0x80`.** Zeek raises this event only for a header whose magic and CRC passed, once for each application fragment, at the fragment's first frame (`DNP3_Base::ProcessData`, and the `Header_Block` refinement in `dnp3-analyzer.pac`). A link-only frame (length 5) raises no event and gives no server.
2. **The frame's sender** is the connection's originator when `is_orig` is true, and its responder otherwise.
3. **If DIR is clear, the sender is the outstation, so the server is the sender's address, port and transport.** If DIR is set, the sender is a master, so the server is the other end.
4. **The server is never taken from the flow's responder** (CH-49; the brief's exclusions).
5. **When one flow's frames name two different servers** (DIR clear from both ends, or set from both), the script names no server for the flow. It logs the conflict, and the judge reads a conflict as `fail`. That is a new judge rule, for D6 to write and pin in stage 2. D2 is asked whether any legitimate DNP3 arrangement does this on one 5-tuple, for example a device that is both master and outstation.
6. **Where it goes:**
   - `probe.zeek`'s `link` row gains the DIR bit, the one new field. The judge (`table.py`) takes the zeek-probe configuration's service rows from it, not from `conn.log`'s responder. The other configurations keep today's reading, as controls.
   - **No contract changes.** CH-49 already defines the server this way (`inference` that D1 confirms).
7. **What part (a) alone fixes, by section 1** (`desk`):
   - `dnp3-udp-temp-port`'s service row. The responses' flow carries only the relay's frames, with DIR clear from the originator, so the server is 192.0.2.20 udp/20000, and the master's port 20000 is no longer named.
   - It does not fix `dnp3-udp-unsolicited`. The relay's 130 names the right server, but the confirm stops the analyzer, so the flow row and the function rows still fail.

## 4. What stage 2 needs (D6 writes and pins it)

D6 writes the cases and the conditions, and pins them before the counted run. Labels come from how each case was built. This section states what the measurement needs, and the control's result that section 1 predicts (`desk`; the run settles it).

**4.1 Port arrangement.** **Every new relay-started case puts both ends on ports in `likely_server_ports`** (20000 and 20000, as `dnp3-udp-unsolicited` does), or on two ports that are not in it. Otherwise Zeek swaps the roles at creation, and the case does not test HR-23 (section 1, item 2). One further case with the relay on 20000 and the master on a port outside the set is wanted as a control of section 1 item 2: the control engine is expected to pass every row of it.

**4.2 The control, row by row** (the engine as on `main`, Zeek with the project's script). A row the control passes reads `unknown` for the fix, never `pass`.

| Case | Row | Control expected | Fix expected (a)+(b) | Basis |
| --- | --- | --- | --- | --- |
| `dnp3-udp-temp-port` | the service | fail (the master named as a server) | pass | measured, run 43373373987 |
| `dnp3-udp-temp-port` | the other 4 | pass | pass, `unknown` for the fix | measured |
| `dnp3-udp-unsolicited` | all 5 (flow, service, codes 1, 5, 2) | fail | pass | measured, run 43419437949 |
| `dnp3-udp-relay-write` | the flow | pass (no message shorter than 4 octets, so no violation) | pass, `unknown` | `desk`, section 1, items 4 and 5 |
| `dnp3-udp-relay-write` | the service | fail (the master named as the responder) | pass | `desk` |
| `dnp3-udp-relay-write` | the write's code | pass on the code (from `dnp3_application_response_header`) | pass, `unknown` | `desk`, section 1, item 5 |
| `dnp3-udp-relay-write` | the write's objects | fail (no object header parsed) | pass | `desk`, section 1, item 5 |
| `dnp3-udp-relay-restart` | the flow and the service | fail (the restart stops the analyzer, and `dpd.zeek` removes the service) | pass | `desk`, section 1, items 5 and 6 |
| `dnp3-udp-relay-restart` | the restart's code, and every row after it | fail | pass | `desk` |

- So the control is expected to fail `dnp3-udp-relay-write`'s service row and its objects row, and to pass its flow and code rows. D6's §3b names only the service row; the objects row fails too, by section 1 item 5.
- The write's objects should be labelled (no `?`), so that the objects column can tell the fix from the control.
- `dnp3-udp-relay-restart` should carry one request of 4 octets or more after the restart, so that the run shows that nothing after the restart is parsed.
- Stock Zeek and ICSNPP are shown beside the control, not judged for the fix.

**4.3 The regression.**

- **Every row of E-D4-03's conditions file, and every GT-PCAP DNP3 case.**
- **The UDP false-positive set, with a floor that D6 sets.** It needs near misses that start `05 64`, in these classes:
  - (1) `05 64` and nothing more, and `05 64` with 1 to 8 more octets;
  - (2) a header whose CRC fails (expected: never named, since confirmation needs the CRC);
  - (3) a header whose CRC passes, then non-DNP3 bytes, in three forms:
    - (3a) in the same datagram, failing the chunk CRC;
    - (3b) a later datagram without the magic;
    - (3c) in the same datagram, with valid chunk CRCs and an application part too short for its parser.

    By `DNP3_Base::ProcessData` and `ParseAppLayer`, (3a) and (3b) raise only a weird (`dnp3_corrupt_app_chunk_checksum`, `dnp3_header_lacks_magic`) and set `skip`. Neither raises an analyzer violation, so `dpd.zeek` never removes the service the header's CRC confirmed. (3c) throws in binpac, which raises a violation (section 1 item 6), so the control removes the service;
  - (4) real UDP protocols whose first two octets happen to be `05 64`: a DNS query with ID `0x0564`, and NTP, Syslog and SNMP payloads built that way;
  - (5) random UDP payloads forced to start `05 64`, enough of them that a 1 in 65,536 CRC match is unlikely across the set.

  So (3a) and (3b) flows are expected to stay named DNP3, a false positive, under every configuration, the control's included (`desk`). (3c) is expected to be named under the control only until its violation. Whether a changed engine keeps it named is what the class measures. The floor compares the fix with the control, and does not need zero there. For classes (1), (2), (4) and (5), whose CRC fails, the floor is zero named flows (`desk`, from section 1 item 4). Each class also has its rate of `undecoded`, against the control, because part (b) must not turn an unnamed flow into a named one.
- **The malformed DNP3-over-UDP datagrams** (D4-100 item 2), under the changed engine and the control, for any option outside the script. Expected: no crash, and no reporter or analyzer error that the control lacks. The set:
  - 1 to 3 octets;
  - a link length field of 0 to 4, which makes `ProcessData`'s target length less than its buffer;
  - a length of 5 with trailing bytes;
  - a length of 6, a transport octet and no application octet;
  - bad header and chunk CRCs;
  - a datagram longer than its frame, and two frames in one datagram;
  - a frame of 292 octets or more, against `MAX_BUFFER_SIZE` 300;
  - a fragment without FIR, one without FIN, and one beyond `DNP3::max_application_layer_fragment_size`;
  - DIR set from both ends, and DIR changing within one flow;
  - the master's 2- and 3-octet messages on each side of the flow.

**4.4 What the harness reports.** For each case and configuration, `weird.log`'s `dnp3_unexpected_flow_direction` count, and `analyzer.log`'s rows. The judge does not read them. They show which parser ran.

## 5. Limits

- Everything above is `desk`. The ports relays and masters use are `inference` until H-23 (D2). TCP is not changed by part (b). Under TCP, a relay that opens the connection is the same question, and it is not measured.
- Two things were not read: whether binpac raises `dnp3_header_block` for a message whose application header then fails, and the code binpac generates at all. A Zeek build makes that code. The run shows them.
- The tarball's signature was not checked (opening section).
