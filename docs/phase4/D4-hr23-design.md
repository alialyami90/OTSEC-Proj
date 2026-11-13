# D4: HR-23's fix, the design (P4-4-HR23, stage 1)

D4, 2026-11-13, revised 2026-11-14 for the four reviews on #675 and D1's rulings on them. Brief P4-4-HR23 (`docs/agent-handoffs.md`, "After D4-100"), under D4-100 items 1 to 3. This PR is documents only: nothing here is built or run.

- **Evidence class: `desk`.** Every statement below about Zeek's code comes from reading its source, and stage 3's counted run measures it. The earlier results this note cites (section 1 item 5, and section 4.2's Basis column) were measured, `CI-Linux`, `simulated`, and each is named with its run. Every statement about IEEE 1815 is `inference`, because the project holds no text of it (D2 on #675).
- **What was read.** The release tarball `https://github.com/zeek/zeek/releases/download/v9.0.1/zeek-9.0.1.tar.gz`, fetched over HTTPS on 2026-11-13, SHA-256 `fbee2eb5ee6ebd64ef0db830fbb9fa1d702d58807643c719e8338a59329197f2`. It was unpacked in D4's scratch folder, outside the repository. Its signature file `zeek-9.0.1.tar.gz.asc` has SHA-256 `269e266a0b473b4621448034b98a9f8aafe39f0e53f026ad03bff5312e5bffce`. The tarball matches the pin in `docs/phase4/D4-engine-linux-eval.md` §3 (tag `v9.0.1`): its `DNP3.cc`, `dnp3-protocol.pac`, `dnp3-objects.pac`, `events.bif`, `base/protocols/dnp3/main.zeek` and `dpd.sig` have the SHA-256s that §3 records.
- **The signature was checked by D7** (comment 6864785127 on #675, "What I checked", `desk`), not by D4. The check needs Zeek's public key, not a signing key. GnuPG 2.4.9's `--verify`, in a keyring that held only that key, gave "Good signature from The Zeek Team". The primary key is `962F D218 7ED5 A1DD 82FC 478A 33F1 5EAE F8CB 8019`, and the signing subkey is `E969 0B2B 7D8A C1A1 9F92 1C4A C68B 494D F56A CC7E`. It has two limits:
  - **The key comes from one channel,** `keys.openpgp.org`. So the binding of that key to the Zeek project is `inference` until a second check agrees (section 6, R-3).
  - **The signature's digest is SHA-1.** The SHA-256 pin of the tarball is the integrity anchor, and the signature is provenance checked once, at intake.
- **Files cited**, with their SHA-256 in the tarball. Code is cited by function, never by line.

  | File | SHA-256 |
  | --- | --- |
  | `src/analyzer/protocol/dnp3/DNP3.cc` | `8a6fb005cc7b52cbd7a3846a733a3be017ee248af3966d12eae366c1c28c7e6e` |
  | `src/analyzer/protocol/dnp3/DNP3.h` | `f459be85ee1389de9e05de33665925f5bafa2a330f1d84b82ec04cfe9ec223c9` |
  | `src/analyzer/protocol/dnp3/dnp3.pac` | `f33361279aa4a536be31b22382447f327661b08699bdafcb8160a100ea97aa5b` |
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
  | `scripts/base/frameworks/analyzer/logging.zeek` | `28a74e2a2d12c6f96cc6cd149969fcebc8543cc0da0b58b27a68fb029cad1df3` |
  | `scripts/base/protocols/dnp3/main.zeek` | `37f51eab720db2d744ef229c0a10b0fbcd90a131b859f5500f4665a51258d2cd` |
  | `scripts/base/protocols/dnp3/dpd.sig` | `b2067b53fca4dff949c837928e94af647318cc4937d8a37fac3be5d62488a402` |
  | `src/fuzzers/CMakeLists.txt` | `eaefb55fb3c8cb35cad7f2c9aaa368a9c8fbbc75d11d4b6eff2bc00d9113ecb7` |
  | `src/fuzzers/generic-analyzer-fuzzer.cc` | `ac1bd357d007e41e1f4562139f0956c66d15fad58d72527a7fd916e45fbca0f8` |
  | `src/fuzzers/FuzzBuffer.cc` | `49d59eb9abfbd409da32fe3847fbb57aeffa21ef943d6641dbac87b2c104e2b5` |
  | `src/analyzer/protocol/dnp3/dnp3-objects.pac` | `0ba3df0cab28933f6729d6cab06d9b5c0d88bb9554c9b4a89caeb5b6b24dc493` |
  | `src/analyzer/protocol/dnp3/events.bif` (DNP3's events) | `c3c3107870fb0347e0aaa7f3e004d35fb369b9e7908e88862889b970e2de7100` |
  | `src/packet_analysis/protocol/udp/events.bif` (UDP's events) | `d9d7f5a2fec8a32a789add0bcee07957fdabe51f35c464dec0e632fc10ef52c2` |
  | `src/analyzer/protocol/dns/DNS.cc` | `e7c7de92ce075551d5d15d76f4e86d3319463168e6abbc49cb7c547fcd3e5876` |
  | `src/analyzer/protocol/tcp/TCP_Endpoint.cc` | `6a935b5b13f855d792ea671bd08269d3f851991ae70488047f254cd5554bf2a7` |

- **Inputs:** HR-23 in `docs/threat-model.md`; D4-98 and D4-100; D4's reading 6852704517 on #657; `docs/phase4/D4-engine-linux-eval.md` §3 and 5.8; D6's E2 note §3 (`docs/phase4/D6-modbus-signature-conditions.md`); the project's script, `modules/telemetry/experiments/engine-linux/probe.zeek`, and its judge, `table.py`; GT-PCAP's `dnp3-udp-temp-port` and `dnp3-udp-unsolicited` labels.
- **The reviews on #675:** D7 6864785127, D2 6864828995, D3 6864835839 and D6 6864977091. **D1's rulings** are 6864990229, and they replace D1's provisional points 6862064732. **D4's confirmation of ruling 1** is 6865038018. Section 7 maps each finding to the place where it is answered.

## 1. How Zeek picks the DNP3 parser by direction

1. **Which end is the originator.** A UDP connection's originator is the sender of the first datagram the sensor sees. At creation, Zeek swaps the two roles only when the source port is in `likely_server_ports`, the destination port is not, and the responder is not a broadcast address (`UDPAnalyzer::WantConnection`, `IPBasedAnalyzer::NewConn`). It never swaps them later for DNP3. Only the DNS analyzer and TCP's own code call `FlipRoles` (`DNS.cc`, `TCP_Endpoint.cc`), and no script function swaps roles (`zeek.bif`, `analyzer.bif`).
2. **20000/udp is in `likely_server_ports`.** `base/protocols/dnp3/main.zeek` registers `DNP3_TCP` for `{ 20000/tcp, 20000/udp }` through `Analyzer::register_for_ports`, and that function adds every server port to `likely_server_ports` (`base/frameworks/analyzer/main.zeek`).
   - **This moves HR-23 item (3)'s `inference` about `likely_server_ports` (also D6's, on #666) to `desk`. It is not yet checked against a run.** A flow that the relay starts from 20000 to a master's port outside the set is swapped at creation, and so it is parsed the right way round. The record of the set's contents is the UDP line that `ports.zeek` printed on run 43373373987 ("likely_server_ports at …: … udp …"). Stage 2 or 3 cites that line, and section 4.1's swap control measures the swap itself.
   - **HR-23's trigger is therefore a 5-tuple that the relay starts, where both ports, or neither, are in `likely_server_ports`.** One such case has both ends on 20000, the arrangement GT-PCAP's two failing cases use. Another has two moved ports.
3. **What attaches `DNP3_UDP`.** The signature `dpd_dnp3_server_udp` (`dpd.sig`) does, on a UDP payload that starts `05 64`, from either end.
4. **What happens to each datagram.** `DNP3_Base::ProcessData(len, data, orig)` keeps one buffer for each end, chosen by `orig`. That buffer survives across datagrams (`AddToBuffer` keeps `buffer_len`, D2 on #675). It then checks these, in order:
   - the magic `05 64`;
   - the link header's CRC, once the 10-octet header is complete. With 10 octets or fewer, nothing is checked. **`AnalyzerConfirmation` comes only after the CRC passes;**
   - the link's direction bit (DIR, `ctrl & 0x80`) against `orig`. **A mismatch raises only the weird `dnp3_unexpected_flow_direction`, and parsing goes on by `orig`.**

   Each chunk's CRC is checked in `DNP3_Base::ParseAppLayer`. The reassembled fragment goes to binpac's `upflow` when `orig` is true, and to its `downflow` otherwise, one flow unit for each FIN (`FlowEOF`). The unit is `DNP3_PDU(is_orig)` (`dnp3-analyzer.pac`): `DNP3_Request` for the originator and `DNP3_Response` for the responder (`dnp3-protocol.pac`). `DNP3_Application_Request_Header` is 2 octets. `DNP3_Application_Response_Header` is 4 octets (control, function code, IIN). The function code is the second octet of both.
   - **DNP3 over TCP uses the same parser.** `DNP3_TCP_Analyzer` and `DNP3_UDP_Analyzer` both derive from `DNP3_Base`, whose constructor creates the one binpac interpreter, `DNP3_Conn` (D3's B1 and D6's B2 on #675). `DNP3_TCP_Analyzer::DeliverStream` calls `SetSkip(true)` in the same two cases as UDP (item 6).
5. **What happens to a master's message on the responder's side of a flow the relay started.** It is parsed with the response header.
   - **Shorter than 4 application octets** (a confirm, code 0; a cold or warm restart, codes 13 and 14; any request with no object header): binpac throws `out_of_bound`, measured as `DNP3_Application_Response_Header: 4 > 2` on #657. **This moves HR-23's `inference`, that any message of the master shorter than 4 octets stops the analyzer, to `desk`.**
   - **4 octets or more:** the header parses. `dnp3_application_response_header` carries the right function code, with `is_orig` false, and the first two octets of the object headers are read as IIN. Every code except 129, 130 and 131 takes the response's `default` arm (`Debug_Byte`). So **no object header is parsed and no `dnp3_object_header` event is raised.** This moves HR-23 item (1) to `desk`: the code is seen, and the objects, a control block among them, are not.
6. **How the analyzer stops, and why it stays stopped.** `DNP3_UDP_Analyzer::DeliverPacket` calls `SetSkip(true)` in two cases:
   - when `ProcessData` returns false: a lost magic, a bad header or chunk CRC, a missing first chunk, a length error, or the fragment-size limit;
   - when it catches a `binpac::Exception`, which it then rethrows.

   `Analyzer::NextPacket` returns at once while `skip` is set. `skip` is set false only in `Analyzer`'s constructor. So from that datagram on, the analyzer parses nothing on the connection, in either direction. The rethrown exception reaches `Analyzer::NextPacket`'s `catch`, which calls `AnalyzerViolation`, and that raises `analyzer_violation_info`.
   - **`dpd.zeek` removes the service only below 10 KiB.** It ignores a violation once the connection has carried more than `DPD::ignore_violations_after` (`10 * 1024`) octets, counted as `c$orig$size + c$resp$size` (D6's N1 on #675). Above that size, the control already leaves the flow named `dnp3_udp` while parsing nothing. Every case in section 4 is far below that size (`dnp3-udp-unsolicited` is 542 octets), and stage 2 states each case's octet count at its violation. D3 adds this bound to HR-23's row (D1's ruling 9).

## 2. Part (b): what the script cannot do, and the change D1 chose

### 2.1 Part (b) cannot be done from the script

- **The `DPD::ignore_violations` redef does not keep the analyzer.** D6's E2 note §3 is right about what the redef removes. `dpd.zeek`'s `analyzer_violation_info` handler returns before `disable_analyzer`, and so before `analyzer_failed`, which would delete the service from `conn.log`. But the analyzer has already called `SetSkip(true)` on itself, inside `DeliverPacket`, before any script handler runs (section 1, item 6). With the redef, a flow like `dnp3-udp-unsolicited`'s keeps `dnp3_udp` in `conn.log`'s `service`, and parses nothing after the confirm.
  - **That is worse than the control.** The flow reads as named DNP3, so it is not `undecoded` (D4-90's signal for an unidentified server), and the write after the confirm is still unseen. **The redef is not adopted for `DNP3_UDP`, alone or with part (a)** (D1 6862064732, point 1, which ruling 1 keeps). Stage 2 may still measure it as a configuration, to show this.
- **No other script mechanism re-attaches the analyzer or re-orients it.**
  - `disable_analyzer` exists. Nothing adds an analyzer to an existing connection: `Analyzer::__enable_analyzer` enables a tag globally, and `Analyzer::__schedule_analyzer` is for a connection still to come (`analyzer.bif`).
  - No script function swaps roles (section 1, item 1). `likely_server_ports` acts only at creation, and it cannot tell apart two ends that are both on 20000.
- **One script-level route exists that D4-100 does not list: (s), the project's own decoder written in Zeek's script language,** reading each UDP payload through `udp_contents` (`UDP.cc`, `UDPAnalyzer::DeliverPacket`). **It is not taken** (D1 6862064732, point 1; D2's and D3's agreement on #675). It would copy every UDP payload on the segment into the interpreter, including SNMP communities and Syslog bodies, and reach them from any script log write (D3). It would read content beyond the script's. And it would re-implement link CRCs, transport reassembly and object-header parsing in a language whose out-of-range errors silently skip a message (D2).

### 2.2 The options, and the choice

The options were proposed in comment 6862045681 and agreed in comments (D4-99). They are summarised here only.

| Option | What it is | Rough size (`inference`) | Ruled |
| --- | --- | --- | --- |
| (i) | Patch Zeek 9.0.1's DNP3 analyzer to pick the request or response parser by the function code instead of by `is_orig` (section 2.3). | Tens of lines of binpac in `dnp3-protocol.pac` and `dnp3-analyzer.pac`; the whole binary is rebuilt | **Chosen** (ruling 1) |
| (ii) | A Zeek plugin with an analyzer of its own: a renamed copy of the DNP3 analyzer, or a Spicy grammar, enabled in place of `DNP3_UDP`. | About 3,650 lines if copied (the analyzer's folder today); a few hundred in Spicy | Fallback, if (i)'s build cannot be pinned |
| (iii) | The project's own decoder for DNP3 over UDP, in Go, on the sensor, outside Zeek. | Several hundred lines of Go, and a new pipe from the frame stage | Fallback, after (ii) |
| (s) | The project's own decoder in the script, from `udp_contents`. | A few hundred lines of Zeek script | Not taken (section 2.1) |

- **The upstream offer waits on the owner** (D7's N1; ruling 8). `LICENSE.md` grants no licence, so offering the patch to Zeek under BSD-3-Clause needs the owner's written grant for that patch, recorded in the decision log. D1 brings this to the owner. Until then, nothing is offered upstream. Without the grant, the project may still ship the patched binary, because BSD-3-Clause allows a modified build under the project's own terms.
- **What (i) adds to the parse surface** (D3's N4). It adds no object parser. But the restructured top-level `DNP3_PDU` is new generated code on the path: it reads the header before the dispatch, and its `&length` moves. The analyzer also stays on flows that it drops today, such as the whole of a relay-started flow and class (3c) of section 4.3, so the existing parsers see more hostile bytes. Section 4.6's fuzz run is what covers that.

### 2.3 Option (i): the parser is picked by the function code (ruling 1)

- **The rule.** Each application fragment is parsed by its function code: codes 129, 130 and 131 by `DNP3_Response`, and every other code by `DNP3_Request`. It is not picked by DIR, because a sender sets DIR frame by frame, under a CRC it computes itself (D3's B2; D2's note on Q3).
- **What stays the same.**
  - The buffers stay one per end: `upflow` and `downflow`, chosen by `orig`.
  - Events keep `is_orig` as the connection's side, so no record or field changes.
  - The weird `dnp3_unexpected_flow_direction` is unchanged.
- **Why it covers a forged DIR** (D4 6865038018):
  - A master's write with DIR clear goes to the request parser, on either side of the flow, so its objects are parsed. The control does that only on a flow the master started.
  - A sender that wants its frame parsed as a response must give it code 129 to 131, and an outstation does not execute those as a write.
  - A forged 129 or 130 toward a master is parsed as a response, objects included.
  - The disagreement stays visible. The `link` row carries DIR (section 3), and the `fc` row carries the code. So a frame whose DIR disagrees with its code's class can be counted from the probe log.
- **Whether an outstation acts on a request whose DIR is clear** is D3's question to D2 (ruling 1). For SEL it is `unknown`. The rule does not depend on the answer.
- **The cases it covers:**
  - Conforming traffic, on TCP and on a UDP flow the master starts: the same parser as the control.
  - A flow the relay starts: the confirm (0) and the restarts (13, 14) reach the request parser's `empty` arms, and 129 and 130 reach the response parser. This rests on ruling 3's control case (section 4.1).
  - Multi-frame fragments: binpac gets one reassembled fragment for each FIN, and every application fragment starts with its own header.
  - The reserved codes, 34 to 128 and 132 to 255: the request parser's `default` arm.
  - SAv5: codes 32 and 33 take the request parser, and 131 the response parser, as Zeek's arms already expect.
- **Two cases with no usable code:**
  - A fragment of 0 or 1 application octets has no code. It throws, as both parsers do today.
  - A fragment of 2 or 3 octets with code 129 to 131 throws in the response parser, from either side.

  Both are in the malformed set (section 4.3).
- **TCP changes too** (ruling 4). The dispatch is in the shared grammar (section 1, item 4). On TCP, it changes the parser only where the code's class disagrees with the side: a response code from the originator, or a request code from the responder. A connection that an outstation opens is one such case. GT-PCAP's TCP cases all have the master open the connection, so stage 2 adds TCP cases that reach the changed path (section 4.3).

## 3. Part (a): the server taken from DIR

The rule, in the project's script. It is CH-49 (C13 0.2), and it applies to DNP3 over UDP and over TCP. **No contract changes** (ruling 2).

1. **DIR is read from `dnp3_header_block(c, is_orig, len, ctrl, dest_addr, src_addr)`, as `ctrl & 0x80`.** Zeek raises this event only for a header whose magic and CRC passed, at the first frame of each application fragment (`DNP3_Base::ProcessData`, and the `Header_Block` refinement in `dnp3-analyzer.pac`). Every frame of one fragment comes from one sender, so that is enough (D2's Q1).
2. **The frame's sender** is the connection's originator when `is_orig` is true, and its responder otherwise.
3. **Each frame names one server** (D2's B1, ruling 2):
   - DIR clear: the sender is an outstation, so the server is the sender's address, port and transport;
   - DIR set: the sender is a master, so the server is the other end.
   - **The exception is a DIR-set frame sent to a broadcast or multicast address: it names no server** (D2's note on Q1). Otherwise a master's broadcast time sync or freeze on udp/20000 would name the broadcast address as a DNP3 server. Zeek keeps such a responder unswapped (section 1, item 1).
4. **A flow's servers are the union of the servers its frames name: 0, 1 or 2.** When both ends are named, the script logs that as a field of its own. It never suppresses a server.
   - **Both ends can be legitimate** (D2's Q2, `inference` from IEEE 1815, which the project does not hold). A dual-role device can be a master on one association and an outstation on another, on the same channel. Two concentrators that poll each other over UDP, with both ends on 20000, would do that. Stage 2 may label such a case on that reading, as `inference`.
   - **The judge stays strict.** Each case's labels give its set of servers, so a missing or extra server fails the Service row. Each case in section 4.2 has one server, so none of its labels changes.
   - **An attacker can cause the both-ends outcome** with one datagram of the opposite DIR and a valid CRC, from either end. A CRC is not authentication (D3's N3, D6's N5). The union rule then names a second, false server; it does not hide the real one. That this outcome can be caused is an open item that D1 records, and in production it must fail closed (ruling 2; section 6, R-1). The case `dnp3-udp-dir-spoof` measures it (section 4.2).
5. **The server is never taken from the flow's responder** (CH-49; the brief's exclusions).
6. **No server is named from a link-only frame.** A frame of length 5 (ACK, NACK, link status, reset, test) raises no `dnp3_header_block`. So a flow that carries only link-status keep-alives names no server (D2's Q1, a limit).
7. **Where it goes:**
   - `probe.zeek`'s `link` row gains the DIR bit, the one new field. It reads only the `ctrl` octet, which the engine already passes to the script, so no session content is read beyond the script's.
   - **The field stays a probe and judge field.** It is not a C13 field, and it is not on SL-22's allow-list (D3's N2).
   - The judge (`table.py`) takes the DNP3 Service rows of both configurations in `PROBED`, `zeek-probe` and `zeek-modbus-sig`, from the `link` rows (D6's N6). Both load `probe.zeek`. The other configurations keep today's reading from `conn.log`'s responder, as controls.
8. **What part (a) alone fixes, by section 1** (`desk`). These are configuration C1's predictions in section 4.2:
   - `dnp3-udp-temp-port`'s Service row. The responses' flow carries only the relay's frames, with DIR clear from the originator. So the server is 192.0.2.20 udp/20000, and the master's port 20000 is no longer named.
   - Not `dnp3-udp-unsolicited`. The relay's 130 parses whole and names the right server, but the confirm then stops the analyzer, so the flow row and the function rows still fail.

## 4. What stage 2 needs (D6 writes and pins it)

D6 writes the cases and the conditions, and pins them before the counted run. Labels come from how each case was built, never from an engine. **A case with a forged DIR takes its labels from the builder's role, not from tshark's `dnp3.ctl.dir`,** since that bit is the one being forged (D2's Q4). This section states what the measurement needs, and the results that section 1 predicts (`desk`; the run settles them).

### 4.1 The configurations, the port arrangement and the control cases

**The configurations** (D6's B1, D7's N3, ruling 5):

| Id | Engine | Script |
| --- | --- | --- |
| C0 | Zeek as on `main`: the `zeek/zeek` image (D4-100's control) | Today's script |
| C1 | The same binary as C0 | The script with part (a) |
| C1p | The project's build from the same inputs as C2, without the patch | The script with part (a) |
| C2 | The project's build with the patch (option (i)) | The script with part (a) |

- Part (a)'s effect is judged as C1 against C0.
- Part (b)'s effect is judged as C2 against C1p, which differ only by the patch.
- C1p against C1 shows what the project's build changes apart from the patch: the base system, the compiler, the libraries, and the configure line (Spicy on or off changes which analyzers exist). So a difference in the public-capture rows can be put down to the right cause.
- The fuzz run's unpatched build (section 4.6) is C1p's source and configure line, built with sanitizers.

**What "named" means on an unlabelled flow** (D6's B1):
- Under C0, a flow is named DNP3 when `conn.log`'s `service` holds `dnp3_udp` or `dnp3_tcp`, which is today's reading.
- Under C1, C1p and C2, a flow is named DNP3 when the `link` rows name at least one server on it.
- The harness reports both readings for every flow under every configuration. They are expected to differ in two places:
  - (3b) with a link-only frame: it is confirmed, so `conn.log` names it, but it has no `link` row;
  - (3c): a `link` row may name a server before the violation removes the service from `conn.log`.
- **Whether a `link` row is written for a fragment whose application header then fails** depends on when binpac evaluates the `Header_Block` refinement, in code that was not read (section 5). So (3c)'s Service rows read `unknown` under C1, C1p and C2 until the run.
- On `dnp3-udp-relay-restart` the question does not arise, because the relay's first message parses whole before the restart (section 4.2).

**The port arrangement.** **Every new relay-started UDP case puts both ends on ports in `likely_server_ports`** (20000 and 20000, as `dnp3-udp-unsolicited` does), or puts both on ports outside the set. Otherwise Zeek swaps the roles at creation, and the case does not test HR-23 (section 1, item 2).
- **A swap control** puts the relay on 20000 and the master on a port outside the set. The control engine is expected to pass every row of it, and that measures section 1 item 2. D1 gives it its id.

**`dnp3-udp-master-short`, run under C0 before any build** (D2's B2, D6's §4.1, ruling 3). Option (i)'s fix of the confirm assumes that Zeek's request parser accepts a 2-octet application part. By the grammar it should, since the request header is `&length = 2` and the arms for CONFIRM, COLD_RESTART and RECORD_CURRENT_TIME are `empty`. But the record-level `&length` of `DNP3_Request` and `DNP3_Response` is in generated code that was not read, and no GT-PCAP capture holds a 2-octet master message on a flow the master starts.
- **The case:** one UDP flow that the master starts. It carries a confirm (code 0), a cold restart (13) and a record current time (24, the LAN time sync's 2-octet request). Each is followed by a request of 4 octets or more.
- **Expected under C0:** every row passes.
- **If any row fails,** (i)'s premise does not hold, and the choice comes back to the comments before stage 3.

### 4.2 The cases, row by row

A row that C0 passes reads `unknown` for the fix, never `pass`. C1's column holds section 3 item 8's predictions.

| Case | Row | C0 | C1 (part (a)) | C2 ((a)+(b)) | Basis |
| --- | --- | --- | --- | --- | --- |
| `dnp3-udp-temp-port` | the service | fail (the master named as a server) | pass | pass | measured under C0, run 43373373987 |
| `dnp3-udp-temp-port` | the other 4 | pass | pass | pass, `unknown` for the fix | measured under C0 |
| `dnp3-udp-unsolicited` | the service | fail | pass (the relay's 130 names it) | pass | measured under C0, run 43419437949; C1 and C2 `desk` |
| `dnp3-udp-unsolicited` | the flow, and codes 1, 5, 2 | fail | fail (the confirm stops the analyzer) | pass | as above |
| `dnp3-udp-relay-write` | the flow | pass (no message shorter than 4 octets, so no violation) | pass | pass, `unknown` | `desk`, section 1, items 4 and 5 |
| `dnp3-udp-relay-write` | the service | fail (the master named as the responder) | pass | pass | `desk` |
| `dnp3-udp-relay-write` | the write's code | pass (from `dnp3_application_response_header`) | pass | pass, `unknown` | `desk`, section 1, item 5 |
| `dnp3-udp-relay-write` | the write's objects | fail (no object header parsed) | fail | pass | `desk`, section 1, item 5 |
| `dnp3-udp-relay-restart` | the service | fail | pass (the relay's first message names it) | pass | `desk`, section 3 |
| `dnp3-udp-relay-restart` | the flow | fail (the restart stops the analyzer, and `dpd.zeek` removes the service) | fail | pass | `desk`, section 1, items 5 and 6 |
| `dnp3-udp-relay-restart` | the restart's code, and every row after it | fail | fail | pass | `desk` |
| `dnp3-udp-master-short` | every row | pass | pass | pass, `unknown` | `desk`; it tests (i)'s premise (section 4.1) |
| `dnp3-udp-dir-spoof` | the service | pass (`conn.log`'s responder is the outstation) | fail (server conflict: the false server is named too) | fail (server conflict) | `desk`, section 3 item 4 |
| `dnp3-udp-dir-spoof` | the other rows | pass | pass | pass, `unknown` | `desk` |
| the swap control | every row | pass | pass | pass, `unknown` | `desk`, section 1 item 2 |

C1p is expected to equal C1 on every row. A row where it does not shows the build, not the patch (section 4.1).

- **How `dnp3-udp-relay-write` is built** (D2's Q4; D6's N4). Starting the flow with a 130 is not a conforming session: its CON bit is set, so the master must confirm it, and the 2-octet confirm stops the analyzer first. So the case is built as a sensor joining mid-session, which is HR-23 item (3):
  - the first datagram the sensor sees is the relay's solicited 129 with CON clear, answering a request the sensor missed;
  - the master's write and the relay's 129 follow, on the same 5-tuple;
  - every master message before the write is 4 octets or more, and the relay's first message needs no confirm.
- **How `dnp3-udp-relay-restart` is built.** It starts the same way: the relay's first datagram needs no confirm, and every master message before the restart is 4 octets or more. After the cold restart (13), the master sends a request of 4 octets or more, so the run shows that nothing after the restart is parsed. The natural one is the master's write of g80v1 index 7, which clears IIN1.7 DEVICE_RESTART. Its code is 2, so it also tests whether `unauthorized-write` sees a write after the restart (D2's Q4).
- **How `dnp3-udp-dir-spoof` is built** (D6's N5, ruling 3). It is an otherwise valid UDP flow that the master starts, carrying one frame from the master's address with DIR clear and a valid CRC.
  - The labels give one server, the outstation, from how the case was built.
  - The frame should be a write (code 5) with a control block, so that its objects row also tests the code rule under C2: parsed as a request, whatever DIR says.
  - The case shows what the attacker-caused outcome costs (section 3 item 4, R-1).
- The write's objects in both relay cases are labelled (no `?`), so that the objects column can tell the fix from the control.
- Stock Zeek and ICSNPP are shown beside C0, and are not judged for the fix.

### 4.3 The regression

**The reruns of D4-100 item 2, on C2 by hash, with C0 as the control** (D6's B2; one source, D4-97). The run names C2 by the tarball's SHA-256, the patch's SHA-256 and the built image's digest (section 4.5). It reruns:
- every row of E-D4-03's conditions file;
- every GT-PCAP DNP3 case, over UDP and over TCP;
- every counted measurement that names the engine: the PRP pairs, the public captures, E2's corpus rows, and HR-24's stage 3 once it is pinned. Where one of these cannot change, the note that pins stage 2 says why;
- the harness check that the engine emits no record or field that the script does not emit now. That check compares C2 with C1 and C1p, which run the same script. Against C0, part (a)'s DIR field would be new (D6's B2, D3's N2).

**TCP cases that reach the changed path** (ruling 4). They are TCP connections where the code's class disagrees with the side:
- a connection the outstation opens, carrying its 129 or 130 from the originator, and the master's confirm, cold restart and write from the responder;
- frames whose DIR does not match their side: DIR clear from the originator and DIR set from the responder, with 2, 3 and more application octets.

D1 gives these cases their ids. Under C0 they are expected to fail as the UDP relay cases do. Under C2 they are expected to pass.

**The UDP false-positive set.** Each item is on its own 5-tuple, in a flow of one datagram unless its class says otherwise. The per-end buffer survives across datagrams, so a later datagram could complete an earlier one's header (D2's Q4). The classes:
- (1) `05 64` and nothing more, and `05 64` with 1 to 8 more octets. The header is never complete, so no CRC is ever checked (D2, D6's N2);
- (2) a complete header whose CRC fails. Expected: never named, since confirmation needs the CRC. It raises `AnalyzerViolation("broken_checksum")`;
- (3) a header whose CRC passes, then non-DNP3 bytes, in three forms:
  - (3a) in the same datagram, failing the chunk CRC;
  - (3b) a later datagram on the same flow without the magic. The first datagram must be a whole valid frame, header and chunks. Otherwise the next datagram's bytes are taken as chunk data and never checked for the magic (D2);
  - (3c) in the same datagram, with valid chunk CRCs and an application part too short for its parser.

  By `DNP3_Base::ProcessData` and `ParseAppLayer`, (3a) and (3b) raise only a weird (`dnp3_corrupt_app_chunk_checksum`, `dnp3_header_lacks_magic`) and set `skip`. Neither raises an analyzer violation, so `dpd.zeek` never removes the service that the header's CRC confirmed. (3c) throws in binpac, which raises a violation (section 1, item 6), so C0 removes the service;
- (4) real UDP protocols whose first two octets are free and can be `05 64` (D6's N2): a DNS query with ID `0x0564`, NetBIOS name service and LLMNR with the same ID, and a RADIUS Accounting-Response (code 5, identifier `0x64`);
- (5) random UDP payloads forced to start `05 64`. This class also holds NTP, Syslog and SNMP payloads forced to start that way, since none of those protocols can start `05 64` (D6's N2). **The generator computes every header CRC, and draws again whenever one passes** (D6's N3). For a header split across datagrams from one end, it computes the CRC over the octets that `ProcessData` would assemble. The labels then say that each CRC fails, from how the case was built.

**The bounds** (D6's N2):
- For classes (1), (2), (4) and (5), the bound is no named flow, under every configuration (`desk`, from section 1 item 4).
- (3a) and (3b) are expected to stay named DNP3, a false positive, under every configuration, C0 included (`desk`). (3c) is expected to be named under C0 only until its violation. What C2 does with it is what the class measures, judged against C1p, with its Service rows `unknown` until the run (section 4.1).
- Each class also has its rate of `undecoded`, against the control, because part (b) must not turn an unnamed flow into a named one.
- The set's smallest size, its floor, is D6's to set (E2's `fp-floor`).

**The malformed DNP3 inputs** (D4-100 item 2), run under C2, C1p and C0.
- **Each input is on its own 5-tuple** (D6's B3, ruling 6). Otherwise C0 stops at the first failure on a flow, (i) carries on, and the later inputs raise errors that C0 never reached.
- **How each input is judged** (ruling 6; D1 records this reading of D4-100 item 2 in its next decision entry):
  - **Crashes, sanitizer reports and reporter errors** (`reporter->AnalyzerError` in `AddToBuffer` and `ParseAppLayer`) are judged by "none that the control lacks".
  - **Analyzer violations** are judged against an expected result pinned for each input and each configuration by stage 2, not against the control. Under (i), some inputs fail by design where C0 does not, and that is (i)'s correct behaviour.
- **The set:**
  - 1 to 3 octets;
  - a link length field of 0 to 4, which makes `ProcessData`'s target length less than its buffer;
  - a length of 5 with trailing bytes;
  - a length of 6: a transport octet and no application octet;
  - 1 application octet (a control octet and no function code), from each side (section 2.3);
  - a code of 129 to 131 with 2 or 3 application octets, from each side (section 2.3);
  - bad header and chunk CRCs;
  - a datagram longer than its frame, and two frames in one datagram;
  - a frame of 292 octets or more, against `MAX_BUFFER_SIZE` 300;
  - a fragment without FIR, one without FIN, and one beyond `DNP3::max_application_layer_fragment_size`;
  - DIR set from both ends, and DIR changing within one flow;
  - **DIR disagreeing with the function code's class** (ruling 3; D2's Q3; D3's B2). One is a master's write (code 5 with a control block) with DIR clear, on a UDP flow the master starts and on a TCP connection the master opens. C0 is expected to parse its objects. C2 is expected to parse them too, and a selector keyed by DIR would show here as a regression;
  - the master's 2- and 3-octet messages on each side of the flow;
  - the TCP inputs of "TCP cases that reach the changed path" above.

### 4.4 What the harness reports

For each case and configuration, the harness reports:
- `weird.log`'s count of `dnp3_unexpected_flow_direction`;
- `analyzer.log`'s rows, read for `failure_reason` and the analyzer's name only. **It does not read `failure_data`,** which in Zeek 9.0.1 carries up to `Analyzer::Logging::failure_data_max_size` (40) octets of the payload that caused the violation. That is session content beyond the script's (D3's N1, `base/frameworks/analyzer/logging.zeek`);
- the count of frames whose DIR disagrees with their code's class (section 2.3), from the probe log;
- the both-ends field (section 3 item 4);
- both "named" readings (section 4.1);
- the SHA-256 of the `zeek` binary inside the image (section 4.5).

The judge does not read these. They show which parser ran.

### 4.5 The build and the pin of option (i)

These keep the engine that is measured the engine that ships (D4-100 item 2; O-7; AP-31; D7's answer 1; D3's N4; ruling 8).

- **Every input is pinned:**
  - the tarball by SHA-256, with its `.asc` checked by `gpgv --keyring` against a committed public key, whose SHA-256 and two fingerprints `docs/release.md` records. The build never reads the runner's default keyring and never fetches a key from a keyserver. The key's fingerprint is confirmed from a source other than the release page before a sensor ships (section 6, R-3). D1 assigns the key file's path;
  - the patch by SHA-256;
  - the base image by digest, not by tag;
  - the configure line, written down. Zeek 9.0.1's `configure` can leave the fetchers out of the build: `--disable-zkg`, `--disable-zeekctl`, `--disable-javascript`, `--disable-python`, `--disable-cluster-backend-zeromq` and `--disable-af-packet` (D7). That serves AP-31 (1);
  - the versions of the build and runtime packages, the compiler, libpcap and OpenSSL among them, listed for D7.
- **The artifact the counted run measures is the image by digest. It is the image that ships, never a rebuild.** A rebuild is a new engine for this purpose, and needs its own run or a shown reproducible build (D7's N2).
- **The measured image's digest is kept beyond GitHub's artifact retention** (ruling 8), so that the claim can be checked later. D1 says where it is kept.
- **The counted run's log records the SHA-256 of the `zeek` binary inside the image.** That ties the program hash in `config_digest` (SL-19, CH-32) to the measured binary.
- **The release carries the image itself,** and the sensor host pulls nothing from a registry (AP-31 (1)).
- **The proposed paths, for D1 to assign** (the brief: "a change outside the script names its path in stage 1"):
  - the patch: `modules/telemetry/experiments/engine-linux/zeek-patch/`, with the image's build file beside it;
  - the fuzz job: a new dispatch-only workflow, `.github/workflows/d4-zeek-dnp3-fuzz.yml`;
  - the public key file.
- D7 writes the inventory and release-record entries when a build exists (D7's answer 2). Nothing is owed in this PR.

### 4.6 The sanitizer fuzz run

The fuzz run is agreed for (i) (D1 6862064732, point 2). D4 adds the job, and D6 runs it and judges it. Its terms are ruling 7, from D3's B3 and D6's point 2.

- **The targets.** Zeek's generic fuzzer (`generic-analyzer-fuzzer.cc`) has a `dnp3_tcp` target and no `dnp3_udp` target. `dnp3_udp` is added with one line in `src/fuzzers/CMakeLists.txt` (`add_generic_analyzer_fuzz_target`). Each target runs on the patched build (C2's source) and the unpatched build (C1p's source), built with ASan and UBSan.
- **How the fuzzer drives the analyzer.** It instantiates the analyzer directly, on one fixed synthetic connection, with no signature, no DPD and no role swap. Each chunk's `is_orig` comes from its `FuzzBuffer` flag byte, so both sides can be driven.
- **The CRC fix-up.** `DNP3_Base::CheckCRC` checks every header and every chunk in C++ before binpac sees a byte, and `DNP3.cc` has no fuzzing bypass. So a plain mutator would almost never reach the patched dispatch. The run uses a libFuzzer custom mutator (`LLVMFuzzerCustomMutator`) that recomputes the header and chunk CRCs after each mutation. The code under test stays byte for byte the shipped source.
- **The settings, pinned before the run:**
  - UBSan with `-fno-sanitize-recover=all`, so that a report stops the run and is counted;
  - `-timeout`, `-rss_limit_mb` and `-max_len`;
  - whether LSan is on or off;
  - `-seed`.
- **The seeds.** Zeek's `dnp3_tcp` corpus (5 inputs, 4,847 octets) for both targets, plus stage 2's malformed set and the HR-23 cases, converted into `FuzzBuffer` chunks by a script pinned by hash. The two builds run on equal terms: the same corpus hash, flags, `-seed`, runner image and duration. The run reports each build's exec count.
- **The duration.** 30 minutes for each target on each build (D1 6862064732, point 2), on a GitHub-hosted runner, never on the owner's PC. It is a stated limit of the result.
- **What counts as a report:** an ASan error; a UBSan error; a deadly signal; a libFuzzer timeout; an out-of-memory stop.
- **The pass rule.** Every input that gives a report, in either build's campaign, is replayed alone on both builds, with the same options.
  - It counts against the patch only when it reproduces on the patched build and not on the unpatched one.
  - An input that does not reproduce on its own build is `unknown`. It is recorded, never dismissed.
  - A report that reproduces on the unpatched build is a memory-safety finding in stock Zeek 9.0.1, which the sensor ships either way. It becomes a threat-model row, and is not netted out.
- **The coverage condition.** The final patched corpus is replayed on a coverage build, and the run reports what it reached. It must reach the new dispatch's changed paths both ways: a response code from the originator's side, and a request code from the responder's side, each with DIR set and with DIR clear. It must also reach `DNP3_Request` and `DNP3_Response`. If it does not, the result is `unknown`, never `pass`.
- **Disclosure.** The repository is public, so a dispatch job's logs are public and its artifacts can be downloaded. A crashing input or a sanitizer trace for Zeek's DNP3 analyzer is an exploit lead against every Zeek deployment.
  - The job prints counts and each input's SHA-256 only. It uploads no input or trace.
  - The inputs reach D6 outside the public record.
  - Any report to Zeek's maintainers waits for the owner's word, because it is contact with an outside party about a security flaw.
- **What the run leaves unshown, even on its terms.** It is evidence that nothing was found in that time, not a proof that nothing is there. It does not show:
  - fragments assembled across many datagrams (FIR and FIN sequences), or the 100,000-octet `DNP3::max_application_layer_fragment_size`, which a short input cannot reach;
  - algorithmic and memory exhaustion beyond the limits set;
  - reads of uninitialised memory, since no MSan is run;
  - the optimised binary that ships, which is a different build from the sanitizer one. So the result speaks for the source and the patch, not for the shipped bytes;
  - the script layer above the analyzer.

## 5. Limits

- Everything above is `desk`. Statements about IEEE 1815 are `inference`. The ports that relays and masters use are `inference` until H-23 (D2).
- **Option (i) changes DNP3 over TCP too** (section 2.3). A relay that opens a TCP connection is the same question as over UDP, and section 4.3's TCP cases measure it.
- **Not read:**
  - when binpac raises `dnp3_header_block` for a fragment whose application header then fails;
  - the code binpac generates at all, the record-level `&length` included.

  A Zeek build makes that code. `dnp3-udp-master-short` and the run show its effect.
- **One failed frame stops the analyzer for the whole flow, under the control and under (i), whatever key picks the parser** (D4 6865038018). `DNP3_UDP_Analyzer::DeliverPacket` and `DNP3_TCP_Analyzer::DeliverStream` set `skip` on a bad chunk CRC, a lost first chunk, or a fragment too short for its parser (section 1, item 6). So a sender can stop the analyzer with one bad datagram, and then write unseen. Option (i) does not change this. Section 6 (R-2) asks D1 where it is recorded.
- **Reassembly is per end of the flow, not per pair of link addresses** (D2's Q2). A dual-role end that interleaves the multi-frame fragments of two associations would break Zeek's reassembly. This note does not introduce it.
- **The `.asc` check** rests on a key from one channel, and on a SHA-1 digest (opening section).
- **The 10 KiB bound of `dpd.zeek`** (section 1, item 6).

## 6. Risk records and open items, for D1

These are D1's to record. The note does not close them.

- **R-1. The attacker-caused both-ends outcome** (D3's N3, D6's N5; ruling 2). One datagram of the opposite DIR names a false second server on a flow. In production that must fail closed: the flow counts as `undecoded`, or takes a cause of its own in D4-90's closed set, and is never a quiet DNP3 flow. That mapping may need C13 text, so it is settled in comments first (D4-99). `undecoded` is not yet a ready path, because its first-sight key needs a server address (C13 0.1 §4.2, "The key of a first sight"; D6's N5).
- **R-2. One failed frame blinds the analyzer for the flow** (section 5): in HR-23's row, or in a row of its own.
- **R-3. A second channel for Zeek's signing key** (D7's N5). The binding of key `962F…8019` to the Zeek project rests on one keyserver. Before a sensor ships, a second check is needed: the same primary key's signatures on earlier Zeek releases, or a fingerprint that the Zeek project publishes.
- **R-4. The patch's couplings** (D7's N6):
  - the first patched build is a rollback floor for the sensor image, since rolling below it reopens HR-23 without a sound;
  - until upstream takes the patch, every Zeek security release means re-applying it, rebuilding and re-measuring, which lengthens the patch interval HR-21 (2) names;
  - pushing the image to a public registry is a distribution, so the notices must be in the image from its first push.
- **R-5. The patch's licence for an upstream offer is the owner's** (D7's N1; ruling 8; section 2.2).
- **dpd's 10 KiB bound in HR-23's row:** D3 adds it (D6's N1; ruling 9). This PR does not edit `docs/threat-model.md`.

## 7. Where each finding is answered

| Finding | Kind | Answered in |
| --- | --- | --- |
| D2 B1: the conflict rule names none, and is not CH-49 | blocking | Section 3 items 3 and 4 (ruling 2) |
| D2 B2: the request parser and a 2-octet APDU, unmeasured | blocking | Section 4.1, `dnp3-udp-master-short` (ruling 3) |
| D2 Q1: a DIR-set frame to a broadcast or multicast address | non-blocking | Section 3 item 3 |
| D2 Q1: link-only frames name no server, and keep-alive flows | limit | Section 3 item 6 |
| D2 Q2: both ends as servers can be legitimate | answer | Section 3 item 4 |
| D2 Q2: reassembly per end, not per link-address pair | risk | Section 5 |
| D2 Q3: say which key (i) uses; add DIR against the code | non-blocking | Section 2.3; section 4.3 (rulings 1, 3) |
| D2 Q3 and D3 B1: TCP changes under (i) | non-blocking and blocking | Sections 2.3, 4.3 and 5 (ruling 4) |
| D2 Q4: `dnp3-udp-relay-write` built mid-session | non-blocking | Section 4.2 |
| D2 Q4: `dnp3-udp-relay-restart`'s later write of g80v1 | non-blocking | Section 4.2 |
| D2 Q4: forged-DIR labels from the builder's role | non-blocking | Section 4 (opening) |
| D2 Q4: classes (1) and (3b) corrected | non-blocking | Section 4.3 |
| D3 B2: a DIR selector lets the sender hide a write | blocking | Section 2.3 (ruling 1); section 4.3's DIR-against-code input |
| D3 B3: the fuzz run cannot reach the patched code | blocking | Section 4.6 (ruling 7) |
| D3 N1: `failure_data` carries payload | non-blocking | Section 4.4 |
| D3 N2: the DIR field's baseline, and its scope | non-blocking | Sections 3 item 7 and 4.3 |
| D3 N3: the conflict can be caused by an attacker | risk | Section 3 item 4; section 6, R-1 (ruling 2) |
| D3 N4: build and pin conditions; "no parse surface" too strong | non-blocking | Sections 4.5 and 2.2 |
| D6 B1: a configuration for part (a) alone, and "named" | blocking | Section 4.1 (C0, C1, C2; ruling 5) and section 4.2 |
| D6 B2: §4.3 lacks D4-100 item 2's reruns; TCP | blocking | Section 4.3 (rulings 4, 5) |
| D6 B3: the malformed set's pass condition | blocking | Section 4.3 (ruling 6) |
| D6 N1: `DPD::ignore_violations_after` | non-blocking | Section 1 item 6; HR-23's row by D3 (ruling 9) |
| D6 N2: class (4) cannot be built; class (1); "floor" | non-blocking | Section 4.3 |
| D6 N3: class (5) zero by construction | non-blocking | Section 4.3 |
| D6 N4: the new cases' first datagram | non-blocking | Section 4.2 |
| D6 N5: the conflict rule hides a service | risk | Section 3 item 4; section 4.2, `dnp3-udp-dir-spoof`; section 6, R-1 |
| D6 N6: `zeek-modbus-sig`'s Service rows | non-blocking | Section 3 item 7 |
| D6 point 2: the fuzz run's pass rule, report, coverage, seeds, equal terms | blocking (on the terms) | Section 4.6 (ruling 7) |
| D7 N1: the upstream offer needs the owner's grant | non-blocking | Section 2.2; section 6, R-5 (ruling 8) |
| D7 N2: the measured digest is the one that ships, kept beyond retention | non-blocking | Section 4.5 (ruling 8) |
| D7 N3: an unpatched project build as a second control | non-blocking | Section 4.1, C1p (ruling 5) |
| D7 N4: cite D7's signature check, with its limits | non-blocking | Opening section; section 5 |
| D7 N5: a second channel for the key | risk | Section 6, R-3 |
| D7 N6: rollback floor, rework, registry push | risk | Section 6, R-4 |
| D7 answers 1 and 3: pin every input; hold the public key | answer | Section 4.5 |
