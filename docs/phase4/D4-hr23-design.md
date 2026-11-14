# D4: HR-23's fix, the design (P4-4-HR23, stage 1)

D4, 2026-11-13. Revised on 2026-11-14 for the four reviews on #675 and D1's rulings on them, again for the re-reviews of `9919fd24` and D1's ruling 6866095230, and again for D6's re-review of `52c7592c` under D1's ruling 6866534402, which narrows this PR to option (i). Revised again for D6's re-review of `542a42cf` (6866817721): P1, P2 and N-A. Revised again (round 6) for the re-reviews of `be6b8cea` under D1's ruling 6879529451, items 1 to 7. Brief P4-4-HR23 (`docs/agent-handoffs.md`, "After D4-100"), under D4-100 items 1 to 3. This PR is documents only: nothing here is built or run.

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
  | `src/Reporter.cc` | `9bdb6c0597165da9476988e4768905c8ecf28e53b3f3ee5334e5663646b44dac` |
  | `src/packet_analysis/protocol/tcp/TCP.cc` | `585e70b69fcf9eb85984872ecdb34c4bb60cc684b860238ca873254707e38400` |
  | `src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc` | `4ee34a68a009a54956c35716e8210fc4ab32aac937b252959cea410260c2419c` |
  | `src/analyzer/protocol/pia/PIA.cc` | `2d4284ca1ea772e3c3369d933d8e5eb04bcca82e426302dd256dbad856c29cd8` |
  | `scripts/base/init-bare.zeek` | `05e960679cdc6832276c35f8dc2623bce3fa786555cbf80a4a4f19cd9cc4c675` |
  | `src/analyzer/protocol/tcp/TCP.cc` | `4543b47c49f40dcb49ee967d1717465c0a70d56abce2a4ed9531ce5557b6e02f` |
  | `src/analyzer/protocol/tcp/TCP_Reassembler.cc` | `cfc7e077da132118db2e2c52aff7fae2a6ede75fea6f659f383699aea18df84e` |
  | `src/packet_analysis/protocol/ip/SessionAdapter.cc` | `68d8e8d4d0aa68b8b674fd973a13f596d410f07404f2a9d751c383c7dba5a09d` |
  | `src/Conn.cc` | `96555ee783b7681a59bdcaa5e92e6f110ea19a2e074eb2e9f583c36cd13ac57d` |
  | `src/session/Manager.cc` | `bdcf83d5c23d8a4ac61790604add7c305e961762b1f14ff466c632db1b6bfe6f` |
  | `src/packet_analysis/Manager.cc` | `4bc5f2f3d88bcf7b96320a7908bed153cda591713918790c93a709ecaba64228` |
  | `src/RunState.cc` | `6da21a5118e567e6710869fe1bd0fd2841a7767d43633c767ab6c46351876984` |
  | `src/main.cc` | `19435f21163401f66c2025b3c51716bce591c975a71fe96255a01edcd73106da` |
  | `src/fuzzers/fuzzer-setup.h` | `af5cdcf389df162ade7aa2e35b88ba3baa73754abcc4c2f8cb5d4e526e3ff7c9` |
  | `tools/binpac/src/pac_flow.cc` | `6bc0b1fc3d4ff2eb34651cd1cb5e396044617a8f718ca315668710623b60c8f9` |

- **Inputs:** HR-23 in `docs/threat-model.md`; D4-98 and D4-100; D4's reading 6852704517 on #657; `docs/phase4/D4-engine-linux-eval.md` §3 and 5.8; D6's E2 note §3 (`docs/phase4/D6-modbus-signature-conditions.md`); the project's script, `modules/telemetry/experiments/engine-linux/probe.zeek`, and its judge, `table.py`; GT-PCAP's `dnp3-udp-temp-port` and `dnp3-udp-unsolicited` labels.
- **The reviews on #675:** D7 6864785127, D2 6864828995, D3 6864835839 and D6 6864977091. **D1's rulings** are 6864990229, and they replace D1's provisional points 6862064732. **D4's confirmation of ruling 1** is 6865038018.
- **The re-reviews of `9919fd24`:** D7 6865821469, D2 6865838202, D3 6865838688 and D6 6866085736. **D1's rulings on them** are 6865138996 (ids, paths, HR-25) and 6866095230.
- **The re-reviews of `52c7592c`:** D7 6866209008, D2 6866220392, D3 6866236602 and D6 6866520537. **D1's rulings** are 6866203475 and 6866534402. The second moves HR-25's resync design to its own brief, P4-4-HR25 (section 5.2).
- **D6's re-review of `542a42cf`:** 6866817721.
- **The re-reviews of `be6b8cea`:** D2 6879378145, D7 6879361218, D3 6879466063 and D6 6879522761. **D1's ruling** is 6879529451, items 1 to 7.
- Section 7 maps each finding to the place where it is answered.

## 1. How Zeek picks the DNP3 parser by direction

1. **Which end is the originator.** A UDP connection's originator is the sender of the first datagram the sensor sees. At creation, Zeek swaps the two roles only when the source port is in `likely_server_ports`, the destination port is not, and the responder is not a broadcast address (`UDPAnalyzer::WantConnection`, `IPBasedAnalyzer::NewConn`). It never swaps them later for DNP3. Only the DNS analyzer and TCP's own code call `FlipRoles` (`DNS.cc`, `TCP_Endpoint.cc`), and no script function swaps roles (`zeek.bif`, `analyzer.bif`).
2. **20000/udp is in `likely_server_ports`.** `base/protocols/dnp3/main.zeek` registers `DNP3_TCP` for `{ 20000/tcp, 20000/udp }` through `Analyzer::register_for_ports`, and that function adds every server port to `likely_server_ports` (`base/frameworks/analyzer/main.zeek`).
   - **This moves HR-23 item (3)'s `inference` about `likely_server_ports` (also D6's, on #666) to `desk`. It is not yet checked against a run.** A flow that the relay starts from 20000 to a master's port outside the set is swapped at creation, and so it is parsed the right way round. The record of the set's contents is the UDP line that `ports.zeek` printed on run 43373373987 ("likely_server_ports at …: … udp …"). Stage 2 or 3 cites that line, and `dnp3-udp-swap-control` (section 4.1) measures the swap itself.
   - **HR-23's trigger is therefore a 5-tuple whose first datagram, as the sensor sees it, is the relay's, unless the relay's port is in `likely_server_ports` and the master's is not** (D6's B1 on #677, 6879737166; D1's ruling 6879752967 item 4). Three arrangements stay unswapped: both ports in the set (both ends on 20000, the arrangement GT-PCAP's two failing cases use), neither in the set (two moved ports), and the relay's port outside the set with the master's inside it (a relay on a moved port sending to a master on 20000).
   - **The third arrangement needs no case of its own** (`desk`). Once `NewConn` has left the roles unswapped, it reaches the analyzer as the first does: the relay is the originator, and `BuildSessionAnalyzerTree` attaches `DNP3_UDP` by the responder's port, 20000, as it does when both ends are on 20000. Nothing after that reads a port number: `DNP3.cc`, `dnp3.pac`, `dnp3-protocol.pac` and `dnp3-analyzer.pac` read none. So the analyzer gets the same `orig` flags and bytes as on `dnp3-udp-unsolicited`, under C0, C1, C1p and C2 alike, and under option (i) each fragment's parser is chosen by its code, not by its side (section 2.3). If D6 still wants it measured, the case is `dnp3-udp-unsolicited`'s frames with the relay's port moved outside the set and the master's kept on 20000, expected to give the same rows; D6 numbers it.
   - **An attacker can cause the trigger** (`desk`, from item 1's reading of `UDPAnalyzer::WantConnection` and `IPBasedAnalyzer::NewConn`). The originator is whoever sends the first datagram the sensor sees. So anyone who can send on the segment can make a 5-tuple in any of the three arrangements relay-started, with one first datagram from the relay's address. The windows are each sensor start and each spell of quiet on the 5-tuple longer than `udp_inactivity_timeout`, after which the next datagram makes a new connection.
3. **What attaches `DNP3_UDP`.** The signature `dpd_dnp3_server_udp` (`dpd.sig`) does, on a UDP payload that starts `05 64`, from either end.
4. **What happens to each datagram.** `DNP3_Base::ProcessData(len, data, orig)` keeps one buffer for each end, chosen by `orig`. That buffer survives across datagrams (`AddToBuffer` keeps `buffer_len`, D2 on #675). It then checks these, in order:
   - the magic `05 64`;
   - the link header's CRC. **`AnalyzerConfirmation` comes only after the CRC passes;**
   - the link's direction bit (DIR, `ctrl & 0x80`) against `orig`. **A mismatch raises only the weird `dnp3_unexpected_flow_direction`, and parsing goes on by `orig`.**

   **These checks run only once 11 octets are buffered** (D6's B2 on `9919fd24`). In the header stage, `AddToBuffer`'s target is `PSEUDO_APP_LAYER_INDEX`: the 10-octet header and the transport octet. With 10 octets or fewer, nothing is checked. Two things follow:
   - **A link-only frame** (length 5) is 10 octets. So its check waits for the first octet of whatever that end sends next.
   - **On a length of 5,** `ProcessData` calls `ClearEndpointState` and returns true. That drops the rest of the delivery: the rest of the next datagram on UDP, the rest of the segment on TCP. No weird and no violation is raised. Section 5.1 states the silent loss this causes.

   Each chunk's CRC is checked in `DNP3_Base::ParseAppLayer`. The reassembled fragment goes to binpac's `upflow` when `orig` is true, and to its `downflow` otherwise, one flow unit for each FIN (`FlowEOF`). The unit is `DNP3_PDU(is_orig)` (`dnp3-analyzer.pac`): `DNP3_Request` for the originator and `DNP3_Response` for the responder (`dnp3-protocol.pac`). `DNP3_Application_Request_Header` is 2 octets. `DNP3_Application_Response_Header` is 4 octets (control, function code, IIN). The function code is the second octet of both.
   - **DNP3 over TCP uses the same parser.** `DNP3_TCP_Analyzer` and `DNP3_UDP_Analyzer` both derive from `DNP3_Base`, whose constructor creates the one binpac interpreter, `DNP3_Conn` (D3's B1 and D6's B2 on #675). `DNP3_TCP_Analyzer::DeliverStream` calls `SetSkip(true)` in the same two cases as UDP (item 6).
5. **What happens to a master's message on the responder's side of a flow the relay started.** It is parsed with the response header.
   - **Shorter than 4 application octets** (a confirm, code 0; a cold or warm restart, codes 13 and 14; any request with no object header): binpac throws `out_of_bound`, measured as `DNP3_Application_Response_Header: 4 > 2` on #657. **This moves HR-23's `inference`, that any message of the master shorter than 4 octets stops the analyzer, to `desk`.**
   - **4 octets or more:** the header parses. `dnp3_application_response_header` carries the right function code, with `is_orig` false, and the first two octets of the object headers are read as IIN. Every code except 129, 130 and 131 takes the response's `default` arm (`Debug_Byte`). So **no object header is parsed and no `dnp3_object_header` event is raised.** This moves HR-23 item (1) to `desk`: the code is seen, and the objects, a control block among them, are not.
6. **How the analyzer stops, and why it stays stopped.** `DNP3_UDP_Analyzer::DeliverPacket` calls `SetSkip(true)` in two cases:
   - when `ProcessData` returns false: a lost magic, a bad header or chunk CRC, a missing first chunk, a length error, or the fragment-size limit;
   - when it catches a `binpac::Exception`, which it then rethrows.

   `Analyzer::NextPacket` returns at once while `skip` is set. `skip` is set false only in `Analyzer`'s constructor. So from that datagram on, the analyzer parses nothing on the connection, in either direction. **On TCP there is one exception:** at the connection's end, `EndpointEOF` and `Done` hand any held data back to binpac whatever `skip` is (section 4.7, item 1). The rethrown exception reaches `Analyzer::NextPacket`'s `catch`, which calls `AnalyzerViolation`, and that raises `analyzer_violation_info`.
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
  - A fragment of 0 or 1 application octets has no code. Both parsers throw on it today (C0 and C1p). Under C2 its result is `unknown`, because `&length` decides it (section 4.7, item 2).
  - A fragment of 2 or 3 octets with code 129 to 131 throws in the response parser, from either side.

  Both are in the malformed set (section 4.3).
- **TCP changes too** (ruling 4). The dispatch is in the shared grammar (section 1, item 4). On TCP, it changes the parser only where the code's class disagrees with the side: a response code from the originator, or a request code from the responder. DIR plays no part in it. A connection whose originator is the outstation is one such case. GT-PCAP's TCP cases all have the master open the connection, so stage 2 adds `dnp3-tcp-master-short`, which reaches the changed path, and the TCP inputs of the malformed set (section 4.3).

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
6. **No server is named from a link-only frame.** A frame of length 5 (ACK, NACK, link status, reset, test) raises no `dnp3_header_block`. So a flow that carries only link-status keep-alives names no server (D2's Q1, a limit). The frame also hides the next delivery from the same end (section 1 item 4; section 5.1).
7. **Where it goes:**
   - `probe.zeek`'s `link` row gains the DIR bit, the one new field. It reads only the `ctrl` octet, which the engine already passes to the script, so no session content is read beyond the script's.
   - **The field stays a probe and judge field.** It is not a C13 field, and it is not on SL-22's allow-list (D3's N2).
   - The judge (`table.py`) takes the DNP3 Service rows of both configurations in `PROBED`, `zeek-probe` and `zeek-modbus-sig`, from the `link` rows (D6's N6). Both load `probe.zeek`. The other configurations keep today's reading from `conn.log`'s responder, as controls.
8. **What part (a) alone fixes, by section 1** (`desk`). These are configuration C1's predictions in section 4.2:
   - `dnp3-udp-temp-port`'s Service row. The responses' flow carries only the relay's frames, with DIR clear from the originator. So the server is 192.0.2.20 udp/20000, and the master's port 20000 is no longer named.
   - Not `dnp3-udp-unsolicited`. The relay's 130 parses whole and names the right server, but the confirm then stops the analyzer, so the flow row and the function rows still fail.

## 4. What stage 2 needs (D6 writes and pins it)

D6 writes the cases and the conditions, and pins them before the counted run. Labels come from how each case was built, never from an engine. **A case with a forged DIR takes its labels from the builder's role, not from tshark's `dnp3.ctl.dir`,** since that bit is the one being forged (D2's Q4). This section states what the measurement needs, and the results that section 1 predicts (`desk`; the run settles them).

**Case ids name their transport** (D1 6866534402, point 3; D6's N7 on `52c7592c`). None ends in `-udp` or contains `moved-port`, because `table.py`'s summary columns tag a capture by those strings (`endswith("-udp")`, `"moved-port" in`). The new ids here are `dnp3-udp-relay-write`, `dnp3-udp-relay-restart`, `dnp3-udp-master-short`, `dnp3-udp-dir-spoof`, `dnp3-udp-swap-control`, `dnp3-tcp-master-short` and `dnp3-tcp-dir-spoof`, and each meets the rule. The `dnp3-resync-*` ids go to P4-4-HR25.

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
- The harness reports both readings for every flow under every configuration. They are expected to differ in these places:
  - (3b-link): it is confirmed, so `conn.log` names it, but it has no `link` row;
  - (3a) and (3c): a `link` row may name a server before the failure.
- **Whether a `link` row is written for a fragment that then fails** depends on when binpac evaluates the `Header_Block` refinement, in code that was not read (section 5.1). At a fragment's first frame, `ProcessData` hands the 8 header octets to binpac (`interp->NewData`) before `ParseAppLayer` checks any chunk CRC. Whether `dnp3_header_block` is raised then, or only once the `DNP3_PDU` completes, is the question. So these read `unknown` under C1, C1p and C2 until the run (D6's B2 on `9919fd24`):
  - the Service rows of (3a), whose fragment never completes, and of (3c);
  - the malformed inputs that fail after their header: a bad chunk CRC, and a fragment without FIR.
  - Section 4.7 adds the other inputs whose header binpac holds first (link lengths 0 to 4, a fragment without FIN, one over the size limit), because the patch rewrites the code that decides this.
- On `dnp3-udp-relay-restart` the question does not arise, because the relay's first message parses whole before the restart (section 4.2).

**The port arrangement.** **Every new relay-started UDP case puts both ends on ports in `likely_server_ports`** (20000 and 20000, as `dnp3-udp-unsolicited` does), or puts both on ports outside the set. With the relay on 20000 and the master outside the set, Zeek swaps the roles at creation, and the case does not test HR-23. The third unswapped arrangement, the relay outside the set and the master on 20000, reaches the analyzer as both ends on 20000 do, and has no case of its own (section 1, item 2).
- **`dnp3-udp-swap-control`** puts the relay on 20000 and the master on a port outside the set. The control engine is expected to pass every row of it, and that measures section 1 item 2.
- **The TCP arrangement for `dnp3-tcp-master-short`** (D6's B1 on `9919fd24`). By S22, an SEL relay opens no TCP session (D2's table in `docs/phase4/D6-engine-run-pass-conditions.md` §7). So the case is a sensor joining a long-lived session mid-stream, and the first segment the sensor sees is the outstation's (HR-23 item (3)).
  - **When Zeek swaps a TCP connection** (D6's N1 on `52c7592c`):
    - `TCPAnalyzer::WantConnection` never swaps a connection seen from its SYN. It swaps one seen without its SYN by the port numbers (`TCP.cc`);
    - a connection first seen at its SYN-ACK is swapped once an ACK or data follows (`TCP_Endpoint::CheckHistory`);
    - a SYN and SYN-ACK seen the wrong way round swap it too (`TCPSessionAdapter.cc`).
  - **So the case's capture holds neither a SYN nor a SYN-ACK,** and puts both ports outside `likely_server_ports`. With the outstation on 20000 and the master outside the set, the roles would be put right, and the case would not reach the changed path.
  - **When the analyzer attaches.** `dpd_dnp3_server` (`dpd.sig`) has `tcp-state responder`, so `DNP3_TCP` attaches at the first matching payload from the responder, here the master. The outstation's frames before that reach the analyzer only by the PIA's replay (`PIA_TCP::ReplayStreamBuffer`, `PIA.cc`), within `dpd_buffer_size` (1024 octets) and `dpd_max_packets` (100, `init-bare.zeek`). **The case keeps the outstation's frames before the master's first frame within both limits.**
  - **The control for attachment and replay** (D6's N-A on `542a42cf`). A C1 pass on the Service row shows only that the analyzer attached. The master's frames carry DIR set, and by section 3 item 3 they name the other end, the outstation, so once the analyzer is attached they can pass that row on their own. The control is therefore: under C1, a `link` row with `is_orig` true, stamped with the time of the master's first frame. `PIA_TCP::ReplayStreamBuffer` replays the buffered frames without their own times, so only the replay can write that row, and the case gives no frame of the outstation that same time.

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
| `dnp3-udp-swap-control` | every row | pass | pass | pass, `unknown` | `desk`, section 1 item 2 |
| `dnp3-tcp-master-short` | the service | fail (the master is `conn.log`'s responder) | pass (the outstation's frames, DIR clear, name it) | pass | `desk`, sections 2.3 and 3 |
| `dnp3-tcp-master-short` | the flow, and the first short message with every row after it | fail (the first short message from the responder throws) | fail | pass | `desk`, section 1 item 5 |
| `dnp3-tcp-dir-spoof` | the service | pass | fail (server conflict) | fail (server conflict) | `desk`, section 3 item 4 |
| `dnp3-tcp-dir-spoof` | the direct operate's objects, and the other rows | pass | pass | pass, `unknown` | `desk`; a selector keyed by DIR would fail the objects row |

C1p is expected to equal C1 on every row. A row where it does not shows the build, not the patch (section 4.1). The C2 column is option (i). HR-25's fix is not part of it (section 5.2). Section 4.7 lists every expectation that (i) changes.

- **How `dnp3-udp-relay-write` is built** (D2's Q4; D6's N4). Starting the flow with a 130 is not a conforming session: its CON bit is set, so the master must confirm it, and the 2-octet confirm stops the analyzer first. So the case is built as a sensor joining mid-session, which is HR-23 item (3):
  - the first datagram the sensor sees is the relay's solicited 129 with CON clear, answering a request the sensor missed;
  - the master's write and the relay's 129 follow, on the same 5-tuple;
  - every master message before the write is 4 octets or more, and the relay's first message needs no confirm.
- **How `dnp3-udp-relay-restart` is built.** It starts the same way: the relay's first datagram needs no confirm, and every master message before the restart is 4 octets or more. After the cold restart (13), the master sends a request of 4 octets or more, so the run shows that nothing after the restart is parsed. The natural one is the master's write of g80v1 index 7, which clears IIN1.7 DEVICE_RESTART. Its code is 2, so it also tests whether `unauthorized-write` sees a write after the restart (D2's Q4).
- **How `dnp3-udp-dir-spoof` is built** (D6's N5, ruling 3). It is an otherwise valid UDP flow that the master starts, carrying one frame from the master's address with DIR clear and a valid CRC.
  - The labels give one server, the outstation, from how the case was built.
  - The frame should be a direct operate (code 5) with a control block (g12v1), so that its objects row also tests the code rule under C2: parsed as a request, whatever DIR says (D2's N1 on `9919fd24`: a write is code 2).
  - The case shows what the attacker-caused outcome costs (section 3 item 4, R-1).
- **How `dnp3-tcp-master-short` is built** (D6's B1 on `9919fd24`, replacing D1's first mapping). It is a TCP connection whose originator is the outstation, on the arrangement of section 4.1.
  - The outstation sends its responses (129, one with CON set) from the originator's side.
  - From the responder's side, the master sends a confirm (0) where the response calls for one, a cold restart (13) and a record current time (24). Each is followed by a labelled write (code 2) of 4 octets or more.
  - It reaches the changed path both ways: response codes from the originator, and request codes from the responder.
- **How `dnp3-tcp-dir-spoof` is built.** It is `dnp3-udp-dir-spoof` over a TCP connection the master opens. One frame from the master's side has DIR clear and a valid CRC, and it is a direct operate (code 5) with a control block (g12v1). It does not reach the changed parser path (D3's N5 on `9919fd24`). It tests part (a)'s both-ends outcome on TCP, and it guards the code rule: under C0 and under C2 the master's frame is parsed as a request, so its objects row passes, and a selector keyed by DIR would fail it.
- The write's objects in both relay cases are labelled (no `?`), so that the objects column can tell the fix from the control.
- Stock Zeek and ICSNPP are shown beside C0, and are not judged for the fix.

### 4.3 The regression

**The reruns of D4-100 item 2, on C2 by hash** (D6's B2; one source, D4-97). The run names C2 by the tarball's SHA-256, the patch's SHA-256 and the built image's digest (section 4.5). **All of these are rerun.** C2 is a new build, with a new base image, compiler and configure line, so none of them is exempt (D6's N4 on `9919fd24`):
- every row of E-D4-03's conditions file;
- every GT-PCAP DNP3 case, over UDP and over TCP;
- every counted measurement that names the engine: the PRP pairs, the public captures, E2's corpus rows, and HR-24's stage 3 once it is pinned;
- the harness check that the engine emits no record or field that the script does not emit now. That check compares C2 with C1 and C1p, which run the same script. Against C0, part (a)'s DIR field would be new (D6's B2, D3's N2).

**The control for each judgement** (D6's N1 on `9919fd24`):
- **In the reruns,** a regression is a row that C2 fails and C0 passes. C0 is D4-100 item 2's control, because what counts is the engine that ships. C1p then shows whether the build or the patch caused it.
- **In the malformed set,** see "How each input is judged" below.
- **Part (b)'s new cases** (section 4.2) are judged as C2 against C1p.

**TCP cases that reach the changed path** (ruling 4; D6's B1 on `9919fd24`). The parser changes only where the function code's class disagrees with the side: a code of 129 to 131 from the originator, or any other code from the responder. DIR plays no part (section 2.3). These cases are:
- `dnp3-tcp-master-short` (section 4.2), a connection whose originator is the outstation;
- the malformed set's TCP inputs below, on a connection the master opens.

`dnp3-tcp-dir-spoof` does not reach the changed path. It guards the code rule (section 4.2).

**The UDP false-positive set.** Each item is on its own 5-tuple, in a flow of one datagram unless its class says otherwise. The per-end buffer survives across datagrams, so a later datagram could complete an earlier one's header (D2's Q4). The classes:
- (1) `05 64` and nothing more, and `05 64` with 1 to 8 more octets. The header stage never reaches 11 octets, so no check runs (section 1 item 4; D2, D6's N2);
- (2) a header whose CRC fails, **in a datagram of 11 octets or more**. A 10-octet one is never checked, as in class (1) (D6's B2 on `9919fd24`). Expected: never named, since confirmation needs the CRC. It raises `AnalyzerViolation("broken_checksum")`;
- (3) a header whose CRC passes, then non-DNP3 bytes, in these forms:
  - (3a) in the same datagram, failing the chunk CRC;
  - **(3b-data):** a whole frame, with an application fragment and FIN, then a later datagram on the same flow without the magic. That datagram raises `dnp3_header_lacks_magic` and sets `skip`;
  - **(3b-link):** a link-only frame, then a later datagram without the magic (D6's B2 on `9919fd24`). Nothing is checked on the first datagram. The second datagram's first octet completes the check, which confirms the flow, and the rest of that datagram is dropped with no weird. A third datagram of 11 octets or more without the magic raises `dnp3_header_lacks_magic`;
  - (3c) in the same datagram, with valid chunk CRCs and an application part too short for its parser.

  By `DNP3_Base::ProcessData` and `ParseAppLayer`, (3a) and (3b-data) raise only a weird (`dnp3_corrupt_app_chunk_checksum`, `dnp3_header_lacks_magic`) and set `skip`. Neither raises an analyzer violation, so `dpd.zeek` never removes the service that the header's CRC confirmed. (3c) throws in binpac, which raises a violation (section 1, item 6), so C0 removes the service;
- (4) real UDP protocols whose first two octets are free and can be `05 64` (D6's N2): a DNS query with ID `0x0564`, NetBIOS name service and LLMNR with the same ID, and a RADIUS Accounting-Response (code 5, identifier `0x64`). **The generator checks every header CRC.** When one passes, it changes a field outside the first two octets that keeps the message valid for its protocol, and checks again: the flags of a DNS, NetBIOS or LLMNR query, or the authenticator of a RADIUS response (D6's N2 on `52c7592c`, correcting D6's N3 on `9919fd24`). The ID is not changed, because it is the field that carries `05 64`. In a real payload, octets 8 and 9 sit where the header CRC is (a DNS header's NSCOUNT, for one), so a payload could otherwise match by chance;
- (5) random UDP payloads forced to start `05 64`. This class also holds NTP, Syslog and SNMP payloads forced to start that way, since none of those protocols can start `05 64` (D6's N2). **The generator computes every header CRC, and draws again whenever one passes** (D6's N3). For a header split across datagrams from one end, it computes the CRC over the octets that `ProcessData` would assemble. The labels then say that each CRC fails, from how the case was built.

**The bounds** (D6's N2):
- For classes (1), (2), (4) and (5), the bound is no named flow, under every configuration (`desk`, from section 1 item 4).
- (3b-data) is expected to stay named DNP3, a false positive, under every configuration, C0 included (`desk`).
- (3b-link) is expected to be named under C0 from its second datagram on, and never under C1, C1p or C2, because no `link` row is written (`desk`).
- (3a) stays named under C0. Its Service rows are `unknown` under C1, C1p and C2 (section 4.1).
- (3c) is expected to be named under C0 only until its violation. What C2 does with it is what the class measures, judged against C1p, with its Service rows `unknown` until the run (section 4.1).
- Each class also has its rate of `undecoded`, against the control, because part (b) must not turn an unnamed flow into a named one.
- The set's smallest size, its floor, is D6's to set (E2's `fp-floor`).

**The malformed DNP3 inputs** (D4-100 item 2), run under C2, C1p and C0.
- **Each input is on its own 5-tuple** (D6's B3, ruling 6). Otherwise C0 stops at the first failure on a flow, (i) carries on, and the later inputs raise errors that C0 never reached.
- **How each input is judged** (ruling 6; D6's N1 on `9919fd24`; D1 records this reading of D4-100 item 2 in its next decision entry):
  - **A reporter error** (`reporter->AnalyzerError` in `AddToBuffer` and `ParseAppLayer`) is judged against the pin for its input, as a violation is (D6's N4 on `52c7592c`). Some are expected by design under every configuration: link lengths 1 to 3 raise `AddToBuffer`'s invalid-target-length error (below).
  - **A crash, or a reporter error that no pin expects, is the finding.** It counts against the patch when C1p lacks it. One that C1p or C0 also shows is a finding in Zeek or in the build. It is not netted out, and section 4.6's disclosure rule handles it.
  - **Sanitizer reports come only from the fuzz run,** where this set is part of the seed corpus. C0, C1p and C2 are not sanitizer builds.
  - **Analyzer violations** are judged against an expected result pinned for each input and each configuration by stage 2, not against the control. Under (i), some inputs fail by design where C0 does not, and that is (i)'s correct behaviour.
- **The set:**
  - 1 to 3 octets;
  - **a link length of 0 to 4 with a valid header CRC, each treated as a failed header** (D6's N3 on `52c7592c`; D2's N1 on `52c7592c`, as it applies to (i)). There is no length to read such a frame by. By `ProcessData` and `AddToBuffer`, the weirds, the reporter errors and `skip` are the same under C0, C1p and C2 (D2's N2 on `be6b8cea`). Their `link` rows are not: those are `unknown` for C2 against C1p (section 4.7, item 1). The results:
    - **0:** the weird `dnp3_negative_or_zero_length_link_layer`, raised before any target is computed, then `skip`. No violation;
    - **1 to 3:** a target of 8 to 10 octets, below the 11 already buffered. So `AddToBuffer` raises its invalid-target-length `AnalyzerError`, which sets `skip`. That reporter error is expected by design. No violation;
    - **4:** a target of 11, equal to the buffer. The 11th octet is taken as the transport octet, and `ParseAppLayer` runs with no chunk. With FIR clear: `dnp3_first_application_layer_chunk_missing`, then `skip`. With FIR and FIN: binpac gets only the 8-octet header. Section 5.1's unread generated code decides what happens, so it is `unknown` and the run pins it. With FIR and no FIN: no failure at that frame, and the fragment stays open with no application octet.

    Stage 2 pins each;
  - a length of 5 with trailing bytes. **Expected under every configuration: the trailing bytes are dropped, with no weird and no violation** (D6's B2 on `9919fd24`);
  - a length of 6: a transport octet and no application octet;
  - 1 application octet (a control octet and no function code), from each side (section 2.3);
  - a code of 129 to 131 with 2 or 3 application octets, from each side (section 2.3);
  - bad header and chunk CRCs;
  - a datagram longer than its frame, and two frames in one datagram;
  - a frame of the largest length, 255, whose target is 292 octets, against `MAX_BUFFER_SIZE` 300. **Expected: no `AnalyzerError`.** `AddToBuffer` never copies more than its target, and 292 is the largest target `ProcessData` computes, so the buffer-exceeded error cannot be reached (D6's B2 on `9919fd24`);
  - a fragment without FIR, one without FIN, and one beyond `DNP3::max_application_layer_fragment_size`;
  - DIR set from both ends, and DIR changing within one flow;
  - **DIR disagreeing with the function code's class** (ruling 3; D2's Q3; D3's B2). One is a master's direct operate (code 5) with a control block (g12v1) and DIR clear, on a UDP flow the master starts and on a TCP connection the master opens. C0 is expected to parse its objects. C2 is expected to parse them too, and a selector keyed by DIR would show here as a regression;
  - the master's 2- and 3-octet messages on each side of the flow;
  - **the TCP inputs, on a connection the master opens, restated by code and side** (D6's B1 on `9919fd24`; D3's N5). They are a 129 from the originator with 2, 3, and 4 or more application octets, and codes 0, 13 and 2 (with objects) from the responder. Each is sent with DIR set and with DIR clear. Stage 2 pins the expectations for each configuration. Under C0, the 129 from the originator takes the request parser, and the codes from the responder take the response parser. Under C2, each takes its own code's parser. The 2- and 3-octet 129s throw under C2.
  - **TCP inputs that leave a header held when the connection ends** (D3's B1 and D6's N1 on `be6b8cea`; D1 6879529451, item 1). Each is on a connection the master opens, on its own 5-tuple. They reach the end-of-connection parse of section 4.7 item 1, which runs outside the analyzer's `binpac::Exception` handlers. The four, which cover both of D6's endings (closed by a TCP FIN, which calls `EndpointEOF`; left open until the capture ends, when `Done` runs):
    - a fragment with FIR and without the DNP3 FIN bit, then a TCP FIN from that end;
    - the same fragment with no TCP FIN segment, so that it is still held at the end of the capture, when `Done` runs;
    - a good header, then a bad chunk CRC, then a TCP FIN from that end. The weird sets `skip`, `ProcessData` returns false, and `DiscardFlowBuffer` does not run, so binpac keeps the header to the end;
    - a link length of 4 with FIR and without the DNP3 FIN bit, then a TCP FIN from that end.

    Each is judged by the rule above: a crash, or a reporter error that no pin expects, is the finding. **Expected under every configuration: no crash.** For C0 and C1p, D3's reading is that nothing parses at the end, because `NewData(nullptr, nullptr)` on a held, incomplete frame copies nothing and leaves the frame incomplete (`FlowBuffer::MarkOrCopyFrame` and `ready()`, D3 6879466063, N1, `desk`). For C2 it is `unknown`, because the patch rewrites the unit that requests the frame (section 4.7, item 1). Their `link` rows are section 4.7 item 1's.

### 4.4 What the harness reports

For each case and configuration, the harness reports:
- `weird.log`'s count of `dnp3_unexpected_flow_direction`, and of every other `dnp3_` weird by name;
- `analyzer.log`'s rows, read for `failure_reason` and the analyzer's name only. **It does not read `failure_data`,** which in Zeek 9.0.1 carries up to `Analyzer::Logging::failure_data_max_size` (40) octets of the payload that caused the violation. That is session content beyond the script's (D3's N1, `base/frameworks/analyzer/logging.zeek`);
- the count of frames whose DIR disagrees with their code's class (section 2.3), from the probe log;
- the both-ends field (section 3 item 4);
- both "named" readings (section 4.1);
- the SHA-256 of the `zeek` binary inside the image (section 4.5).

The judge does not read these. They show which parser ran.

### 4.5 The build and the pin of option (i)

These keep the engine that is measured the engine that ships (D4-100 item 2; O-7; AP-31; D7's answer 1; D3's N4; ruling 8).

- **Every input is pinned:**
  - the tarball by SHA-256, with its `.asc` checked by `gpgv --keyring` against a committed public key, whose SHA-256 and two fingerprints `docs/release.md` records. The build never reads the runner's default keyring and never fetches a key from a keyserver. The key file is `modules/telemetry/experiments/engine-linux/zeek-patch/zeek-release-key.asc`, with its fingerprint and D7's check recorded beside it (D1 6865138996, point 3; D7's M1). Before a sensor ships, the key is confirmed from a second source other than `keys.openpgp.org`, where it came from: the same primary key's signatures on earlier Zeek releases, or a fingerprint that the Zeek project publishes (section 6, R-3; D7's M2);
  - the patch by SHA-256;
  - the base image by digest, not by tag;
  - the configure line, written down. Zeek 9.0.1's `configure` can leave the fetchers out of the build: `--disable-zkg`, `--disable-zeekctl`, `--disable-javascript`, `--disable-python`, `--disable-cluster-backend-zeromq` and `--disable-af-packet` (D7). That serves AP-31 (1);
  - the versions of the build and runtime packages, the compiler, libpcap and OpenSSL among them, listed for D7.
- **The artifact the counted run measures is the image by digest. It is the image that ships, never a rebuild.** A rebuild is a new engine for this purpose, and needs its own run or a shown reproducible build (D7's N2).
- **The measured image's digest is kept beyond GitHub's artifact retention** (ruling 8), so that the claim can be checked later. It is kept in `docs/release.md` (D7), and in the decision entry that records the counted run (D1 6865138996, point 3; D7's M1).
- **The counted run's log records the SHA-256 of the `zeek` binary inside the image.** That ties the program hash in `config_digest` (SL-19, CH-32) to the measured binary.
- **The release carries the image itself,** and the sensor host pulls nothing from a registry (AP-31 (1)).
- **The paths, as D1 assigned them** (6865138996, point 3; the brief: "a change outside the script names its path in stage 1"):
  - the patch and the image's build: `modules/telemetry/experiments/engine-linux/zeek-patch/` (D4);
  - the fuzz job: a new dispatch-only workflow, `.github/workflows/d4-zeek-dnp3-fuzz.yml`. D4 writes it, D6 reviews it, and D6 runs it and judges it;
  - the public key: `modules/telemetry/experiments/engine-linux/zeek-patch/zeek-release-key.asc`.
- D7 writes the inventory and release-record entries when a build exists (D7's answer 2). Nothing is owed in this PR.

### 4.6 The sanitizer fuzz run

The fuzz run is agreed for (i) (D1 6862064732, point 2). D4 adds the job, and D6 runs it and judges it. Its terms are ruling 7, from D3's B3 and D6's point 2.

- **The targets.** Zeek's generic fuzzer (`generic-analyzer-fuzzer.cc`) has a `dnp3_tcp` target and no `dnp3_udp` target. `dnp3_udp` is added with one line in `src/fuzzers/CMakeLists.txt`: `add_generic_analyzer_fuzz_target(dnp3_udp udp)`. Without `udp`, `generic-analyzer-fuzzer.cc` drives the analyzer by `NextStream`, not `NextPacket` (D6's B3 on `9919fd24`). Each target runs on the patched build (C2's source) and the unpatched build (C1p's source), built with ASan and UBSan.
- **How the fuzzer drives the analyzer.** It instantiates the analyzer directly, on one fixed synthetic connection, with no signature, no DPD and no role swap. Each chunk's `is_orig` comes from its `FuzzBuffer` flag byte, so both sides can be driven.
- **Which end-of-connection path the `dnp3_tcp` target reaches** (D1 6879529451, item 1; D4's reading of `generic-analyzer-fuzzer.cc` and `fuzzer-setup.h`, `desk`). It reaches `FlowEOF` through `Done`, and never through `EndpointEOF`. So D6's N1 is right on `Done`, and D3's B1 is right that the fuzzer never calls `EndpointEOF`.
  - **`Done`:** after `Fuzzer::Process` returns, `LLVMFuzzerTestOneInput` calls `Fuzzer::Cleanup`, which calls `fuzzer_cleanup_one_input` (`fuzzer-setup.h`). That calls `session_mgr->Drain()`, and `Manager::Drain` (`session/Manager.cc`) calls each session's `Done`. `Connection::Done` (`Conn.cc`) calls the adapter's `Done`. `TCPSessionAdapter::Done` calls `SessionAdapter::Done` (`SessionAdapter.cc`), which calls `Analyzer::Done`, and that calls `Done` on each child not yet finished, `DNP3_TCP_Analyzer::Done` among them, which calls `FlowEOF(true)` and `FlowEOF(false)`. So every input whose analyzer is still attached at cleanup reaches the end-of-connection parse.
  - **That parse runs outside the fuzzer's `catch`.** `Fuzzer::Process` catches `binpac::Exception` only around each `NextChunk`. Nothing in `LLVMFuzzerTestOneInput` or `fuzzer_cleanup_one_input` catches it. So a throw there is not caught inside the target. That it then ends the process as a deadly signal, which "What counts as a report" below counts, rests on the fuzzing engine, which is outside the tarball (`inference`).
  - **`EndpointEOF`:** only `TCPSessionAdapter::EndpointEOF` calls a child's `EndpointEOF`, and only `TCP_Reassembler::CheckEOF` calls that, on a TCP FIN, close or reset (`TCP_Reassembler.cc`). The fuzzer hands each chunk to `NextStream` directly, with no segment and no reassembler, so `EndpointEOF` is never called.
- **The CRC fix-up.** `DNP3_Base::CheckCRC` checks every header and every chunk in C++ before binpac sees a byte, and `DNP3.cc` has no fuzzing bypass. So a plain mutator would almost never reach the patched dispatch. The run uses a libFuzzer custom mutator (`LLVMFuzzerCustomMutator`) that recomputes the header and chunk CRCs after each mutation. The code under test stays byte for byte the shipped source.
- **The settings, pinned before the run:**
  - UBSan with `-fno-sanitize-recover=all`, so that a report stops the run and is counted;
  - `-timeout`, `-rss_limit_mb` and `-max_len`;
  - whether LSan is on or off;
  - `-seed`.
- **The seeds.** Zeek's `dnp3_tcp` corpus (5 inputs, 4,847 octets) for both targets, plus stage 2's malformed set and the HR-23 cases, converted into `FuzzBuffer` chunks by a script pinned by hash. The two builds run on equal terms: the same corpus hash, flags, `-seed`, runner image and duration. The harness is equal too: the custom mutator's source and the line that adds the UDP target are pinned by SHA-256, and are the same for both builds (D6's B3 on `9919fd24`). The run reports each build's exec count.
- **The duration.** 30 minutes for each target on each build (D1 6862064732, point 2), on a GitHub-hosted runner, never on the owner's PC. It is a stated limit of the result.
- **What counts as a report:** an ASan error; a UBSan error; a deadly signal; a libFuzzer timeout; an out-of-memory stop.
- **The pass rule.** Every input that gives a report, in either build's campaign, is replayed alone on both builds, with the same options, **inside the job** (D1 6866095230, point 3). No input leaves the runner.
  - It counts against the patch only when it reproduces on the patched build and not on the unpatched one.
  - An input that does not reproduce on its own build is `unknown`. It is counted, never dismissed.
  - A report that reproduces on the unpatched build may be a vulnerability in stock Zeek 9.0.1, which the sensor ships either way. It is not netted out. It is handled by the disclosure rule below.
- **The coverage condition** (D1 6866095230, point 3, restating D3's and D6's form). The final patched corpus is replayed on a coverage build inside the job. The coverage report shows the lines and branches of the patched parser path that were reached: both arms of the new dispatch, and `DNP3_Request` and `DNP3_Response` entered. If they were not reached, the result is `unknown`, never `pass`.
  - **A limit of that report** (D6's B3 on `9919fd24`): side and DIR are values in the input, not branches. Under ruling 1 the dispatch branches only on the code, and `is_orig` only picks `upflow` or `downflow`, which run the same generated code. So the report shows that both arms ran. It does not show from which side, or with which DIR.
- **Disclosure** (D1 6866095230, point 3). The repository is public, so a dispatch job's logs are public and its artifacts can be downloaded. A crashing input or a sanitizer trace for Zeek's DNP3 analyzer is an exploit lead against every Zeek deployment.
  - **The job publishes only pass or fail, and its counts.** It uploads no input, trace or crashing input, and prints none.
  - **If a crash is found,** it may be a vulnerability in Zeek itself. D1 brings it to the owner for disclosure before anything about it is made public, a threat-model row included.
  - Any report to Zeek's maintainers waits for the owner's word, because it is contact with an outside party about a security flaw.
  - **The limit this leaves** (D6's N5 on `52c7592c`). No input leaves the runner and none is kept. So a report against the patch can be counted, but not reproduced, fixed or reported. Whether inputs are kept privately is the owner's decision.
- **What the run leaves unshown, even on its terms.** It is evidence that nothing was found in that time, not a proof that nothing is there. It does not show:
  - fragments assembled across many datagrams (FIR and FIN sequences), or the 100,000-octet `DNP3::max_application_layer_fragment_size`, which a short input cannot reach;
  - algorithmic and memory exhaustion beyond the limits set;
  - reads of uninitialised memory, since no MSan is run;
  - the optimised binary that ships, which is a different build from the sanitizer one. So the result speaks for the source and the patch, not for the shipped bytes;
  - the script layer above the analyzer;
  - **the end-of-connection parse by `EndpointEOF`** (D3's B1 on `be6b8cea`). The fuzzer never drives it (above), so it is shown only by section 4.3's TCP inputs that end by a TCP FIN while a header is held. The `Done` path is reached at each input's cleanup, but only on the fuzzer's one synthetic connection, and for the UDP target not at all, since `DNP3_UDP_Analyzer` has no `Done` of its own that calls `FlowEOF`.

### 4.7 Every expectation that option (i) changes

This is the complete list that D6's B2 on `52c7592c` asks for, as far as (i) changes it, judged as C2 against C1p (`desk`). Option (i) changes two things (section 2.2; D6's P1 on `542a42cf`):
- which binpac parser reads a reassembled fragment, chosen by its code instead of by `is_orig` (section 2.3);
- the generated code of the top-level unit, `DNP3_PDU`, which reads the header before the dispatch and carries the record-level `&length` that moves.

`ProcessData`, `ParseAppLayer`, the CRC checks, the 11-octet header stage, `AddToBuffer` and `SetSkip` are C++ in `DNP3.cc`, and are unchanged. The lists below sort every expectation into three: what the code rule changes, what depends on the rewritten generated code, and what does not change.

**What changes by the code rule.** A fragment changes its result only when its code's class disagrees with its side: a code of 129 to 131 from the originator, or any other code from the responder.
- **The twin rule** (D6's P2.1 on `542a42cf`, in place of per-arm results). Under C2, a fragment gives the binpac result that C1p gives for the same bytes from the side its code belongs to, and `is_orig` is the only difference in binpac's events. Stage 2 pins each changed-path input's binpac result from that twin.
  - **The twin covers binpac's result only** (D6's N4 (b) on `be6b8cea`). The weirds that `ProcessData`, `AddToBuffer` and `ParseAppLayer` raise, `dnp3_unexpected_flow_direction` among them, and the reporter errors those functions raise, stay those of the input on its own side (section 2.3; "What (i) does not change"). So no weird count and no reporter error is pinned from the twin. Two examples of what the twin gives, both from `dnp3-protocol.pac`:
  - a request code from the responder, with 3 application octets: if its arm is `empty` (codes 0, 13, 14, 15, 19, 23 and 24), it parses. If its arm parses objects (codes 1, 2 and 5, among others), the one octet left is shorter than `Object_Header`'s first two fields (`object_type_field`, 2 octets, and `qualifier_field`, 1 octet), so it throws under C2, as the same bytes do from the originator under C1p;
  - a response code from the originator, with 4 octets or more: its IIN and objects are parsed only as far as the response parser accepts them.
- **Both directions** (D6's P2.2 on `542a42cf`):
  - where C1p's violation set `skip` and C2's parser does not throw, C2 goes on parsing the flow, so every later row on that flow changes with it;
  - where C2's parser throws and C1p's did not, C2 stops the flow where C1p went on. Three inputs do this (D6's N2 on `be6b8cea`):
    - a code of 129 to 131 with 2 or 3 application octets from the originator. C1p takes the request parser's `default` arm, `unknown: bytestring &restofdata`;
    - a response from the originator whose objects the response parser rejects. C1p takes the same `default` arm;
    - a request code (any but 129 to 131) from the responder, of 4 octets or more, whose objects the request parser rejects. C1p takes the response parser's `default` arm, `Debug_Byte` (`bytestring &restofdata`), which accepts any bytes. C2 throws in `Request_Objects`.
  - **So every relay-started flow's C2 `pass` depends on two things:** the relay's responses parsing in the response parser, and the master's requests parsing in the request parser. Under C1p the relay's responses take the request parser's `default` arm, which accepts any bytes. The master's requests of 4 octets or more take the response parser's; its 2- and 3-octet requests throw in the 4-octet response header, `DNP3_Application_Response_Header`, which comes before that arm (HR-23's own fault; "What changes", D2's note 6879662396). That holds for section 4.2's C2 column on `dnp3-udp-unsolicited` (the relay's 130), `dnp3-udp-relay-write` and `dnp3-udp-relay-restart` (the relay's first 129), `dnp3-tcp-master-short` (the outstation's 129s), and `dnp3-udp-temp-port`'s second flow (below).
- **The events.** Under C2, `dnp3_application_request_header` can be raised with `is_orig` false, and `dnp3_application_response_header` with `is_orig` true. The probe's `fc` rows keep the code and `is_orig`, and the judge classes a message by its code (`NOT_REQUESTS`, `table.py`), so its reading does not change. `dnp3.log`'s rows change where these combinations occur (`base/protocols/dnp3/main.zeek`). Those are values in its existing fields, not new fields.

**Where it shows:**
- in section 4.2: the C2 column where it differs from C1, on `dnp3-udp-unsolicited`, `dnp3-udp-relay-write`, `dnp3-udp-relay-restart` and `dnp3-tcp-master-short`;
- **`dnp3-udp-temp-port`'s second flow** (D6's P2.3 on `542a42cf`). By its labels, the relay starts it: 192.0.2.20:20000 to 192.0.2.14:20000, both ends on 20000, frames 2 and 4. Under C2 its two responses reach the response parser for the first time. Its rows are expected unchanged: section 4.2's C2 `pass` holds if both parse as the responses on `dnp3-udp-req-port` do, where they come from the responder. Its parse path and the probe's `obj` rows change;
- in section 4.3's malformed set: the 129 to 131 fragments of 2 or 3 octets from the originator, the master's 2- and 3-octet messages on the responder's side, and the TCP inputs restated by code and side;
- in classes (3b-data) and (3c) of the false-positive set (D6's P2.4 on `542a42cf`). (3b-data) carries a whole fragment with FIN, so binpac parses it, as it parses (3c)'s. Each changes only where its code's class disagrees with its side. So stage 2 states the code and side of each (3b-data) and (3c) item, and pins its result for each;
- **`dnp3-malformed` and its PRP pair, `dnp3-malformed-prp-a` and `dnp3-malformed-prp-ab`** (`prp-derived.sha256`; D6's P2.5 on `542a42cf`). Section 4.3 reruns both. They are judged per flow, by the rule of the last bullet of "What does not change". In stage 2, D6 labels from the bytes which of their flows hold a fragment whose code disagrees with its side: tshark, with Zeek's sides taken from `conn.log`;
- **every other capture that section 4.3 reruns** (D6's N3 on `be6b8cea`): the GT-PCAP DNP3 cases, the other PRP pairs (`dnp3-digitalbond-part1` and `-part2` among them, `prp-derived.sha256`), the public captures and E2's corpus rows. Stage 2 sorts the DNP3 flows of every rerun capture the same way, by tshark's codes with Zeek's sides from `conn.log`. A flow on which every fragment's code agrees with its side falls under the last bullet of "What does not change". A flow on which any fragment's code disagrees with its side is pinned by the twin rule.

**What depends on the rewritten generated code** (D6's P1 on `542a42cf`). These rows are `unknown` for C2 against C1p, and the run pins them. A difference on one of them is reported, and judged against section 4.3's bounds and its control for each judgement. It is not called a regression by the last sentence of this section.
1. **Whether a `link` row is written for a header that binpac holds when its fragment then fails or never completes.** At a fragment's first frame, `ProcessData` hands the 8 header octets to `interp->NewData` before three checks: the length-0 weird, `AddToBuffer`'s target check, and any chunk CRC (`DNP3.cc`). When `dnp3_header_block` is raised for that held header depends on generated code that the patch rewrites (section 4.1; section 5.1). The inputs are:
   - section 4.1's list: the Service rows of (3a) and (3c), a bad chunk CRC, and a fragment without FIR;
   - link lengths 0 to 4 (section 4.3);
   - a fragment without FIN, and one over `DNP3::max_application_layer_fragment_size`.

   **On TCP the held header may be parsed again when the connection ends.** `DiscardFlowBuffer` runs only on a `binpac::Exception`, and `DNP3_TCP_Analyzer::EndpointEOF` and `Done` call `FlowEOF`. `DNP3_UDP_Analyzer` defines neither, so on UDP nothing calls `FlowEOF` at the end. Two more facts hold on TCP (D6's N1 and D3's B1 on `be6b8cea`, `desk`):
   - **Neither call checks `skip`.** `TCPSessionAdapter::EndpointEOF` calls each child's `EndpointEOF` without checking it, and `DNP3_TCP_Analyzer::Done` calls `FlowEOF(true)` and `FlowEOF(false)` after `TCP_ApplicationAnalyzer::Done`, whatever `skip` is. So data held on either side goes back to binpac's parser when the connection ends, even after the analyzer has stopped. A weird that sets `skip` after a good header (a bad chunk CRC, for one) leaves that header held, since `ProcessData` returns false and `DiscardFlowBuffer` does not run. A flow whose `NewData` threw is called again too, with its buffer discarded.
   - **Neither call is inside a `binpac::Exception` catch.** Zeek catches it only in `Analyzer::NextPacket`, `NextStream` and `NextUndelivered` (`Analyzer.cc`); `DNP3.cc`'s `DeliverStream` and `DeliverPacket` catch it only to discard the flow buffer, set `skip` and rethrow. The generated `NewData` rethrows (`FlowDecl::GenProcessFunc`, `pac_flow.cc`), and the flow's `FlowEOF` marks the buffer's end and calls `NewData(nullptr, nullptr)` (`FlowDecl::GenEOFFunc`). D6 and D4 found no catch on the way up in `Conn.cc`, `session/Manager.cc`, `packet_analysis/Manager.cc`, `RunState.cc` or `main.cc` (whose one `catch` is around setup). The frames in between, the timer and I/O-loop code that call `Done` and deliver segments, were not read. So whether a throw there ends the Zeek process, which would blind every flow at the site, is `unknown`. Section 4.3's TCP inputs that end while a header is held measure it, and a crash there is a finding by section 4.3's rule, not a row of this list.

   Under C0 and C1p, D3's reading is that the end-of-connection call parses nothing on a held, incomplete frame (section 4.3). Under C2 the patch rewrites the unit that requests the frame, so it is `unknown`.
2. **The unit's frame length.** `DNP3_Request` and `DNP3_Response` carry `&length = 9 + addin_header.len - 5 - 1`. A link length of 4 gives 7, below the 8-octet header, and a length of 6 gives 9. At FIN both hand binpac only the 8-octet header, and they differ only in the length field that `&length` reads. So the value of `&length` decides them, and decides a fragment of 0 or 1 application octets. It also decides every fragment longer than its first frame.
   - **Every single-frame fragment reaches binpac one octet short of `&length`** (D2's N1 on `be6b8cea`, the shortfall of D2's B2 on `b677547a`). For a link length L, `NewData` gets the 8 header octets and `ParseAppLayer` buffers L − 6 application octets, so binpac gets L + 2, while `&length` is L + 3. So the restructured unit's frame buffering at `FinishBuffer` is on the path of every fragment, not only of the rows below. The check on paper below must therefore cover the frame-buffering path for all fragments.
   - **The conforming rows stay under "What (i) does not change",** where a difference is a regression: a conforming fragment that stops parsing under C2 is a broken fix.

   The rows of this list are:
   - a link length of 4 with FIR and FIN, a length of 6, and a fragment of 0 or 1 application octets (sections 2.3 and 4.3);
   - every multi-frame fragment, in any case, rerun or capture. Their rows are still expected equal to C1p's, but as this list's `unknown`, not as "does not change".

- **A constraint on the patch.** The patched unit keeps `Header_Block` as its first field, and keeps `&length = 9 + addin_header.len - 5 - 1` as the unit's length for both arms, computed from the same `Header_Block` field. That makes the expectations above likelier. It does not make them `desk`.
- **A check on paper once both builds exist:** diff the parser that binpac generates from `dnp3.pac` in C1p's build against C2's. Where the diff leaves the header's, the length's and the frame buffering's code unchanged, the rows above are expected equal. The diff's result is `desk`, and the run still pins them.
  - **Both builds generate the parser with the binpac inside the pinned tarball** (`tools/binpac/`), never with a binpac from the base system (D7's N1 on `be6b8cea`). Otherwise the diff could show a difference in the generator rather than the patch. Zeek 9.0.1's `configure` parses no `--with-binpac`, although its help text mentions one (D7), so the configure line alone does not show which binpac ran.
  - **The run records the SHA-256 of each build's generated `dnp3_pac.cc` and `dnp3_pac.h` beside the diff,** so that the result can be checked again later.

**What (i) does not change, under any configuration.** C2 is expected to equal C1p on:
- the magic, header CRC and chunk CRC checks, and their weirds and violations;
- the 11-octet header stage, the link-only silent loss, and a length of 5 with trailing bytes (section 1 item 4; section 5.1);
- the weirds, the reporter errors and `skip` of link lengths 0 to 4, of a fragment without FIR, and of the fragment-size limit, which `ProcessData`, `AddToBuffer` and `ParseAppLayer` raise. Their `link` rows, and the result of a length of 4 with FIR and FIN, are in the list above;
- classes (1), (2), (3b-link), (4) and (5) of the false-positive set, and (3a)'s weird and `skip`. (3a)'s Service rows are in the list above;
- `dpd.zeek`'s 10 KiB bound;
- **every flow on which each fragment's code agrees with its side, judged per flow, not per case** (D6's P2.3 on `542a42cf`). That covers every flow of the GT-PCAP DNP3 cases that the master starts, over TCP and over UDP; the first flow of `dnp3-udp-temp-port`, but not its second, which the relay starts; and every flow of the PRP pairs, the public captures and E2's corpus rows by the same rule. Their multi-frame fragments are in the list above.

A difference on any of these is a regression, or a difference in the build when C1p differs from C1 as well (section 4.1).

## 5. Limits, and HR-25's candidate fix

### 5.1 Limits

- Everything above is `desk`. Statements about IEEE 1815 are `inference`. The ports that relays and masters use are `inference` until H-23 (D2).
- **Option (i) changes DNP3 over TCP too** (section 2.3). A relay that opens a TCP connection is the same question as over UDP, and section 4.3's TCP cases measure it.
- **Not read:**
  - when binpac raises `dnp3_header_block` for a fragment that then fails;
  - the code binpac generates at all, the record-level `&length` included;
  - whether binpac 9.0.1's generated flow can safely be reused after a `binpac::Exception`. **On UDP** Zeek never reuses it today, because `skip` ends the flow (D3's condition 2 on `9919fd24`). **On TCP it does:** `EndpointEOF` and `Done` call `FlowEOF` whatever `skip` is, outside any `binpac::Exception` catch, and that includes a flow whose `NewData` threw, with its buffer discarded (section 4.7, item 1; D3's B1 and D6's N1 on `be6b8cea`);
  - whether anything above `Done` and `EndpointEOF` catches a throw from that end-of-connection parse (section 4.7, item 1).

  A Zeek build makes that code. `dnp3-udp-master-short` and the run show its effect.
- **HR-25: one failed frame stops the analyzer for the whole flow,** under the control and under (i), whatever key picks the parser (D4 6865038018; D1 6865138996, point 1). `DNP3_UDP_Analyzer::DeliverPacket` and `DNP3_TCP_Analyzer::DeliverStream` set `skip` on a bad header or chunk CRC, a lost magic, a lost first chunk, or a fragment too short for its parser (section 1, item 6). `Reporter::AnalyzerError` sets `skip` itself (`Reporter.cc`). So one bad datagram stops the analyzer, and a later write goes unseen. On UDP it takes no role in the session: any host on the segment can send it with the flow's addresses and ports (D3). D3 writes HR-25's row. Its candidate fix is briefed as P4-4-HR25 (section 5.2).
- **A link-only frame silently drops the next delivery from the same end** (D6's B2 on `9919fd24`; `desk`, unmeasured). The header stage waits for 11 octets, and a link-only frame is 10 (section 1, item 4). So the first octet of that end's next delivery completes the check, and `ProcessData` then drops the rest of the delivery.
  - **On UDP,** the next datagram from that end is lost, with no weird and no violation, and the flow stays named. Any sender can hide its next datagram, a write included, behind one link-only frame.
  - **On TCP,** the rest of the segment is lost. A frame split across segments then starts without its magic, which sets `skip`.
  - **TCP heartbeats.** S22 documents a TCP heartbeat after `DNPINAn` seconds of inactivity, 120 by default. D2's inference is that it is a link-status request answered by a link status (D2's table, `docs/phase4/D6-engine-run-pass-conditions.md` §7). Both are 10 octets. By that reading, after each heartbeat exchange the master's next request is lost, and so is the relay's next response.
  - **It holds under C0, C1, C1p and (i) alike.** No run has shown it, because no GT-PCAP capture holds a link-only frame.
  - D3 adds it to HR-25's row (D1 6866095230, point 2).
- **Reassembly is per end of the flow, not per pair of link addresses** (D2's Q2). A dual-role end that interleaves the multi-frame fragments of two associations would break Zeek's reassembly. This note does not introduce it.
- **Whether an outstation acts on a request whose DIR is clear** is `unknown`, for SEL and for IEEE 1815 (D2 on `9919fd24`). No held SEL manual describes the receive check on DIR. D2 proposes an H-row, written and not run (section 6).
- **The `.asc` check** rests on a key from one channel, and on a SHA-1 digest (opening section).
- **The 10 KiB bound of `dpd.zeek`** (section 1, item 6).

### 5.2 HR-25's candidate fix

HR-25's candidate fix: see P4-4-HR25. Not part of HR-23's fix (D1 6866534402). The resync design this section held is citable at `52c7592c` (`docs/phase4/D4-hr23-design.md`, section 5.2). P4-4-HR25 takes it as a required input, with the reviews' open findings on it: D2's B1, N1 and N2 (6866220392); D3's B4, B5 and N6 to N9 (6866236602); and D6's B1 (a) to (c) and the resync parts of B2 (6866520537).

## 6. Risk records and open items, for D1

These are D1's to record. The note does not close them.

- **R-1. The attacker-caused both-ends outcome** (D3's N3, D6's N5; ruling 2). One datagram of the opposite DIR names a false second server on a flow. In production that must fail closed: the flow counts as `undecoded`, or takes a cause of its own in D4-90's closed set, and is never a quiet DNP3 flow. That mapping may need C13 text, so it is settled in comments first (D4-99). `undecoded` is not yet a ready path, because its first-sight key needs a server address (C13 0.1 §4.2, "The key of a first sight"; D6's N5).
- **R-2, now HR-25. One failed frame blinds the analyzer for the flow** (section 5.1). D1 made it a high risk of its own, HR-25, open, which D3 writes (6865138996, point 1). D1 decides with the owner whether it blocks item 4's gate. Its candidate fix is P4-4-HR25 (section 5.2). D3's HR-25 row also gains D6's two further triggers: one bad header before confirmation, and a TCP content gap (D1 6866534402).
- **The link-only silent loss** (section 5.1): D3 adds it to HR-25's row on #677 (D1 6866095230, point 2).
- **R-6. Two H-rows, written and not run** (D2 on `9919fd24`; D3). D1 numbers them with the stage-2 brief, together with #671's two (6866203475, point 3):
  - send the SEL-751 one read with DIR clear, to show whether it acts on it;
  - show what an SEL device's link layer does after a bad CRC on TCP, which P4-4-HR25's scan would match.

  Each runs only with the owner's authorization for device contact, like every H-test. Two terms for OT safety (D6's N6 on `52c7592c`):
  - each row runs on a bench unit that is out of service;
  - the DIR-clear frame, and every frame sent after a bad CRC, carry only a read (code 1), never a write, operate, restart or time set.
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
| D2 Q2: reassembly per end, not per link-address pair | risk | Section 5.1 |
| D2 Q3: say which key (i) uses; add DIR against the code | non-blocking | Section 2.3; section 4.3 (rulings 1, 3) |
| D2 Q3 and D3 B1: TCP changes under (i) | non-blocking and blocking | Sections 2.3, 4.3 and 5.1 (ruling 4) |
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
| D7 N4: cite D7's signature check, with its limits | non-blocking | Opening section; section 5.1 |
| D7 N5: a second channel for the key | risk | Section 6, R-3 |
| D7 N6: rollback floor, rework, registry push | risk | Section 6, R-4 |
| D7 answers 1 and 3: pin every input; hold the public key | answer | Section 4.5 |
| **Re-reviews of `9919fd24`** | | |
| D7 M1: the three path placeholders in section 4.5 | non-blocking | Section 4.5 (D1 6865138996, point 3) |
| D7 M2: the key's second source is other than `keys.openpgp.org` | non-blocking | Section 4.5; section 6, R-3 |
| D2 N1: code 5 is a direct operate, and a write is code 2 | non-blocking | Sections 4.2 and 4.3 |
| D2: does an outstation act on a request whose DIR is clear (`unknown`) | answer | Section 5.1; section 6, R-6 |
| D2: the resync's conditions (violation path, reset, noise, cases) | design | P4-4-HR25 (section 5.2; the design at `52c7592c`) |
| D3 N5: which end opens the TCP connection, and its expected results | non-blocking | Sections 4.2 (`dnp3-tcp-dir-spoof`) and 4.3 |
| D3: the resync's conditions 1 to 5 | design | P4-4-HR25 (section 5.2; the design at `52c7592c`) |
| D6 B1: the TCP cases do not all reach the changed path; the two TCP ids | blocking | Sections 4.1, 4.2 and 4.3 (D1 6866095230, point 1) |
| D6 B2: the header is checked only at 11 octets | blocking | Section 1 item 4; section 3 item 6; sections 4.1 and 4.3 (D1 6866095230, point 2) |
| D6 B2: the link-only silent loss | risk | Section 5.1; section 6; HR-25 by D3 |
| D6 B3: the coverage condition, the inputs' route, equal harness | blocking | Section 4.6 (D1 6866095230, point 3) |
| D6 N1: the control for each judgement | non-blocking | Section 4.3 |
| D6 N2: D1's ids, paths and HR-25 written in | non-blocking | Sections 4.1, 4.2, 4.5 and 6 |
| D6 N3: class (4)'s zero by construction | non-blocking | Section 4.3 |
| D6 N4: everything is rerun, with no exemption | non-blocking | Section 4.3 |
| D6: the resync's items 1 to 6 and its cases | design | P4-4-HR25 (section 5.2; the design at `52c7592c`) |
| D1 6865138996, point 1: HR-25's candidate fix | design | P4-4-HR25 (section 5.2; D1 6866534402) |
| **Re-reviews of `52c7592c`** | | |
| D7 6866209008: pass, no findings | answer | — |
| D2 B1, N1 and N2: the resync's UDP rule, lengths 0 to 4, an embedded frame behind a failed header | design | P4-4-HR25 (section 5.2; D1 6866534402) |
| D2 N1, as it applies to (i): lengths 0 to 4 as a failed header | non-blocking | Section 4.3 (D1 6866534402, point 2) |
| D3 B4, B5 and N6 to N9 (6866236602): the resync design | design | P4-4-HR25 (section 5.2) |
| D6 B1 (a) to (c): blinding routes before confirmation, at a TCP gap, and a link-only frame inside a fragment | design and risk | P4-4-HR25 (section 5.2); (a) and (b) go into HR-25's row by D3 (section 6) |
| D6 B2: the resync's names, and its changed expectations | design | P4-4-HR25 (section 5.2) |
| D6 B2, as far as (i) changes them: the complete list of changed expectations | blocking for pinning | Section 4.7 |
| D6 N1: the TCP SYN-ACK swap and DPD attachment | non-blocking | Section 4.1 |
| D6 N2: class (4), keeping the ID, NSCOUNT | non-blocking | Section 4.3 |
| D6 N3: link lengths 0 to 4 | non-blocking | Section 4.3 |
| D6 N4: reporter errors that are expected by design | non-blocking | Section 4.3 |
| D6 N5: the disclosure rule's limit | non-blocking | Section 4.6 |
| D6 N6: OT safety terms for R-6's H-rows | non-blocking | Section 6, R-6 |
| D6 N7: D1's 6866203475, and ids that name their transport | non-blocking | Section 4 (opening); section 6, R-6; the `dnp3-resync-*` ids and the count's C13 path go to P4-4-HR25 |
| D1 6866534402, point 3: case ids name their transport | ruling | Section 4 (opening) |
| **D6's re-review of `542a42cf` (6866817721)** | | |
| D6 P1: (i) also rewrites the unit's generated code; the `link` row of a held header, and `&length` | blocking for pinning | Section 4.7, opening and "What depends on the rewritten generated code" (its list, the constraint on the patch, the check on paper) |
| D6 P2.1: the twin rule in place of per-arm results | blocking for pinning | Section 4.7, "What changes by the code rule" |
| D6 P2.2: both directions; relay-started flows depend on the response parser | blocking for pinning | Section 4.7, "Both directions" |
| D6 P2.3: `dnp3-udp-temp-port`'s second flow; judged per flow | blocking for pinning | Section 4.7, "Where it shows" and the last bullet of "What (i) does not change" |
| D6 P2.4: (3b-data) beside (3c) | blocking for pinning | Section 4.7, "Where it shows" |
| D6 P2.5: `dnp3-malformed` and its PRP pair | blocking for pinning | Section 4.7, "Where it shows" |
| D6 N-A: the TCP case's control for attachment and replay | non-blocking | Section 4.1 |
| **Re-reviews of `be6b8cea`, under D1's ruling 6879529451** | | |
| D3 B1 and D6 N1: the TCP end-of-connection parse runs outside the analyzer's `binpac::Exception` catch, unmeasured (item 1) | blocking | Section 4.3, the TCP inputs that leave a header held; section 4.7 item 1; section 5.1; section 1 item 6; section 4.6, which end-of-connection path the `dnp3_tcp` target reaches, and what the run leaves unshown; the opening table |
| D6 N2: the third input of "Both directions"; relay-started flows also depend on the request parser (item 2) | non-blocking | Section 4.7, "Both directions" |
| D6 N3: the per-flow sort covers every rerun capture (item 3) | non-blocking | Section 4.7, "Where it shows" |
| D6 N4 (a): section 2.3's fragment of 0 or 1 octets (item 4) | non-blocking | Section 2.3 |
| D6 N4 (b): the twin rule covers binpac's result only (item 4) | non-blocking | Section 4.7, "The twin rule" |
| D2 N1: every single-frame fragment reaches binpac one octet short of `&length` (item 5) | non-blocking | Section 4.7 item 2, and the check on paper |
| D2 N2: lengths 0 to 4 are "the same" only in weirds, reporter errors and `skip` (item 6) | non-blocking | Section 4.3 |
| D7 N1: the tarball's binpac for both builds; the generated files' SHA-256 (item 7) | non-blocking | Section 4.7, the check on paper |
| D3 N1: C1p parses nothing at the end on a held, incomplete frame | note | Sections 4.3 and 4.7 item 1, as D3's reading |
| **After D6's acceptance of `48a66afe` (6879672391)** | | |
| D2's note 6879662396: under C1p, a master's 2- or 3-octet request throws in the response header | non-blocking | Section 4.7, "Both directions" |
| D6's B1 on #677 (6879737166), as D1's ruling 6879752967 item 4 applies it: the third unswapped arrangement, and an attacker's trigger | blocking | Section 1 item 2; section 4.1, "The port arrangement" |
