# D6: pass conditions for the engine run E-D4-03 (P4-4-R1, for P4-4-S2)

D6, 2026-11-11. Brief P4-4-S2 runs candidate engines offline over GT-PCAP and judges its table by pass conditions that D6 commits before the counted run (`docs/agent-handoffs.md`, "Phase 4 item 4, second part"). This note is those conditions.

- **Evidence class: `desk`.** Nothing here was run against an engine. No engine's output, log format or documentation was read to write it.
- **Where the conditions come from:** GT-PCAP's label files, which the pinned tshark 4.2.2 writes (`tests/fixtures/network/gt-pcap/dnp3/`, `tests/integration/gt_pcap/gtlabel.py`); V-M6 and R6.1 in `docs/verification.md`; C13 §4 and §11 (`docs/phase4/D4-c13-netobs.md`); and ADR-0009's protocol points 2 and 3.
- **The per-capture list is a file:** `tests/integration/gt_pcap/engine-pass-conditions.tsv`, 103 rows. `engine_conditions.py` derives it from the committed labels and from nothing else, and `test_engine_conditions.py` fails if the two differ. So a label change moves the conditions with it, in the same reviewed PR, and a condition can't be edited by hand after a run.
- **This is evidence for the engine choice, not V-M6.** V-M6 runs on the real sensor, over the real link, with the checker of P4-4-R1. Nothing in this note changes how any criterion in `docs/verification.md` is measured.

## 1. What "the engine shows" means

These rules hold for every condition below.

1. **Only the engine's own log files count,** as written by the run for that capture and that configuration. Console text, a summary the experiment's script computes, and a value inferred from the port do not count.
2. **A record is tied to a flow** when it carries the flow's transport and both of its (address, port) ends, itself or through an identifier that the engine's connection record resolves to them. A record that names DNP3 and no flow is not tied.
3. **Each row is `pass`, `fail` or `unknown`.** A capture or configuration that did not run is `unknown`, never `pass` (P4-4-S2, deliverable 2). The table cites the log line that makes a row pass.
4. **A column passes for one engine configuration only when every row of it passes.** The table gives n of m beside it. What a failed column means for the engine choice is D1's decision (ADR-0009, "What would turn the choice").
5. **Each configuration is judged alone:** stock, and with the ICSNPP packages; Suricata with and without `stream.midstream=true`. A pass in one is not carried to another.
6. **Extras are listed.** A DNP3 request function that the engine reports and no label row holds is listed beside the capture. It does not fail a row. It is what precision will count on the real sensor.
7. **A name counts as a function code** only when the engine's own source or documentation maps it to exactly one code. The table says which mapping it used.

## 2. The conditions, by column of P4-4-S2's table

Each `condition` value of the TSV is one column.

| Column | TSV rows | A row passes when |
| --- | --- | --- |
| **Protocol** | `protocol`, one per labelled `flow` (25) | the engine has one flow record with the row's transport and both ends, and it names the flow's protocol as DNP3. For TCP, the record's originator is the row's `src`, which sent the SYN. For UDP the label's direction is `none` (C13 §4.1), so either orientation passes, and the table states which one the engine chose. Two records for one labelled flow fail the row. |
| **Service** | `service`, one per labelled service (21) | DNP3 is attributed to the server end the row names: the address, the transport and the port. On `dnp3-udp` the server is 192.0.2.20, the receiver of the first datagram. |
| **Function** | `function`, one per labelled `function` (50) | a record tied to the row's flow shows the row's function code, as a request from the row's `src`. A response's code (129, 130, 131) is not a function, and an engine that shows only responses fails the row. |
| **Objects** (reported beside Function) | the `objects` cell of the same rows | every object header in the cell is shown with its group and variation, in a record tied to the flow. `?` cells are skipped: tshark 4.2.2 dissects no object header there. This column does not decide Function. It is reported because C13's `function.objects` and the node's `time-sync` class need it: on `dnp3-train`, function 2 carries g80v1 on one row and g50v1 on another, and only the objects tell them apart. An engine that fails it leaves that decoding to sensor code, and the table says so. |
| **Group 120 per session** | `g120`, one per `function` row of the five `dnp3-sa` captures (7) | the message in the row's `show` cell is shown **as a message of its own**: a record tied to the flow that carries the function code, the sender and the group 120 object with its variation. The five captures need four distinct messages: `131:g120v1` from the outstation (a challenge), `5:g120v3` from the master (aggressive mode), `131:g120v7` from the outstation and `33:g120v7` from the master (the error, from either end). For the row whose `sa` is `none`, the engine must show the read and its response with no group 120 object between them, in the same session that holds the challenged and the aggressive operate. |
| **Moved port** | every row of `dnp3-moved-port` (4) | Protocol, Service and Function all pass on it **while the engine has not been told the port**. See section 3. |
| **UDP** | every row of `dnp3-udp` (4) | Protocol, Service and Function all pass on it, and the flow is recorded once, as UDP. Both ends are on port 20000, as a relay with `DNPUDPn` at its default answers (S22 Table D.7, p. D.11), so the ports don't say which end is the server. |

**Why group 120 is asked per message and not per connection.** C13's `sa` is a fact about one exchange (§4.3), and the node sets `dnp3_no_sa` from it for one request. `dnp3-sa` holds, in one connection, a read with no SA, a challenged operate and an aggressive-mode operate. An engine that reports "this connection carried group 120" can't say which request was challenged, so it can't show an unchallenged operate that follows a challenged one, which is the downgrade C13 §4.2 keeps apart. The variation is needed because a challenge (v1) and an error (v7) are different outcomes, and the sender because `sa_error_from` records it. A weaker result is written as `fail (group only)` or `fail (no sender)`, so D1 sees how far the engine got.

**Group 120 bodies are filler** (plan §2B, D2 on #542). The project holds no SA specification and no real SA capture, so each object's group, variation and qualifier are real and its body is not. An engine that drops such a message as malformed, and shows no object for it, is written `fail (filler body refused)`. That is not a pass. It is also not evidence that the engine fails on real SA traffic, and the table says both.

## 3. The moved port

`dnp3-moved-port` holds DNP3 between M1 and a second relay, O2 (192.0.2.21), whose `DNPNUM` is 20001. No frame in it uses port 20000.

- **The engine must find DNP3 by content.** The row fails as `fail (told the port)` if the configuration under test names 20001 anywhere: a port list, a decode-as setting, a signature or a script that keys on it. Content detection that is on for every port is allowed, and the table says which setting enabled it.
- **Why:** V-M6 asks for every labelled service to be recorded, a relay's port is a setting (`DNPNUM`, 1 to 65534), and C13 §11 fails a `service` found by port alone on these rows. A sensor that must be told each relay's port sees nothing of a port nobody told it about.
- **GT-PCAP's own labeller is told the port,** with tshark's `-d tcp.port==20001,dnp3`, and the label file's header says so. That is the plan's rule: a label comes from the asset table's settings (§2B). It is not a condition the engine may borrow.
- **Modbus on a moved port has no GT-PCAP capture.** P4-4-R1 asked for the two DNP3 cases. ADR-0009 also names Modbus on a moved port, so that row of P4-4-S2's table is `unknown` until a capture and its label exist (plan §2B's Modbus rows are not built).

## 4. Per capture

The TSV holds each row with its addresses, ports, code, objects and frames. In short:

| Capture | Flows to name DNP3 | Service | Request function codes | Group 120, per message |
| --- | --- | --- | --- | --- |
| `dnp3-authorized-operate` | 1 | 192.0.2.20 tcp/20000 | 5 | not asked |
| `dnp3-authorized-time-sync` | 1 | 192.0.2.20 tcp/20000 | 2 | not asked |
| `dnp3-heldout` | 3 | 192.0.2.20 tcp/20000 | 1 (3 flows), 2 (3 rows), 5, 20 (2 flows), 22 (2 flows) | not asked |
| `dnp3-known-master-new-port` | 1 | 192.0.2.20 tcp/20000 | 1 | not asked |
| `dnp3-moved-port` | 1 | 192.0.2.21 tcp/20001 | 1, 5 | not asked |
| `dnp3-new-master` | 1 | 192.0.2.20 tcp/20000 | 1 | not asked |
| `dnp3-reader-disable-unsolicited` | 1 | 192.0.2.20 tcp/20000 | 21 | not asked |
| `dnp3-reader-time-sync` | 1 | 192.0.2.20 tcp/20000 | 2 | not asked |
| `dnp3-reconnect-learned` | 1 | 192.0.2.20 tcp/20000 | 2, 20, 22 | not asked |
| `dnp3-reconnect-unlearned` | 1 | 192.0.2.20 tcp/20000 | 2, 20, 22 | not asked |
| `dnp3-response-new-group` | 1 | 192.0.2.20 tcp/20000 | 1 | not asked |
| `dnp3-reused-seq` | 1 | 192.0.2.20 tcp/20000 | 5 (2 rows) | not asked |
| `dnp3-sa` | 1 | 192.0.2.20 tcp/20000 | 1, 5 (2 rows) | none in the read's exchange; `131:g120v1` from 192.0.2.20; `5:g120v3` from 192.0.2.10 |
| `dnp3-sa-failed-before-ack` | 1 | 192.0.2.20 tcp/20000 | 5 | `131:g120v7` from 192.0.2.20 |
| `dnp3-sa-failed-master` | 1 | 192.0.2.20 tcp/20000 | 5 | `33:g120v7` from 192.0.2.10 |
| `dnp3-sa-failed-outstation` | 1 | 192.0.2.20 tcp/20000 | 5 | `131:g120v7` from 192.0.2.20 |
| `dnp3-sa-failed-unauthorized` | 1 | 192.0.2.20 tcp/20000 | 5 | `131:g120v7` from 192.0.2.20 |
| `dnp3-train` | 3 | 192.0.2.20 tcp/20000 | 1 (3 flows), 2 (3 rows), 5, 20 (2 flows), 22 (2 flows) | not asked |
| `dnp3-udp` | 1 | 192.0.2.20 udp/20000 | 1, 5 | not asked |
| `dnp3-unauthorized-operate` | 1 | 192.0.2.20 tcp/20000 | 5 | not asked |
| `dnp3-unauthorized-operate-no-response` | 1 | 192.0.2.20 tcp/20000 | 5 | not asked |

That is 19 labelled cases and the two R6.2 series. Notes on single rows:

- **`dnp3-reused-seq`** holds two operates with one application sequence number, the first unanswered. Both requests must be shown. An engine that shows one fails a Function row.
- **`dnp3-unauthorized-operate-no-response`** holds a request with no response. An engine that logs a function only when it has paired a response fails its Function row, and the same engine would miss an operate whose response a SPAN port dropped.
- **`dnp3-sa-failed-before-ack`** has the same frames as `dnp3-sa-failed-outstation` at a later time. They differ only in the node's state at replay, so an engine gives the same result on both.
- **The series** are an hour each. A `function` row is the first occurrence of its (flow, code, objects), so a code shown once on the flow passes the row.

## 5. The nine PRP pairs

The pairs are the stems in `tests/fixtures/network/gt-pcap/prp-derived.sha256`: `dnp3-read`, `dnp3-write`, `dnp3-select-operate`, `dnp3-malformed`, `dnp3-digitalbond-part1`, `dnp3-digitalbond-part2`, `modbus`, `modbus-digitalbond-part1` and `modbus-digitalbond-part2`. Their labels are written in the run by `prp_check.py` with the pinned tshark, and are not committed, because the public sources state no redistribution terms.

A pair passes for one engine configuration when all four hold. These are ADR-0009's PRP condition as E-D4-02 checked it (`modules/telemetry/experiments/prp-engines/compare.py`), unchanged:

1. **Once:** each flow has as many records on `<stem>-prp-ab.pcap`, which holds both LAN copies, as on `<stem>-prp-a.pcap`, which holds LAN A only.
2. **Packets:** each flow's packet total on `-ab` equals its total on `-a`.
3. **Service:** each flow's protocol on `-ab` equals its protocol on `-a`.
4. **Labels:** every labelled flow is in the `-a` output, with the label's packet count. A flow that both runs drop does not pass.

`bytes` is not compared. The label counts link-layer octets with the 6-octet RCT, and an engine may count another layer.

**The result on a stock engine is already known:** Suricata 7.0.3 and Zeek 8.0.4 each count both copies (E-D4-02, run 42407918524). So a stock engine is expected to fail condition 2, and the requirement for a discard stage before the engine stands (ADR-0009). If the run puts such a stage in front of the engine, the table names it and its version, and states the pair's result with and without it.

## 6. What has no pass condition

P4-4-S2's table also reports what each engine logs of SNMPv3's header fields and of Telnet, FTP and HTTP. GT-PCAP holds no labelled capture of those yet (plan §2B's live-recorded rows are not built), so those rows are reports with no pass or fail. The public captures have no committed label file: their only labels are the PRP flow labels of section 5, so this note sets no other condition on them.

## 7. Limits

- The two new label files, `dnp3-moved-port.tsv` and `dnp3-udp.tsv`, are `desk` until D4 (labels) and D2 (protocol reading) review them, as every label is.
- Every capture is synthesized. A pass says the engine decodes these frames from a file. It says nothing about live capture on a SPAN or TAP port, about a hosted runner standing in for the sensor host, or about a real relay's traffic.
- One DNP3 link frame per TCP segment or UDP datagram, and one transport segment per fragment. No capture here splits a link frame across TCP segments, puts two in one segment, or fragments an application message. An engine that passes has not been shown on those.
- IEEE 1815 is not held. Function codes and object names follow S23 Table 2.30 and tshark's dissector.
