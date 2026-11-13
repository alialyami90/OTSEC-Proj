# D6: pass conditions for the Modbus/TCP content signature (P4-4-E2)

D6, 2026-11-13. D1's ruling on #637 adopts a Modbus/TCP content signature in the project's script only on a measurement: its detection on `modbus-moved-port` and its false-positive rate on a corpus with more non-Modbus binary traffic than GT-PCAP holds (D1's comment 6806312738; D4-90). Brief P4-4-E2 (`docs/agent-handoffs.md`, "After D4-90") has D6 set the pass conditions before D4's counted run, pinned by hash, as E-D4-03's were. This note explains them.

- **The conditions are a file:** `tests/integration/gt_pcap/modbus-signature-conditions.tsv`, 37 rows, SHA-256 `7b242b85a3387c3f591eb21cce2e3f036feb8c1c8799e02857548a2e5f6f4418` (LF line endings, as Git stores it). **The file decides, and this note does not:** every rule that turns a result into `pass`, `fail` or `unknown`, and every threshold, is a row of it. `test_modbus_signature_conditions.py` pins that hash and fails on any edit, and checks that the file's detection rows are exactly the Modbus rows of `engine-pass-conditions.tsv`.
- **The run's pin is D4's to add.** It belongs in `modules/telemetry/experiments/engine-linux/pins.env`, beside `CONDITIONS_SHA256`, as `MODBUS_SIGNATURE_CONDITIONS_SHA256=7b242b85a3387c3f591eb21cce2e3f036feb8c1c8799e02857548a2e5f6f4418`. D6 does not edit D4's files; D4's P4-4-E2 PR adds the line, and a run whose file differs from it is a rehearsal (row `judge-counted`).
- **Evidence class: `desk`.** No signature exists, and no engine ran for this note. No engine output over any corpus was read: none exists. What the note says of Zeek's code comes from its source at `v9.0.1`, read through GitHub's API (section 2).
- **Inputs:** D1's ruling on #637; D2's notes 3 and 4 on `c794efb3`, and findings A to C and G on `53554116`; D6's review of `c794efb3` (N7) and its reading of the residual; `docs/phase4/D6-engine-run-pass-conditions.md`, whose rules 1 to 9 and section 3 these rows reuse; C13 §11; `fc-classes/1`; `docs/phase4/D4-engine-linux-eval.md` §5.
- **This is evidence for adopting the signature, not V-M6.** V-M6 runs on the real sensor over the real link.

## 1. What the run must show, and why

| Rows | What they ask | Why |
| --- | --- | --- |
| `cfg-sig`, `cfg-base`, `cfg-alone` | S0 is the approved script with the signature, and with the redef if the script carries it. S1, the approved script without them, runs in the same run. S2, the signature without the redef, runs too when S0 has the redef, and decides nothing. | The regression and the controls compare S0 with S1 in one run, so they still hold if `engine-pass-conditions.tsv` gains rows before this run (P4-D6-GT2 may add some). The run records each script's hash, and an adoption names them. |
| `judge-port`, `judge-named`, `judge-verdict`, `judge-counted`, `judge-seen` | Rule 8, widened to the corpus and to values learned from a capture; what "named Modbus" means; `unknown` is never `pass`; the counted run; earlier runs of S0 over the corpus. | "Named Modbus" counts any record that names Modbus, conn.log's `service`, `modbus.log` and the script's own log, and never reads `analyzer.log`, because with the redef a violation writes nothing there (section 3). A capture the engine did not decode is in no count, which is E-D4-03's lesson: an undecoded file must not read as a negative result. |
| `det-protocol`, `det-service`, `det-function` | `modbus-moved-port`'s three rows of `engine-pass-conditions.tsv` pass under S0. | D1's ruling names them. The rows, and their rule that a configuration told the port fails, are unchanged. |
| `ctl-502`, `ctl-baseline` | S0 passes the same three rows on `modbus.pcap` on port 502; S1 fails them on 15020 in the same run. | The first is the control of `D6-engine-run-pass-conditions.md` section 3. The second shows it is the signature that finds Modbus on 15020: if S1 passes too, the three rows say nothing about the signature, and read `unknown`. |
| `reg-rows` | Every row S1 passes, S0 passes. At the current pin that is 110 of 110. | A Modbus signature must not cost a DNP3 row. |
| `held-502`, `held-other`, `held-count` | The corpus's Modbus flows, moved off 502 by `movedport.py` and labelled by `modbus_label.py` in the run, pass wherever their control on 502 passes; at least 5 count, from at least 2 captures other than `modbus.pcap`. A flow with no client SYN whose first frame is the server's is listed as `(roles not recoverable off 502)`, judged on its protocol row only, and not counted. | `modbus-moved-port` is one midstream conversation with one function and one unit, and whoever writes the signature can see it. A pass on it alone is close to a result on the case it was written against. D4's §5.6 and D6's N7 on #637 both asked for held-out Modbus. **The exception is D2's B1 on #642.** With no SYN, Zeek swaps the two ends only when the first sender's port is a likely server port (`TCP.cc` l.55 to l.70 at `v9.0.1`, SHA-256 `585e70b6…`). Ports registered to an analyzer join that set (`analyzer/main.zeek` l.256 and l.257, `55e4809d…`). So 502 is in the set, and a moved port is not. Moved off 502, a flow whose server spoke first keeps the server as originator. Its requests are then read as responses, for a reason the signature does not control. `modbus-moved-port` is not affected: its first frame is the client's. D6 read both files and they match D2's hashes. |
| `review-text` | D2 and D6 read the signature's text, the settings it needs, and any code it calls, before the counted run: nothing `judge-port` forbids; every Modbus code of `fc-classes/1` accepted as a first request; the reassembled stream read, not segments; any transaction ID, any unit ID from 0 to 255, any length from 2 to 254; an exception reply counted as a reply. The review also says what the signature does with a stream the server opens. | D2's strict check accepts "a public function code". `fc-classes/1` holds SEL's own codes 60h, 61h and 62h (`read`) and 7Dh (`control`), citing S22 Tables E.2 and E.30 (`modules/detection/netdetect/fcclasses.go`). A relay's session may open with one of them (`inference`), and a signature that knows only public codes would miss it. GT-PCAP holds none of them, and whether a public capture does is `unknown`, so this is checked by reading until GT-PCAP has a Modbus/TCP writer (plan §2B, owed). Part (c) is D2's finding G, and parts (d) and (e) are D2's N4 on #642. D2 suggested a synthesized first request for each code, run through S0, to make (b) a measurement. That needs the same Modbus/TCP writer, so it is not in this file. |
| `fp-flows`, `fp-floor`, `fp-near`, `fp-control` | No `not-modbus` flow named Modbus; at least 300 such TCP flows with a flow record; at least 10 near misses from 2 protocols, Modbus RTU in raw TCP among them; the counter shown to count a false positive planted in a copy of the labels. | Section 4. |
| `corpus-*`, `label-*` | What the corpus must be, and what its labels say. | Section 4. |
| `report-redef`, `report-counts` | What the report states, with the count for each protocol and the near misses' own count (D2's N3 on #642). | The rule-of-three bound: zero false positives in N flows bounds the per-flow rate at about 3/N at 95%, so 300 flows support "under 1%", not "zero". Most of those flows cannot match any MBAP check (DNP3, TPKT, IEC 104, text), so the bound is over that mix, and the near misses get a bound of their own: zero in 10 is about 26%. |
| `adopt-when`, `adopt-limits`, `adopt-rerun` | The proposed threshold. | Section 5. |

## 2. What Zeek's Modbus parser checks (`desk`, source at `v9.0.1`)

Read on 2026-11-13 through GitHub's API at the tag, and hashed:

| File | SHA-256 | What it says |
| --- | --- | --- |
| `src/analyzer/protocol/modbus/modbus-protocol.pac` | `49da970052c3b5bc36aa653a6a25c3394db4c1157b77c210d11f30957bae2038` | A PDU is `header.len + 6` octets (l.74). The header enforces a protocol ID of 0 and a length of at least 2 (l.78, l.79). A function code the parser does not know is read as opaque data (l.108 for requests, l.140 for responses), with no violation. |
| `src/analyzer/protocol/modbus/modbus-analyzer.pac` | `26ddb3a4b7a5e7bc57918af9f6c247c1e6c3855ac20550178f90097d9b2a3cfd` | `deliver_ModbusTCP_PDU` (l.101 to l.111) calls `AnalyzerConfirmation` when `IsConfirmed()` is false, and `IsConfirmed()` (l.80 to l.83) needs a PDU from each end. So confirmation is called on the first PDU parsed in full, from either end, although the comment at l.103 says "from both sides". D6's reading of the code; no run shows it. |
| `scripts/base/frameworks/analyzer/dpd.zeek` | `c24fe9d4ab5d12aa260b7a7d0b84a1cbf776cfcd67776c64faee2e7e904833eb` (D2's hash on #637) | Section 3. |
| `scripts/base/frameworks/analyzer/logging.zeek` | `28a74e2a2d12c6f96cc6cd149969fcebc8543cc0da0b58b27a68fb029cad1df3` | Section 3. |

**What follows for the conditions.** The parser's checks on the header are a protocol ID of 0 and a length of at least 2, and it confirms Modbus on one PDU. A known function code can still raise a violation on its body, for an odd byte count or a coil value other than 0 or FF00h (`modbus-analyzer.pac` l.206, l.250, l.287, l.314, l.482), and binpac can raise one on a short body. All of these come after the header (D2's N5 on #642, which corrects this note's first text). So once the signature enables the analyzer, any stream whose first 8 octets have zeros at octets 2 and 3 and a length of 2 or more passes the header, and only the signature stands between such traffic and the name Modbus. A `modbus.log` row needs only the header (D2's N2, `inference` on binpac's order), which is why `judge-named` counts any such row. That is the class `fp-near` asks the corpus to hold. A zero-filled keep-alive, D2's other residual, is not in it: its length is 0, and the parser refuses it at l.79.

## 3. `DPD::ignore_violations`: measured together, and what it costs

D2's finding C on #637: ICSNPP-Modbus's one observed advantage is most likely its single line `redef DPD::ignore_violations += { Analyzer::ANALYZER_MODBUS };`, which the project's script could carry without ICSNPP. If it does, S0 is the signature and the redef together, every row is judged on the pair, and S2 shows the signature alone beside it (`cfg-sig`, `cfg-alone`).

**What the redef removes,** by the source above (`desk`):

- `dpd.zeek` l.87 and l.88 return from `analyzer_violation_info` for a listed analyzer, before the analyzer is disabled (l.104) and before `analyzer_failed` is raised (l.100, l.108).
- So the handler of `analyzer_failed` never runs for Modbus: l.62 and l.63 never remove `modbus` from conn.log's `service`, and `logging.zeek` l.97 to l.112 never write the violation to `analyzer.log`.
- Stock Zeek already stops acting on a violation after 10 KiB of a connection (`ignore_violations_after`, l.14, l.93 and l.94). The redef does so from the first octet.
- It holds for every Modbus flow: one the signature enabled, and one on 502 that Zeek's port registration enabled (D7 on #637).

**What that means here.** A flow the signature enables wrongly, and that then parses one PDU, stays named Modbus for the rest of the connection. Nothing in any log shows the violations that follow. It raises a false `insecure` (Modbus/TCP) and `new-service`, and it is not reported `undecoded`, so it drops out of the signal the gate requires for an unidentified server (D4-90). That is why `judge-named` ignores `analyzer.log`, and why the false-positive count is the one measure of the pair's cost. The report states this beside the result (`report-redef`).

## 4. The corpus

**D4 names it under P4-4-E2,** in #643. No PR of D4's was open when this note was first written. The `corpus-` and `label-` rows say what it must be and what its labels must say. D4 fills its identity: the manifest, the labels, the labeller and the pins. D6 confirms it against every `corpus-` and `label-` row, and D2 reviews the labels, on that PR before it merges (`corpus-pins`). The conditions file does not change when the corpus is named.

**More than GT-PCAP holds.** GT-PCAP's labelled non-Modbus flows are 25, all synthesized DNP3 (24 TCP and 1 UDP; the `flow` rows of `gt-pcap/dnp3/*.tsv`). E-D4-03's public captures add IEC 104, MMS, Telnet and HTTP, with no labels. The corpus is those, plus D4's additions, and it must hold at least 300 `not-modbus` TCP flows with payload and a flow record (`fp-floor`), from at least 8 application protocols with IEC 104, MMS over TPKT, EtherNet/IP and DNP3 among them, none more than half (`corpus-protocols`). Those four are D2's note 4 (IEC 104, MMS and EtherNet/IP) and the protocol GT-PCAP already holds.

**Near misses** (`fp-near`). D2's residual risk is binary protocols that put zeros early. Section 2 makes it exact: if the first 8 octets that one end sends have zeros at octets 2 and 3 and a length of at least 2, they are a header to Zeek's parser, so on such a flow nothing but the signature decides. The definition reads the reassembled stream, not segments, as Zeek's signature engine and parser do (D2's N1 on #642: `PIA.cc` l.285 to l.311, `dpd_reassemble_first_packets`). A corpus with none of them would show a zero that tests nothing. Synthesized near misses may make up the 10, written by a script in this repository and reported apart from public ones.

**Modbus RTU in raw TCP is one of the near-miss protocols** (D2's B2 on #642). An RTU read at address 0 with a quantity of 2, such as `01 03 00 00 00 02 C4 0B`, is a near miss. Zeek's parser reads it as transaction ID 0103h, protocol ID 0, length 2, unit C4h and function 0Bh, a complete PDU, so the analyzer confirms. If the signature enabled Modbus on it, the function codes the sensor reported would come from CRC octets. RTU framing is carried in raw TCP by port servers and by an RTAC's tunnelled serial. It is the closest MBAP look-alike on a station network. A synthesized RTU flow is allowed, and is how the corpus will most likely meet the row.

**The labels.** They come from the flow's source and from the pinned tshark 4.2.2, never from an engine.

- **`modbus`:** the source says the capture holds Modbus/TCP, the server's port is 502 or one the source names for it, and tshark, told that port is Modbus/TCP, reads a request to it.
- **`not-modbus`:** the source names another protocol, or names the capture's protocols and none is Modbus. Tshark reads no Modbus/TCP on the flow with its defaults. Told the port is Modbus/TCP, it reads no request that the server answers with the same transaction ID and function code (or that code plus 80h). That last part keeps a near miss `not-modbus` unless it carries a real Modbus exchange. **Modbus RTU or ASCII framing in raw TCP is `not-modbus` here, whatever its source calls it,** when it meets those two checks (D2's B2 on #642). C13 and V-M6 name Modbus/TCP, and Zeek's parser misreads RTU framing. An RTU reply's octets 2 and 3 are not zero, so tshark reads no answer to the "request". Without this sentence such a flow would fall to `disputed`, where nothing counts it, and a signature that named it Modbus would pass.
- **`disputed`:** anything else. Disputed flows are listed before the run and counted nowhere, at most 5 in 100.

Where a source states no protocol for a flow and tshark reads none, the flow is `not-modbus` only if the source names the capture's protocols. That keeps unknown binary traffic, the hardest negatives, in the count.

**Sources and terms** (`corpus-sources`, `corpus-terms`). Public captures published by a third party, or synthesized by the project. Nothing captured by the project or the owner, from a site of the owner's, from a network either operates, or that its publisher says came from an operational network. A source with no stated terms is fetched in the run at a pinned hash and never committed, as MANIFEST.tsv's are. A source that needs registration or an agreement is not used. D7 confirms any capture that is committed.

**What it does not hold** is listed in the manifest (`corpus-not-held`), so a reader of the result sees what the zero does not cover (D2's note 4).

## 5. The adoption threshold, proposed for D1

D1 states the threshold. This was D6's proposal, written as rows `adopt-when`, `adopt-limits` and `adopt-rerun`, and D1 stated it unchanged on #642 (comment 6837626751). D2's review of that head then changed other rows (B1, B2, N1, N3 and N4 on #642), and with them the file's hash, so D1 restates the threshold against the new hash.

1. **Adopt** the signature, as S0, only when every row with a threshold holds in one counted run. In plain words:
   - the three `modbus-moved-port` rows pass, not told the port, with the 502 control passing and the baseline failing;
   - no row of `engine-pass-conditions.tsv` that the approved configuration passes is lost;
   - every held-out Modbus flow passes wherever its control does, with at least 5 counting; a flow whose server spoke first, with no client SYN, is judged on its protocol row only;
   - D2 and D6 pass the signature's text;
   - **no false positive** on at least 300 `not-modbus` TCP flows, with at least 10 near misses, Modbus RTU in raw TCP among them, and with the counter shown to count one.
2. **Do not adopt** on any `fail`, and not while any of those rows is `unknown`. Then the gate report says Modbus on a moved port is not identified, and HR-22 stands (D4-90).
3. **Why zero false positives.** Each false positive is a standing false `insecure` (Modbus/TCP) and `new-service` on a server that is not Modbus, and under the redef it also takes that server out of the `undecoded` signal (section 3). A check as strict as D2's should give none on non-Modbus traffic. Zero in 300 bounds the per-flow rate at about 1% at 95%; the result says that, not "zero".
4. **What adoption does not close** (`adopt-limits`): HR-22 itself, which D3 writes and D1 closes; the `undecoded` signal with `unknown-pair`, still owed before the gate; a session that opens with a code outside `fc-classes/1`; Modbus RTU or ASCII framing inside raw TCP, which this measurement classes `not-modbus` and no row identifies; live capture; and whatever the manifest lists as not held.
5. **A second run** (`adopt-rerun`): a signature changed after a run that did not adopt it is measured again against this file unchanged, with the corpus stated as seen. D1 decides whether that is enough.

## 6. Limits

- `desk`: no signature exists, and these conditions are set before any measurement. The source readings in section 2 are D6's, from code, and no run shows them.
- A measured rate is only as good as the traffic it was measured on (D2's note 4). Public captures are of mixed and often unknown origin, and none is a SEL relay's traffic. Synthesized near misses are the project's own, and are reported apart.
- SEL's own Modbus codes, and a session opened with a write, are shown only if the corpus holds them. Until GT-PCAP has a Modbus/TCP writer, `review-text` checks them by reading.
- The held-out leg reuses `movedport.py` and `modbus_label.py`. A capture that `modbus_label.py` refuses (it fails on any malformed frame) drops out of the held-out count, and the report lists it. For a midstream flow, `modbus_label.py` takes the first frame's sender as `src`. So for a flow whose server spoke first, its `service` row names the client end. That is one more reason such a flow is judged on its protocol row only (`held-502`).
- Whoever writes the signature also names the corpus. `judge-port` forbids values learned from a capture, `review-text` reads the text, and `judge-seen` reports every earlier run of S0 over the corpus. None of these makes the corpus unseen.
- Offline files on a hosted runner. No live capture, no rate, no latency, and not the sensor host.

## 7. What is left, and for whom

- **D4 (P4-4-E2):** name the corpus; write its manifest and labels as the `label-` rows say; add `MODBUS_SIGNATURE_CONDITIONS_SHA256`, the manifest's hash and the labels' hash to `pins.env`; run S0, S1 (and S2 if the redef is in) in one run; judge these rows; record the script's hashes.
- **D1:** state the adoption threshold on this PR, before it merges.
- **D6:** confirm the corpus and its labels on D4's PR; read the signature's text with D2 (`review-text`); review the counted run against this file.
