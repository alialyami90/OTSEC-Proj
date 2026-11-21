# D4: HR-25's fix, the design (P4-4-HR25, deliverable 1)

D4, 2026-11-15. Brief P4-4-HR25 (`docs/agent-handoffs.md`), deliverable 1. This is a design document only: nothing is built, patched or run, and no capture was made. No device or network was contacted, and no session content was read.

- **The decision: Option A**, frame-by-frame recovery in `DNP3.cc`, as one patch on top of HR-23's option (i). D1's ruling 6893095629 on #690, which D4-106 item 2 records. Options 0, D and E are not taken. D and E stay the fallbacks, in that order, as the options comment states (6885118759, "Recommendation").
- **Inputs:** D4's options 6885118759 (A.1 to A.10, which this note replaces where they differ); D7's 6885160234 (C1 to C6); D2's 6885169858 (C1 to C3); D6's 6885310412 (T1 to T14); D3's 6893081185 (S1 to S9); D1's ruling 6893095629; `docs/phase4/D4-hr23-design.md` §5.2 at `52c7592c` (the candidate), and §4.3 to §4.7 and §6 on `main` at `fadd6516`; HR-25's row in `docs/threat-model.md` on `main` at `fadd6516`; D4-101 items 5 to 8, D4-102 items 7 and 9, D4-105 item 7.
- **Evidence class.** Every statement about Zeek's code is `desk`: read by D4 from the release tarball at the HR-23 note's pin (SHA-256 `fbee2eb5ee6ebd64ef0db830fbb9fa1d702d58807643c719e8338a59329197f2`, checked again for this note). Code is cited by function. What was not read is marked `not read`. Every statement about IEEE 1815 is `inference`, because the project holds no text of it. Every size, rate and default proposed here is a design value, which D6 pins before the run.
- **Files read for this note**, beyond the HR-23 note's table (whose hashes for `DNP3.cc`, `DNP3.h`, `dnp3-protocol.pac`, `dnp3-analyzer.pac`, `dnp3-objects.pac`, `Analyzer.cc`, `Reporter.cc`, `dpd.zeek`, `init-bare.zeek`, `FuzzBuffer.cc`, `generic-analyzer-fuzzer.cc` and `pac_flow.cc` were checked again and match):

  | File | SHA-256 |
  | --- | --- |
  | `tools/binpac/src/pac_conn.cc` | `aa19fc3ec9f58f16e6331f63d9c84ceb0cbd3eae4abdba1c82199f992cdd6e53` |
  | `tools/binpac/lib/binpac_buffer.cc` | `f8afff5023002b54c8a4c1aea1b7acfcf515cfb06e8b4a40ae6a70b4ba1ea55a` |
  | `tools/binpac/lib/binpac_buffer.h` | `7b2031d7e0d1d614131999b1357a3b8d35ffa957b7352c20865e7638ec7280ac` |
  | `src/fuzzers/FuzzBuffer.h` | `1b44c833b085ec8b709360dbfa3ef2014af0454ab0603b7fdc2d8c74b6185742` |
  | `src/analyzer/protocol/dnp3/consts.bif` | `6ec90ab0271dc6a5acc43af3486efc461f30a7c77da0ba7d1d0cb16ebc71d814` |
  | `configure` | `cb6eef0907c42938de08808ef01170be10eff8af9653131cf26c1f3ef1b7edfa` |
  | `CMakeLists.txt` (top level) | `9e9316809298988a588f4b43ccf596720f087ab1f34e2d5d7db07bb49fcbf629` |

- **Revised** for the re-reads at `ec42b475`: D2's 6893241105, D7's 6893255626, D6's 6893379733 and the records-auditor's four points.
- **Revised again** for D1's rulings 6893581874 at `b44cccf6` (which D4-107 is to record), on D6's 6893532533 and D3's 6893572785: D6's B1, option (b) with D6's set of causes (sections 2.7 and 2.8); D6's B7, option (b) (sections 2.6, 2.7 and 2.10); D6's B6 (section 2.8); D3's BM (section 2.8); D3's N1 (section 2.10). Section 3 has their cases.
- **Revised for option (a), the transport sequence check** (D4, 2026-11-21; D4-112 item 3; D1's ruling 6902589450 on #714, on D4's 6902505417, D2's 6902526389 and D3's 6902584812, after D3's F1 in 6901282906 and D4-111 item 8.1). Sections 2.2, 2.3, 2.6 to 2.11, 3, 5, 6, 7 and 8 change, and section 9 gains a table for it. **Evidence class:** the rules are `desk` design values; every statement about what a device does with a segment is `inference` (D2's, from recollection: `reference/` holds no IEEE 1815 text, D4-112 item 3.4); the audit of the pinned rows in section 3.3 is `desk`, a script over the builder's output at `main` `554f9d12`, with no engine run. Nothing was built, patched, run or captured, and no device was contacted.
- Section 9 maps every condition and every re-read finding to the place that answers it.

## 1. What the code does today, as far as this design rests on it (`desk`)

1. **The header stage.** `DNP3_Base::ProcessData` buffers 11 octets per end (`PSEUDO_APP_LAYER_INDEX`), then checks the magic `05 64`, then the header CRC with `CheckCRC`, then calls `AnalyzerConfirmation`. A link length of 5 resets that end and returns, dropping the rest of the delivery. Otherwise it takes the transport octet from the 11th octet, and at a fragment's first frame (`++pkt_cnt == 1`) hands the 8 header octets to `interp->NewData`, before any chunk is checked.
2. **The frame.** For a link length L, `ProcessData` buffers the whole frame with `AddToBuffer` before `ParseAppLayer` checks a chunk. With n = L − 5 user-data octets, the frame is 10 + n + 2 × ceil(n/16) octets (D2's formula, which equals `ProcessData`'s computed target). L = 255 gives 292, under `MAX_BUFFER_SIZE` 300.
3. **`ParseAppLayer`** checks each chunk's CRC and the fragment-size limit, and hands each chunk to binpac with `fb->BufferData` as it goes. Only after the loop does it check FIR. At FIN it calls `FinishBuffer` and `flow->FlowEOF()`. It reads only FIR (0x40) and FIN (0x80) from the transport octet: **the transport sequence number is never checked.** A FIR while a fragment is in progress is not detected: its chunks are appended to the old ones.
4. **Every failure sets `skip`:** `ProcessData` returning false, and a `binpac::Exception` in `DNP3_TCP_Analyzer::DeliverStream` or `DNP3_UDP_Analyzer::DeliverPacket`, which discard the flow buffer, set `skip` and rethrow. `Reporter::AnalyzerError` sets `skip` itself. `Analyzer::NextPacket`, `NextStream` and `NextUndelivered` turn a rethrown exception into a violation.
5. **One interpreter for both ends.** `DNP3_Base` holds one `binpac::DNP3::DNP3_Conn` (`interp`), made in its constructor and deleted in its destructor. `DNP3_Conn` holds `upflow` and `downflow` and nothing else of its own (`dnp3-analyzer.pac`, `connection DNP3_Conn`). Its generated `NewData(is_orig, …)`, `FlowEOF(is_orig)` and `NewGap(is_orig, …)` only pick `upflow` or `downflow` (`ConnDecl::GenProcessFunc`, `GenEOFFunc`, `GenGapFunc` in `pac_conn.cc`).
6. **binpac's unit outlives every drop that is not an exception** (D6's T2; **`inference`**, as D6 labelled it: read from the generator's source in `pac_flow.cc`, not from a generated file, which neither D4 nor D6 read). The generated flow keeps an incomplete unit across `NewData` calls ("Resume upon next input segment", `FlowDecl::GenCodeFlowUnit`). Only the catch in `FlowDecl::GenProcessFunc` cleans it up, and `FlowBuffer::DiscardData` clears the buffer, not the unit. `FlowBuffer::set_eof` sets `eof_`, which only the constructor clears (`binpac_buffer.cc`); what the generated code does with `eof_` on the next fragment is `not read`.
7. **A TCP gap** goes to `DNP3_TCP_Analyzer::Undelivered`, which calls only `Interpreter()->NewGap`. `DNP3_Base` resets nothing.
8. **The end of a TCP connection.** `DNP3_TCP_Analyzer::EndpointEOF` and `Done` call `FlowEOF` outside `DNP3.cc`'s catch, whatever `skip` is (HR-23 note §4.7 item 1). `DNP3_UDP_Analyzer` has neither.
9. **`DNP3::max_application_layer_fragment_size`** is `const … = 100 * 1024 &redef` (`init-bare.zeek`), so the project's script can lower it.
10. **Weird sampling.** `Weird::sampling_global_list` rate-limits the weirds it names globally instead of per connection, with `sampling_threshold` 25 and `sampling_rate` 1000 (`init-bare.zeek`).
11. **`dpd.zeek`** ignores every violation once a connection has carried more than `DPD::ignore_violations_after` (10 KiB).

## 2. The design

Every rule below holds on both transports unless it names one. "Before confirmation" and "after confirmation" refer to section 2.7. **Wherever a rule below raises a weird, it does so only after confirmation.** Before confirmation every cause is counted only, and `budget` alone raises its weird (sections 2.7 and 2.8).

### 2.1 The header stage: judged at 10 octets, and one step for every failed header (A.1, A.3; D2's C1; D3's S4, S6)

- **The check runs at 10 octets,** not 11: magic, then header CRC, then length.
- **A failed header consumes 1 octet and scans.** A header fails on a lost magic, a failed header CRC, or a link length of 0 to 4 whose CRC passes (D2's C1, D3's S6, which replace A.1's "consume 10"). Every failed header takes the same step. A sender chooses CTRL, DEST and SRC, so it can make a header with a length of 0 to 4 whose CRC octets are `05 64`. Consuming 1 then finds the frame at offset 8. That errs on the loud side (D2's C1).
- **A length of 5** (a link-only frame) consumes its 10 octets and goes on with the rest of the delivery. Only the header stage is reset. The transport state and the fragment in progress are left alone, so a link-only frame inside a multi-frame fragment ends nothing (D6's B1 (c)). R4 closes this way, the TCP keep-alive included.
- **The transport octet is read only from a whole frame** (section 2.2), so a link-only frame never reads a stale buffer octet (D3's B4 (4)).
- **The scan** (A.3, on both transports, D1's ruling with D2's and D3's agreement in S7):
  - It looks for `05 64` first, without a copy, and computes the header CRC with `CalcCRC` only at a match. A candidate is `05 64`, a passing header CRC, and a length of 5 to 255 (D2's C1).
  - It never calls `CheckCRC`, which formats and raises a weird on every failure. It allocates nothing and raises no event. After confirmation it raises at most one weird per scan run, the weird of the cause that started the run (S4, T10).
  - Its cost is constant per octet: per octet consumed, at most one comparison for the magic, at most one shift of the 9 octets buffered, and at most one 8-octet CRC at a match.
  - On TCP it keeps up to 9 octets of a partial candidate across a segment boundary (D2's addition). On UDP it is bounded by the datagram (section 2.4).
  - **Where a scan run ends** (D6's B2): at the first candidate it finds; on UDP at the datagram's end; on TCP at a gap or the connection's end, and **not** at a segment's end. A run's held octets (a partial candidate of fewer than 10 octets) are discarded with it at a datagram's end, and count nothing more (section 2.4).
- **Progress** (D3's B4 (2); D6's T9). The measure is the octets buffered plus the octets unread. Every pass of `ProcessData`'s loop after a failure lowers it by at least 1: 1 for a failed header, the frame's length for a dropped frame, and the rest of the delivery for a scan that finds nothing. A 1-octet shift re-reads 9 buffered octets and takes none from the input, which this measure counts correctly. The fuzz run's `-timeout` catches a loop that spins.
- **What becomes unreachable by input.** With lengths 0 to 4 failed at the header, `AddToBuffer`'s "invalid target length" and `ProcessData`'s `pkt_length <= 0` weird are no longer reached by any input (section 2.9).

### 2.2 A frame reaches binpac only whole and checked (A.2; D2's B1 and C2; D6's T4; D3's B4 (3) withdrawn)

- **The order of checks moves** so that nothing from a frame reaches binpac until the frame passes every check in C++. After the header stage, `ProcessData` buffers the whole frame (as today), then checks, in order:
  1. every chunk CRC (`chunk_crc`);
  2. the transport rule (section 2.3: `first_chunk_missing`, `fir_restart`, `transport_seq`, or the discard of a duplicate);
  3. the fragment-size limit (`fragment_limit`). **The octets counted** (D6's N5) are application octets: each frame's user data less its transport octet, with no CRC octet, which is what `ParseAppLayer` hands to `BufferData` today. The sum is the fragment's buffered application octets plus this frame's. A sum equal to the limit passes; one octet over fails. (Zeek 9.0.1 compares only the octets already buffered, before each chunk, with `>`, `desk`; A counts the whole frame first, which section 3's boundary pair pins.)
- **Only then** does the frame's header go to binpac (if it starts a fragment) and its chunks with `BufferData`. `ParseAppLayer` then only feeds binpac and, at FIN, calls `FinishBuffer` and `FlowEOF`. This removes S1's case of a chunk already in the flow buffer when its frame is refused, and HR-23 §4.7 item 1's held header for a frame that then fails at its first chunk.
- **Skip by length.** A frame whose header passed and whose chunk CRC fails is consumed by its computed length, on both transports, and the octets after it in the same delivery are parsed (D2's B1). The sender's fragment in progress is dropped (section 2.6). The scan never runs inside such a frame, so a frame embedded in its data is never parsed (D3's smuggling case).
- **No skip counter.** The frame is already whole in the buffer when a chunk fails, so nothing of a skip crosses a segment (D6's T4). D3 withdraws B4 (3). The counter and its coverage target are dropped.
- **The embedded-header flag** (D2's C2, which D3 supports in S6; D2's B1 on the re-read). While a failed frame of length len is consumed, every offset from 1 to len − 1 is checked for a candidate (`05 64`, a passing header CRC, a length of 5 to 255), by the scan's rule. A candidate that starts in the frame's last 9 octets is read with up to 9 octets past the frame's end, from the same end's stream:
  - on TCP, the frame's last 9 octets are held, as the scan holds a partial candidate, until 9 more octets of that end arrive, and the check then finishes. A gap or the connection's end before then ends the check on what was held;
  - on UDP, only octets of the same datagram are read. A candidate cut by the datagram's end cannot be whole, so the device cannot act on it either, and it is not flagged.

  The octets past the frame are still parsed from the header stage as usual; the check only reads them. If a candidate is found, it is counted under `embedded_header` and (after confirmation) raises `dnp3_embedded_header`, once per failed frame. Nothing is parsed from it: parsing would re-enter the parser from inside a skip (S6). The check runs over at most 291 offsets per failed frame (292 − 1), each read at most once (S4).
  - It covers the case D2 names after a gap or a failed header: the scan locks onto a planted header whose length takes in a genuine frame, the planted frame's chunk CRC then fails, and the check flags the genuine header inside it.
  - It does not cover a planted frame whose every chunk CRC passes. On TCP such a frame is in the sender's own stream; on UDP it is in a datagram the sender sent. Either way it is the sender's data, parsed as sent.

### 2.3 Transport and fragment rules (A.5; D2's non-blocking point on the sequence number; option (a), D4-112 item 3)

- **A frame without FIR and no fragment in progress** is dropped and counted (`first_chunk_missing`), and that end resumes at the next FIR, except for the one duplicate after FIN below.
- **A frame with FIR while a fragment is in progress** drops the old fragment, counts it (`fir_restart`), and then takes this frame as the first frame of a new fragment: its header goes to the new interpreter (section 2.6), then its chunks.
- **The fragment-size limit** (application octets, section 2.2) drops the fragment and counts it (`fragment_limit`), and parsing goes on at the next FIR. Its weird stays `dnp3_max_application_layer_fragment_size_exceeded`.
- **The transport sequence is checked on every frame without FIR** (option (a); D1's ruling 6902589450). Zeek 9.0.1 never reads it (section 1 item 3).
  - **The state, per end:** `tseq`, the 6-bit sequence number of the last segment accepted on that end; `last_seg`, a copy of that segment's user data (its transport octet and every application octet, without CRC octets), at most 250 octets, with its length; and `after_fin`, set when that segment carried FIN. **A segment** here is a frame's user data: the transport octet (FIR, FIN and the 6-bit number) and the application octets that follow it.
  - **Who sets it.** Every frame that the transport rule accepts sets all three: a FIR frame, whatever its number, and every appended frame. The drop function (section 2.6) clears all three. Nothing else changes them: a link-only frame (section 2.1), a failed header and its scan run (section 2.1), and every frame or failure on the other end leave them as they are.
  - **The rule for a frame without FIR while a fragment is in progress,** run in section 2.2's step 2, before the fragment-size limit, with `n` the frame's number:
    1. `n` = (`tseq` + 1) mod 64: **append.** The frame goes on to the limit check and then to binpac, as today.
    2. `n` = `tseq`, and the frame's whole segment equals `last_seg` octet for octet, with equal lengths (D3's C1: FIN, the number and every application octet compared): **discard.** The frame is consumed by its length, nothing of it reaches binpac, nothing is counted, no weird is raised, and the state is unchanged. That is a link-layer retry, or a PRP duplicate that leaked past the frame stage.
    3. Any other frame: **drop under `transport_seq`** through section 2.6's function. The frame itself is consumed by its length; the fragment in progress, this frame included, is dropped, and that end's interpreter is remade (there is always a fragment in progress here).
  - **Duplicates after FIN.** When `after_fin` is set and no fragment is in progress, a frame on that end without FIR whose number equals `tseq` and whose whole segment equals `last_seg` is discarded as in step 2, not counted as `first_chunk_missing`. A discard changes no state, so **any number of identical retries** of the last segment are discarded, as inside a fragment. Any other frame without FIR there is `first_chunk_missing`, as above. The window ends at the next frame on that end that is not such a retry: an accepted frame replaces the state, and a drop (a `first_chunk_missing` among them) clears it.
  - **FIR frames are unchanged.** A FIR frame accepts any number. There is no duplicate rule for FIR frames: a retried first frame of a multi-frame fragment stays `fir_restart` (`dnp3-resync-udp-link-retry-first`'s pin and `val-F` stand), and a retried single-frame fragment (FIR and FIN in one frame) is parsed twice, as today. That second one is an over-report, never a miss (section 7, L-3).
  - **The same rule on both transports.** On TCP a frame without FIR whose number is wrong can only be the sender's own octets, or an overlap that HR-24 counts (CH-53, CH-54).
- **The receive rule this check rests on is `inference`** (D2's 6902526389, from recollection of IEEE 1815-2012's transport function and one open stack; `reference/` holds no IEEE 1815 text; D4-112 item 3.4, and HANDOFF's "Waiting on the owner" item 3). In D2's reading, a device appends a segment numbered `tseq` + 1; discards the fragment in progress on any other number, a repeated one included; and starts a fragment at any FIR. The check does not depend on that reading: a device that discards only the segment, or treats a repeat as harmless, changes which party missed the write, not whether the sensor counts it (below). A correction from the standard's text changes these labels, not the mechanism.
- **Why every divergence is counted** (D4's three cases, D2's general property, D3's proof in 6902584812 §1). Under the rule the sensor accepts a chain of segments without FIR whose numbers each step by 1. Suppose the device accepts a different chain. Take the first position at which they differ: the device accepts d and the sensor accepts s, with the same number.
  - If the sensor sees d after s, d repeats s's number with other octets: `transport_seq`.
  - If the sensor sees d before s, it accepts d, and s is the frame that fails: `transport_seq`.
  - If d and s have the same octets, nothing differs.

  It holds whatever made the device skip s: insertion, the link layer's destination filter, a repeated FCB with FCV set, or the device's own sequence check. The link-layer filters (the destination address, and a repeated FCB with FCV set) are D2's `inference` (6902526389 §1), and the sensor does not model them. After a `transport_seq` drop the rest of the fragment's frames are `first_chunk_missing`. So a write whose fragment differs between the device and the sensor is unseen and counted, never quiet, apart from the two residuals named next.
- **The quiet residuals** (D4-112 item 3.3; HR-25's row, section 8):
  - **Substitution of a segment the capture never delivered** (D3's C3). If the sensor never receives the true segment d, and is given s with d's number, it accepts s and then d's successor, and nothing is counted. It needs the mirror or the capture to lose one chosen frame. A loss inside the sensor host is counted (`drops_decoder`, SL-3); a loss at the switch is not seen. It is the general limit that a sensor cannot count what it never received. Its case is pinned "missed" (section 3.2).
  - **The duplicate rule's over-report.** If a device treats a repeated number as a bad sequence and drops its fragment (D2's reading of (ii), `inference`), the sensor, which discards the repeat and keeps the fragment, logs a write the device never ran. It cannot hide one: identical octets cannot make the two fragments differ, and a repeat with other octets is `transport_seq`. A retried single-frame fragment parsed twice (above) is the same kind.

### 2.4 Datagram boundaries (A.4; D6's T8 `truncated`; D2's non-blocking point on UDP)

- **On UDP, the link-frame buffer is reset at every datagram's end.** The transport state and the fragment in progress are not reset by the boundary itself, because a multi-frame fragment's segments span datagrams (D2: one or more whole link frames per datagram, `inference`).
- **Octets left at a datagram's end.** Where the header stage holds octets it has not judged (fewer than 10), or a frame whose header passed is not whole, that is a drop under `truncated`, and that end is reset by section 2.6's function, its fragment in progress included. After confirmation it raises the weird `dnp3_truncated_frame`; before confirmation it is counted only, like every cause but `budget` (section 2.7). A frame cut short by its datagram's end is therefore counted, never lost quietly.
- **A scan run at a datagram's end** (D6's B2) ends there, and its held octets are discarded with it. They are not counted under `truncated` as well: the run already counted. So a datagram of garbage counts exactly one against F: a failed header and its scan run if it reaches 10 octets, `truncated` if it does not. One frame split across two datagrams, which the UDP mapping does not allow (`inference`), is the changed conforming case, and has a case of its own (section 3).
- There is no skip counter on UDP or TCP (section 2.2).

### 2.5 TCP content gaps (A.7; D6's B1 (b))

- `DNP3_TCP_Analyzer::Undelivered` no longer calls `NewGap`. On a gap it drops that end under `gap` (section 2.6): the frame buffer, the header stage, the fragment in progress and that end's interpreter. That end then scans for the next candidate (section 2.1), and the octets after the gap are never read as the rest of the frame before it.
- No binpac call remains on `Analyzer::NextUndelivered`'s path.

### 2.6 One drop function, and one interpreter per end (A.6; D3's S1, S2, S3; D6's T2, T3, T11)

- **One function for every drop** (S1, which is T2). `chunk_crc`, `first_chunk_missing`, `fir_restart`, `transport_seq`, `fragment_limit`, `gap`, `truncated` and `app_parse` all go through it. It counts the cause, clears that end's endpoint state (`in_hdr`, `buffer_len`, `pkt_length`, `tpflags`, `pkt_cnt`, `encountered_first_chunk`, and section 2.3's `tseq`, `last_seg` and its length, and `after_fin`), and, if that end has a fragment in progress, deletes and remakes that end's interpreter. The other end is not touched (D3's N7). That gives one path to fuzz instead of eight, and no unit held before a drop can reach the next fragment. A failed header (section 2.1) is not a drop: no fragment state changes, the scan only consumes octets. Nor is section 2.3's discard of a duplicate: it consumes the frame and changes no state.
- **No remake for an end with no fragment in progress** (D6's B7, option (b); D1's ruling 6893581874; D3's rule in 6893572785). An end has a fragment in progress when some part of a fragment, its header or a chunk, has reached binpac on that end since the interpreter was made, or since that end's last fragment ended with `FlowEOF` returning normally. With none in progress, a drop clears the endpoint state and keeps the interpreter.
  - **Why it is sound.** Under section 2.2 nothing of a frame reaches binpac until the frame passes every check. So an end with no fragment in progress holds its interpreter in the state from which Zeek 9.0.1 already parses a second fragment today, and S1's purpose, that no unit held before a drop reaches the next fragment, holds.
  - **Which drops it covers.** `first_chunk_missing` always, and `chunk_crc`, `gap` and `truncated` when they fall on an idle end. `fir_restart`, `transport_seq`, `fragment_limit` and `app_parse` always have a fragment in progress, so they always remake (S1, T2).
  - **What it removes.** A run of `first_chunk_missing` before confirmation counts one against F and nothing against O (section 2.7). Without this rule each of its drops remade an interpreter, with no bound (D6's B7). With it, a stream of non-FIR frames costs the CRC checks per octet that valid traffic costs, before and after confirmation.
- **Two interpreters.** `DNP3_Base` holds two `DNP3_Conn`s, one per end. The originator uses its own `upflow`, the responder its own `downflow` (section 1 item 5). No claim about reusing binpac's generated flow is needed, and none is made.
- **The accessor** (S2). `Interpreter()` goes. In its place an accessor takes the end, so a call site that picks no end, or keeps the old pointer, fails to compile. Every binpac call names its end: `NewData` and `BufferData` in `ProcessData` and `ParseAppLayer`, `FlowEOF` in `ParseAppLayer`, and `FlowEOF` in `EndpointEOF` and `Done`, each on its own end's interpreter (T11).
- **Where the replacement happens** (S2). Only where no frame of binpac or of `ParseAppLayer` for that end is on the stack: in `ProcessData`'s loop, after the step that feeds binpac has returned or thrown; in `Undelivered`; and in `EndpointEOF` and `Done`, after `FlowEOF` has returned or thrown. `ParseAppLayer` takes the flow from its end's interpreter at its top and holds it through its loop, so the replacement never happens inside it.
- **The catch is inside the loop** (D6's T3). The step that feeds binpac is wrapped in `catch (const binpac::Exception&)` inside `ProcessData`'s loop. The catch records `app_parse`; after the `try`, the loop calls the drop function and goes on with the rest of the delivery. So after an exception, as after a failed chunk, the octets that follow in the same datagram or segment are parsed. The R1 cases with an exception and a write in one datagram, and in one segment, pin it (section 3).
- **The same catch covers the end of a connection** (T11). `EndpointEOF` and `Done` call `FlowEOF` on their own end's interpreter inside the same catch. A throw there is counted under `app_parse` and the end is reset. HR-23 §4.3's four TCP inputs that hold a header at the end of the connection change their expectation accordingly (section 3).
- **`binpac::Exception` only** (S3). Nothing catches `...`. A `std::bad_alloc`, or any exception the design does not name, keeps today's path: it ends the process, which restarts with back-off and is counted (AP-30 (3)). An exception nobody has reasoned about crashes loudly; it is never turned into a resync.
- **No violation after confirmation.** The caught exception is not rethrown, so `Analyzer::NextPacket` and `NextStream` raise no violation, and `dpd.zeek` never removes the analyzer for it.
- **The existing catches stay** (D6's N1). `DNP3_TCP_Analyzer::DeliverStream`'s and `DNP3_UDP_Analyzer::DeliverPacket`'s `catch (const binpac::Exception&)` stay, with the per-end accessor in place of `Interpreter()`: they discard both ends' flow buffers, set `skip` and rethrow, as today. Under A every binpac call sits inside the new catch, so no input should reach them. A reach means a binpac call was left outside it, and would quietly restore `skip`, so both are on section 5's "must show as not reached" list.
- **The cost** is one interpreter remade per drop on an end with a fragment in progress (D6's N3): a `DNP3_Conn` with its two flows, whose buffers' allocation is `not read`. D3 accepts the cost in principle (S1); section 2.10 measures it and bounds the work per fragment.

### 2.7 Confirmation, and before it (A.8; D6's T5, T6; D3's N6; D2's three points)

- **`AnalyzerConfirmation` moves** from the first passing header CRC to the first fragment that parses whole: every check of section 2.2, FIN, and `FlowEOF` returning without an exception. One forged 10-octet header no longer names a flow or switches on the tolerance below (N6).
- **The forging cost left** is one whole fragment. A request whose arm is `empty` (codes 0, 13, 14, 15, 19, 23, 24 among them) or whose `default` arm takes `bytestring &restofdata` parses with 2 application octets, which makes a frame of 15 octets with two computed CRCs (D6's T6; D2: the smallest whole fragment is a 2-octet application confirm). That cost stays recorded under HR-23 (3c) and R-1, not closed.
- **An object Zeek does not know** (D2's point on A.8). In `Request_Objects`, an unknown `object_type_field` takes `default -> objects: empty` (`dnp3-protocol.pac`, `desk`): it does not throw at its own header, but its data is not consumed, so the next object header is read from it. Whether that throws is `not read`, and so is the response side's `Response_Data_Object` default in full. A real flow whose first fragments carry such objects may then never confirm and spend its budget, which is loud. Stage 2 has a case: the first fragment carries an object unknown to Zeek (section 3).
- **A flow of link-only frames is never named,** which is right by protocol: a link-only frame carries no application layer (D2).
- **Before confirmation, a failure neither raises a violation nor sets `skip`.** It is handled by sections 2.1 to 2.6 like any failure, counted, and raises no weird and writes no row (below). So a bad header on a fresh 5-tuple, after `udp_inactivity_timeout` or at a sensor start, no longer blinds the session that follows (R2). The TCP case of a sensor that joins a connection in the middle of a frame is the same route (D6's R2 TCP case).
- **The budget: two bounds** (T5). Before confirmation, a connection has:
  - a failure budget F, where each failed header's scan run (section 2.1 says where a run ends), each drop and each `embedded_header` counts one. A failed frame that holds an embedded header therefore counts two;
  - an octet budget O, the octets consumed by scans (the failed header's octet included), by dropped frames, and by `truncated`. For `transport_seq`, the dropped frame is the frame that failed the rule; the frames already appended to the fragment were consumed as accepted frames and are not counted again. A duplicate discarded under section 2.3 is not a failure and counts against neither F nor O.

  **The rules of the count** (D6's B2; D2's B2):
  - **Reaching ends it.** The budget runs out at the step at which the failure count reaches F, or the octet count reaches O.
  - **When O is checked:** after each step that adds to it, which is per octet in a scan and per frame at a drop.
  - **Per connection.** The two ends' failures and octets add up, because `skip` is the analyzer's and covers both ends (`SetSkip`, `desk`). The counts written in rows stay per end (section 2.8).
  - **`transport_seq` counts one against F,** like any drop. If frames of the same fragment follow the frame that failed, they are a run of `first_chunk_missing`, which counts one more (below). So a middle segment lost at the sensor before confirmation costs 1 against F when the failing frame is the fragment's last (a three-frame fragment), and 2 when at least one frame follows it (section 7, L-3, class 2).
  - **A run of `first_chunk_missing`** (D2's B2). On one end, the drops under `first_chunk_missing` from the first one up to that end's next frame with FIR, or its next failure of another cause, count **one** against F, and their octets do not count against O. Such frames passed every link check, and the device discards them too (`inference`) when it received the same frames. Under insertion it did not, and that route is made visible by the flow's `end` row, not by the budget (below). Such a drop remakes no interpreter (section 2.6, D6's B7). The next FIR then confirms or fails on its own. Without this rule, a sensor that joins a 2,048-octet response after its first frame spends F and O on 8 valid frames of 2,119 octets (D2's arithmetic: the fragment is 9 frames, 8 × 292 + 75 octets). Each drop is still counted per end under its cause.
  - **When it runs out mid-delivery,** `skip` is set at that step, and the rest of the delivery and every later delivery on both ends are ignored.

  Proposed values: F = 8 and O = 2,048. D6 pins both in the stage-2 pins PR, at values the fuzz harness reaches within 64 chunks and `-max_len`; if it cannot, the coverage condition leaves the budget to its stage-2 case and says so.
- **When the budget runs out,** the analyzer counts `budget`, raises `dnp3_resync_budget_exhausted`, writes its row (section 2.8), raises one violation, and **sets `skip` itself.** Setting `skip` makes the outcome independent of `dpd.zeek`'s 10 KiB bound (T5); a case above 10 KiB shows it. An attacker who spends the budget gets a loud flow, not a quiet one. That is R2's residual, which goes into HR-25's row (section 8).
- **Rows on flows that never confirm** (T6; D6's B1, option (b), D1's ruling 6893581874). Before confirmation nothing is written at the time of a failure. The counts are kept, and written in the flow's `first` row if it confirms (at confirmation, section 2.8), or in its `budget` row. **A flow that never confirms writes an end's `end` row only when one of these six counts is not zero on that end:** `app_parse`, `fragment_limit`, `embedded_header`, `first_chunk_missing`, `transport_seq` or `gap`. Each needs a frame whose header and every chunk CRC passed, or, for `gap`, octets that the sensor lost and the device may have received. `transport_seq` joins the five of D1's ruling 6893581874 under option (a): its frame passed every link check, so the device may have taken a different segment at that place (section 2.3). `fir_restart` is not in the set: an inserted FIR either confirms the flow (a `first` row) or throws (`app_parse`).
  - **What it makes visible.** A datagram inserted on a fresh UDP 5-tuple to hide a multi-frame write leaves the write's tail as `first_chunk_missing` on a flow that never confirms, and so a row. A valid middle segment inserted, or sent by the master itself, in the same place leaves `transport_seq` there (section 2.3), and so a row. A write lost to a TCP gap at the sensor leaves a `gap` row. That is S8's residual, counted in the probe log (section 8).
  - **The false-positive set stays rowless.** Classes (1), (2), (4) and (5) hold no frame whose header and every chunk CRC pass (T7's redraw, which stage 2 applies to (1) and (2) as well), and their cases carry no TCP gap. So they write no row unless they spend the budget, and the set gains D6's second bound beside "never named": `budget` rows on unnamed flows, per class, against C1p, which writes none. (3c) writes its `end` row under `app_parse`. The benign cost is a flow that ends before its first whole fragment, and a non-DNP3 TCP flow on a DNP3 port with a capture gap, which writes a `gap` row.
- **"Named" under A** (T6). Under `conn.log`'s reading, a flow is named only by a whole parsed fragment. Under the `link`-row reading, a header reaches binpac only from a whole, checked frame (section 2.2), but whether `dnp3_header_block` is raised before the fragment completes is the generated code's, `not read` (HR-23 §4.1). So (3a) and (3c) stay `unknown` under that reading.

### 2.8 Observability (A.9; D3's B5, N8, S4; D6's T8, T10; D2's cause on rows)

- **The closed set of causes:** `magic`, `header_crc`, `link_length`, `chunk_crc`, `embedded_header`, `first_chunk_missing`, `fir_restart`, `transport_seq`, `fragment_limit`, `app_parse`, `gap`, `truncated`, `budget`, `invariant`. Fourteen, in that order. `transport_seq` (option (a)) takes the place after `fir_restart`, so every later cause's index in `counts` moves up by one; nothing that reads `counts` is built yet, and the C13 minor's count list (D4-102 item 9) takes the fourteen.
- **One weird per cause:**

  | Cause | Weird | New? |
  | --- | --- | --- |
  | `magic` | `dnp3_header_lacks_magic` | existing |
  | `header_crc` | `dnp3_corrupt_header_checksum` | existing |
  | `link_length` (0 to 4) | `dnp3_invalid_link_length` | new |
  | `chunk_crc` | `dnp3_corrupt_app_chunk_checksum` | existing |
  | `embedded_header` | `dnp3_embedded_header` | new |
  | `first_chunk_missing` | `dnp3_first_application_layer_chunk_missing` | existing |
  | `fir_restart` | `dnp3_fragment_restarted` | new |
  | `transport_seq` | `dnp3_transport_sequence` | new |
  | `fragment_limit` | `dnp3_max_application_layer_fragment_size_exceeded` | existing |
  | `app_parse` | `dnp3_app_parse_failed` | new |
  | `gap` | `dnp3_content_gap` | new |
  | `truncated` | `dnp3_truncated_frame` | new |
  | `budget` | `dnp3_resync_budget_exhausted` | new |
  | `invariant` | `dnp3_invariant` | new |

  A length of 0 raises `dnp3_invalid_link_length` under A, not `dnp3_negative_or_zero_length_link_layer` (T8), which no input reaches any more.
- **The weirds' bound** (N8, T10). Every weird in the table, the existing ones included, is added to `Weird::sampling_global_list` by the project's script, so each is rate-limited across the host, not per connection. The scan raises at most one weird per scan run (section 2.1). Before confirmation only `budget` raises a weird.
- **The counters,** per end: one count per cause, and `scanned_octets`.
- **How the counts reach the script.** The patch adds one event, `dnp3_resync(c: connection, is_orig: bool, why: string, cause: string, counts: index_vec, scanned_octets: count)`, with `counts` in the closed set's order. It is raised:
  - `why = "first"`, once per end (D6's B3): at confirmation, if that end's counts kept from before confirmation are not zero, stamped with the confirming fragment's time; otherwise at the first failure on that end after confirmation, at once, stamped with that frame's time (T10). So R2's case, a bad header and then a clean session, writes its row at confirmation, not days later at the `end`;
  - `why = "interval"`: anchored at that end's `first` row, at the first delivery on that end at or after the `first` row's time plus n × `DNP3::resync_report_interval` (n = 1, 2, …), if that end's counts changed since its last row. At most one per end per interval;
  - `why = "end"`: when the analyzer is done, if any count on that end is not zero; on a flow that never confirmed, only if one of `app_parse`, `fragment_limit`, `embedded_header`, `first_chunk_missing`, `transport_seq` or `gap` is not zero on that end (D6's B1, section 2.7; a `Done` is added to `DNP3_UDP_Analyzer` for this; that `Done` is called for a UDP connection's analyzers at its removal is `inference` from the HR-23 note §4.6's reading of the TCP path);
  - `why = "budget"`: when the budget runs out (section 2.7).

  `counts` and `scanned_octets` are cumulative on that end from the analyzer's start, never counted since the last row. So a flow writes at most two rows per interval, one per end, plus its first and last.
- **The interval and the host cap.** `DNP3::resync_report_interval` is a new `const … &redef` in `consts.bif`, proposed at 60 s. The project's script caps `resync` rows across the host at K per interval, proposed 100 (D6's B3):
  - the host's intervals are a grid of network time, anchored at the script's first `resync` row;
  - **every `resync` row but the overflow row counts against K, whatever its `why`,** `budget` and `end` included;
  - for an interval in which at least one row was held back, and only then, the script writes one row with `why = "overflow"` and the count of rows held back in `overflow`, by a timer at the interval's end in network time, or at `zeek_done` for the last interval. **The overflow row does not count against K** (D6's B6, D1's ruling 6893581874), so the cap never holds back its own report. It belongs to the interval whose rows it counts, is charged to none, and is at most one per interval, so the rows stay bounded at K + 1 per interval.

  A flow beyond the cap is visible only in that overflow count, and K rows in an interval can hold back a `budget` row. Both are a residual (section 8). D6 pins the interval and K for the run. Until the C13 minor that carries the count exists, the counted run judges the probe log (T10), and the node's side is D4-102 item 9's limit.
- **The cause on rows after a resync** (D2's addition to A.3; D3's S7). The patch raises `dnp3_resync_mark(c: connection, is_orig: bool, cause: string)` once before the first fragment that reaches binpac on an end after a drop or a scan on that end. The project's script puts that cause on the next `fc` row of that end in a field `resync_cause`. An analyst can then see that the row followed a resync. That the script handles the mark before that fragment's events rests on Zeek's event queue being in order (`inference`, `not read`).
  - **Where the pending cause lives** (D3's BM, D1's ruling 6893581874). On the connection record: the project's script adds one `&optional` field per end to `connection` (by `redef record`), and holds no global table, set or other container keyed by connection or end for it. A later mark on the same end overwrites the pending cause; nothing is queued. The next `fc` row of that end takes the cause and clears the field.
  - **When it is freed.** With the connection record, when Zeek removes the connection (`connection_state_remove` is its last event). That Zeek frees the record then is `inference`, `not read` for this note, and stays so (section 7, L-4): no case here shows it. What the design shows is that the script keeps no state of its own for the mark outside the record. So a fragment that throws (`app_parse`), which writes no `fc` row, or a flow that ends after the mark, leaves no script state behind, and a sender that varies its 5-tuple cannot grow it. Section 3 has the case, which shows exactly that.
- **The probe-log record** (D6's B2 item 1). `otsec_probe.log` gains `kind = "resync"` rows with exactly these fields: `why` (`first`, `interval`, `end`, `budget` or `overflow`), `cause`, `counts`, `scanned_octets` and `overflow` (on the overflow row), and the `fc` rows gain `resync_cause`. The no-new-field check admits exactly these, the two events and the nine new weird names (`dnp3_transport_sequence` the ninth, under option (a)), and nothing else.
- **Content.** No weird, event or row carries a payload octet: causes and counts only, as the HR-23 note §4.4 rules for `failure_data`.

### 2.9 The invariants (A.10; D3's B4; D6's T8)

1. `AddToBuffer`'s three checks and `ParseAppLayer`'s overflow check stay where they are, and still return before the `memcpy`. After section 2.1 no input reaches them. `ProcessData`'s `pkt_length <= 0` check joins them. A hit is a broken invariant: it counts `invariant`, raises `dnp3_invariant` and writes its row **before** the existing `AnalyzerError` call, which stops the analyzer loudly. It is never resynchronised, and the flow is never quiet (T8). No input reaches it, so it has no case, and the coverage condition shows it not reached (section 5).
2. Progress, as section 2.1 states it.
3. Withdrawn by D3 (no skip counter, section 2.2).
4. The transport octet is read only from a whole frame (section 2.1). No sanitizer sees a stale read here, because `Endpoint::buffer` is initialised, so only D6's T9 case shows it.
5. **The copy into `last_seg`** (option (a), section 2.3). Its length is the frame's user data, which the header stage has already bounded to 1 to 250 octets (link lengths 6 to 255 carry user data; 5 is link-only). A check that the length is at most `last_seg`'s 250 octets runs before the copy and before the compare, and a hit is handled as item 1's: counted under `invariant`, never resynchronised. No input reaches it, and the coverage condition shows it not reached (section 5).

### 2.10 The cost per fragment (D3's S5)

- **What option (a) adds per frame** (`desk`): one 6-bit compare for each frame without FIR with a fragment in progress; a copy of at most 250 octets into `last_seg` for each accepted frame; and a compare of at most 250 octets only when a number repeats. Each is linear in the frame, as its chunk CRCs already are. A stream of identical repeats of one middle segment is discarded frame by frame with no remake and no count; it is not an S5 input, since each frame costs one such compare beside the CRCs it already costs. If D6 wants it measured, it is a ninth input, which is a change to the pins for D1.
- **What changes.** A turns one exception per flow into one per fragment. The smallest throwing fragment is about 15 octets (T6), so a 1,472-octet datagram carries about 98 of them, each costing an unwind and an interpreter remade.
- **The measurement,** made on an (i)+A build in deliverable 3, `simulated`: the engine's CPU time reading offline, **with the project's script that the image ships loaded** (D3's N1, D1's ruling 6893581874), so that the script's handling of `dnp3_resync` and of `dnp3_resync_mark`, which is raised about once per hostile fragment, is in the cost. A run of `zeek -r` without that script does not count. The inputs, each:
  - UDP datagrams, and a TCP stream, full of the smallest throwing fragments;
  - a run of repeated `05 64` (S4's input);
  - a stream of 13-octet non-FIR frames with valid CRCs on a connection that never confirms (D6's B7), which under section 2.6 remakes no interpreter;
  - **input (8), option (a)'s remake** (D1's 6902589450 item 3.1): after one P R, pairs of a 13-octet FIR frame without FIN (user data: its transport octet alone) and a 13-octet frame without FIR, with valid CRCs, whose number is the FIR frame's plus 2 mod 64 (neither the next nor a repeat), packed 56 pairs (1,456 octets) to a datagram, or in a TCP stream. Each pair is one `transport_seq` drop and one interpreter remade, and nothing else: the next frame is a FIR, so no `first_chunk_missing` follows. It is valid only if `transport_seq` equals its pairs and every other count is 0. At 26 octets per remake it costs the octets of input (2) of row `s5-inputs` in `resync-conditions.tsv` (a FIR-only frame and a frame with a bad chunk CRC), and more than the 15 octets of the smallest throwing fragment, so it does not lower S5's worst case (D4's 6902505417; D3's 6902584812 §2). Before confirmation F bounds it, so it is measured after confirmation only;

  each against the same number of octets of valid DNP3. D6 pins the metric, the inputs and the ratio (D6's 6893379733, section 4 item 10). This note cannot give the number, because nothing is built (the brief's exclusions for this deliverable).
- **The order** (D6's B4). The measurement comes **before the image that the counted run measures is fixed**, because adding the bound changes A's patch, and C2 has the counted run measure the image that ships, by digest. If the bound is added, A's patch is re-pinned, the image is rebuilt, and the counted run measures that image. The bound's cases go in deliverable 2's pins either way, on the condition that the bound is added.
- **The bound, if the measurement is above D6's ratio:** after R interpreter replacements in one delivery on one end (R, not K, which is the host cap of section 2.8), the rest of that delivery on that end is dropped under `budget`. After confirmation, a `budget` drop counts `budget`, raises `dnp3_resync_budget_exhausted` and writes a `budget` row (under the host cap), and resets that end through section 2.6's function. It does **not** set `skip` and raises no violation: the next delivery on that end starts at the header stage. Before confirmation, the budget of section 2.7 applies as written: `app_parse` is bounded there by F, and a run of `first_chunk_missing`, which F counts once, remakes no interpreter (section 2.6, D6's B7). R is then pinned with the ratio.
- **Either way overload is loud:** it shows as `drops_decoder` (SL-3; **[S2]** in C13 0.2's counters table, because it assumes that the engine reads the frame stage's pipe, which E-D4-03's pipe case decides; D6's N4) and as gaps that section 2.5 recovers from. That is a loss of coverage the node sees, not a silent miss.

### 2.11 Memory and crash containment (D3's S9)

- **Memory per flow does not grow,** apart from the second interpreter and option (a)'s state: at most the fragment limit per end, plus two `DNP3_Conn`s, each with two flows, plus per end a fixed 250-octet `last_seg`, its length, `tseq` and `after_fin` (section 2.3). A flow stays longer in the parser, but holds no more.
- **The fragment limit.** It is `&redef` (section 1 item 9). Zeek's own comment in `ParseAppLayer` expects fragments of 2 to 4 KiB, and its limit is 100 KiB. The largest fragment the SEL families send is D2's question (S9) and is `unknown`. Until D2 answers, the limit stays at Zeek's 100 KiB in the shipped script, and `fragment_limit` is left to its stage-2 case in the fuzz run (section 5). If D2 gives a size, the script redefines the limit just above it, the bound per flow falls in proportion, and the fuzz run uses that value.
- **Crash containment does not change under A, and it is still not shown.** The engine runs under its own account in an empty network namespace, with no key, no packet socket and no dump, and restarts with back-off (AP-30 (1) and (3), SL-3, SL-22). SL-T2 and SL-T22 are written and not run, because no sensor is built. What A changes is the odds: a hostile flow gets every later frame as a try. The fuzz run under ASan and UBSan, attributed by T13, measures that. A crash loses coverage for the whole sensor, loudly, and the restart delay limits the discard of 64 runs (AP-30 (3)).

## 3. What stage 2 needs (D6 pins it; D1 gives the ids)

**The judge for these cases** (D6's T1):
- The labels come from how each case was built: the builder records each frame as valid, or as the failure it carries. tshark's own resynchronisation is not the reference; where tshark reads a frame differently, that is reported, never used as a label.
- Rule 6 of `docs/phase4/D6-engine-run-pass-conditions.md` §1 does not hold for `dnp3-resync-*`: a function row on a case's flow that the labels lack fails the case. A misparse after a drop shows as such a row.

**The cases,** in the form `dnp3-resync-{udp,tcp}-<path>`, each on its own 5-tuple, the write being the master's direct operate (code 5, g12v1). D6's list in 6885310412 §1 is the base, for each route; this design adds or changes:
- **D2's C1** (and D6's T9, second case, reversed): a header with a length of 0 to 4 whose CRC octets are `05 64`, with a valid write at its offset 8, over TCP and UDP. Expected: the write is seen. The mutant that consumes 10 misses it.
- **D6's T9, first and third cases, unchanged:** a false `05 64` whose CRC fails with a valid header 2 octets later, straddling a segment boundary (the mutant that consumes 10 misses the write); and the `tpflags` case across two segments.
- **D2's C2:** a frame whose header passes and whose chunk CRC fails, with a valid write inside its data, over TCP and UDP. Expected: not parsed, `embedded_header` counted.
- **D2's B1 (re-read):** a failed frame whose last octets start a valid header of a write that runs past the frame's end, over TCP and UDP. Expected: flagged under `embedded_header`. On TCP, a twin where the octets past the frame arrive in the next segment, also flagged; and a twin with a gap before them, not flagged.
- **D3's smuggling case:** a failed frame with an embedded valid frame. Expected: not reported, and flagged as above.
- **D2's N2:** a failed header whose data holds a valid frame, over TCP and UDP. Expected: seen, under the scan.
- **One case per cause,** over UDP and TCP, `gap` over TCP only: a failure, then the write. Expected: seen, and the cause counted.
- **T3:** a fragment that throws in binpac, then the write, in one datagram and in one segment. Expected: seen.
- **T8 `truncated`:** one frame split across two datagrams, then the write in a third. Expected: the split frame counted under `truncated`, the write seen.
- **D2's unknown object:** the first fragment of a session carries an object unknown to Zeek; and a twin with F such fragments in a row, as a master that reads group 0 first would send (D2's non-blocking (b) on the re-read), which pins whether such a master is blinded by the budget. Expected: pinned by D6 before the run (D6's N2), from a reading of the arm or as a two-branch condition in which both branches pass. A quiet flow, a reporter error, a crash or an unlabelled function row fails it.
- **D2's B2 (re-read):** a flow joined after the first frame of a 2,048-octet response, over TCP and UDP. Expected: named at the next whole fragment, no `budget` row, and `first_chunk_missing` counted 8 on the responder's end.
- **D6's B1 (re-read; ruled (b)):** one throwing write alone on a fresh 5-tuple, over UDP and over TCP. Expected: never named, and the master's `end` row with `app_parse` counted. Control: C0 and (i) name the flow and raise a violation.
- **D6's B1, insertion** (6893532533), over UDP: a multi-frame write as the first fragment on a fresh 5-tuple, with one datagram from the master's address inserted between its frames, under 10 octets (`truncated`) or a frame whose chunk CRC fails (`chunk_crc`), one case each. Expected: never named, and the master's `end` row with `first_chunk_missing` counted. Controls: the same write without the inserted datagram, in which the write is seen; and C0 and (i), pinned per case.
- **D6's B7, the idle end** (D3's case in 6893572785): a drop on an end with no fragment in progress (`first_chunk_missing`, and `chunk_crc` on an idle end), then a whole fragment that parses. Expected: the fragment's rows. Whether the interpreter was remade cannot be seen in a capture run, so that is shown by the coverage condition (section 5, both arms of the branch), not by this case. Control: a drop with a fragment in progress, whose remake T2's case and the same coverage show. The stream of non-FIR frames before confirmation is also an S5 input (section 2.10).
- **D3's BM, the pending mark:** N fresh 5-tuples, each with one drop then one throwing fragment, and no `fc` row. Pass: after the connections are removed, the script holds no global state for the mark. That shows the script's side only; that Zeek frees the connection record stays `inference` (section 7, L-4); D6 pins the probe that reads it, for example the size of every global container that the shipped script declares, read at `zeek_done` by a test-only script. Control: a mutant of the shipped script that keeps the pending cause in a global table keyed by connection and end, with no delete, which reports N.
- **The budget's boundary** (T5), by section 2.7's rules: F − 1 failures, then a session, seen; F failures, then a session, unseen with the `budget` row; the same for O; and one above 10 KiB that shows `skip` set without `dpd.zeek`.
- **The fragment limit's boundary** (D6's N5): a fragment whose application octets equal the limit, parsed; one octet over, counted under `fragment_limit`.
- **The interval rows and the host cap** (T10), by section 2.8's rules: a flow longer than two intervals, one row per interval and one at its end, against the same flow without failures, which writes none; R2's case, a bad header then a clean session, its `first` row at confirmation; K failing flows in one interval, no overflow row; K + 1, one overflow row with `overflow` 1, belonging to that interval and charged to none, so that the next interval's K rows are all written (D6's B6).
- **The weirds' bound** (T10): a burst of garbage on one flow, with the count of each weird pinned.
- **S5's load inputs** (section 2.10) are measurements, not pass or fail cases.
- **R3's validity rule** (D6): each gap case opens with a full handshake, the peer's ACK past the hole comes before the write, and the case is valid only if `conn.log` shows `missed_bytes` and the gap in that end's `history`.
- **The controls,** for every case: C0, C1p and the (i) build, each pinned per case ("unseen" on the route cases); a twin without the failure, seen under every configuration; a twin with the failure and no write, which gives no function row.

**Every expectation that A changes** (D6's B2 item 2, T6, T7, T11), judged as (i)+A against the (i) build:
- **The false-positive set** (HR-23 note §4.3):
  - (1) `05 64` with up to 8 more octets: under 10 octets, counted under `truncated` at the datagram's end; at 10 octets, a failed header and its scan run. Either way one count against F, no weird and no row, never named;
  - (2) a failed header CRC: checked at 10 octets, no violation and no weird before confirmation, the rest of the datagram scanned, no row, never named;
  - for (1) and (2), as for (4) and (5), the generator checks the header CRC at every offset where `05 64` occurs and draws again when one passes, so that "no row" is exact under section 2.7's `end` rule (D6's B1);
  - (3a) a passing header then a failed chunk: no longer named under `conn.log` (C0 names it), its `link` rows `unknown`;
  - (3b-data): named only if its fragment parses, which a code with an `empty` or `restofdata` arm does with 2 octets (T6). The generator labels each item by construction;
  - (3b-link): never named;
  - (3c): no violation, counted under `app_parse`, its `end` row written, never named;
  - (4) and (5): each generator checks the header CRC at every offset where `05 64` occurs, and draws again when one passes (T7);
  - the second bound of section 2.7: `budget` rows on unnamed flows, per class.
- **The malformed set** (T11):
  - lengths 0 to 4: a failed header, with no `AddToBuffer` reporter error for 1 to 3;
  - a length of 5 with trailing bytes: the trailing bytes are now parsed;
  - a datagram longer than its frame: its tail is scanned, and counted under `truncated` or as scanned octets;
  - a fragment without FIR, one without FIN followed by a new FIR, and the fragment limit: each counted, and parsing goes on;
  - class (2): no violation before confirmation;
  - the four TCP inputs that hold a header at the end of the connection: their `FlowEOF` runs inside A's catch on its own end's interpreter. "A good header, then a bad chunk CRC, then a TCP FIN" holds nothing at the FIN, because the chunk failure dropped the end and its interpreter. The others are pinned by D6 before the run (D6's N2), as a two-branch condition where the arm is `not read`, with a throw counted under `app_parse`.
- **Every rerun of HR-23 §4.3** (E-D4-03, GT-PCAP, PRP pairs, public captures, E2's corpus): a conforming flow is named at its first whole fragment instead of its first header. Its rows are expected equal; a difference is a regression of A.
- **The reporter-error rule:** no input reaches a reporter error under A (section 2.9), so a reporter error on any input is a finding.

### 3.1 Option (a): each rule, its test and its control

D1 gives the ids, D6 pins the cells (D4-112 item 3.5; brief P4-4-HR2325S, deliverable 3). The ids below are examples. The notation is `resync-cases.tsv`'s; W is the master's two-frame direct operate (W1 holds only its application control octet, as `builder-msgs` splits it), and "the controls" are C0, C1p and the (i) build. A case marked **(+)** is a test of a rule of section 2.3 that D4-112 item 3.5's list does not name; deliverable 3 takes them beside that list (D1's 7060193584 on #782, D4-122).

| Rule (section 2.3) | Its test | Its control: the mutant the test kills |
| --- | --- | --- |
| Append at `tseq` + 1, mod 64 | The wrap case (3.2 item 4): seen, nothing counted | A check without mod 64: `transport_seq=1` at the frame numbered 0, W absent |
| Drop on any other number | F1 over UDP (3.2 item 1): `transport_seq=1` | A as its note stood before (a), which checks nothing: W absent, nothing counted, which is today's quiet route |
| The whole segment compared | D3's C1 (3.2 item 9, (+)): a repeat with W2's application octets and FIN set, counted | A compare of the application octets only: the repeat is discarded, W is seen, nothing counted |
| An identical repeat discarded | `dnp3-resync-udp-link-retry-middle`, narrowed (3.3): W seen, nothing counted, no row | A rule that counts every repeat: `transport_seq=1`, W absent |
| Identical retries after FIN discarded | `link-retry-last` (3.2 item 10): no count, with the retry sent twice | No window: `first_chunk_missing=2`; a window of one retry only: `first_chunk_missing=1` |
| A drop ends the window | `link-retry-last`'s twin with a frame without FIR before the retry (3.2 item 10): `first_chunk_missing=2` | A window that a drop does not end: `first_chunk_missing=1` |
| Off by one: append at `tseq` + 1 | Every pinned case with a multi-frame fragment, `dnp3-resync-{udp,tcp}-link-only-mid-fragment` among them, and the wrap: seen, nothing counted | An append at `tseq` or at `tseq` + 2: `transport_seq` on the second frame, W absent |
| Off by one: the 250-octet bound on `last_seg` | `dnp3-resync-udp-fragment-limit-at`, whose full frames (250 octets of user data) are accepted and copied: parsed, nothing counted | A check of `< 250`: `invariant` on the first full frame; a 249-octet buffer: an ASan report in the fuzz run |
| A FIR frame accepts any number | A FIR whose number does not follow the last fragment's (3.2 item 11, (+)): seen | A check that includes FIR frames: W absent, counted |
| Per-end state | D3's C2 (3.2 item 7), over UDP and TCP: m's W seen, nothing counted on m | One `tseq` for both ends: a count on m (`transport_seq` or `first_chunk_missing`), W absent |
| A link-only frame and a failed header leave the state | `dnp3-resync-{udp,tcp}-link-only-mid-fragment` as pinned (W seen, `rows=none`), and D3's N4 (3.2 item 14) | A link-only frame or a failed header that clears the state: W2 or the next frame is `first_chunk_missing` or `transport_seq` |
| Every divergence counted, whatever made the device skip the segment | D2's FCB-repeat and wrong-destination cases (3.2 items 5 and 6), and the in-sequence twin (3.2 item 2) | A rule that appends a repeated number: W2 appended after I, W absent, nothing counted |
| The residual: substitution under capture loss | D3's C3 (3.2 item 8), pinned "missed" under C2A and the controls | None: it is a residual, not a pass, as F1's case was before (a) |

### 3.2 The cases D4-112 item 3.5 adds, and the rule tests

Each case is on its own 5-tuple. Under C2A the defaults of `judge-defaults` hold unless a cell names otherwise. Every expectation below is `desk`, from this note's rules; each control's cell is D6's to pin, and where this note gives one it is `desk` from section 1 item 4 (in Zeek 9.0.1 every failure sets `skip`, for both ends).

1. **F1 over UDP** (D3's F1; D1's 6902589450 item 3.2), after confirmation: `P R | W1 | I | W2 | Q R`, where I is a whole frame from m with every CRC valid, FIR and FIN clear, a number that is neither W1's + 1 nor W1's, and one application octet, a function code from 34 to 128. Under C2A: P and Q seen; W absent; no function row for I's code; `cnt.m.transport_seq=1`; `cnt.m.first_chunk_missing=1`; `rows=m.first@I,m.end`; `weird.dnp3_transport_sequence=1`; `weird.dnp3_first_application_layer_chunk_missing=1`. Controls: W absent, and the merged fragment W1 + I + W2 read as I's code through its `default` arm (row `arm-3bdata`), which the builder labels. **(+)** Its twin on a fresh 5-tuple, before confirmation (`W1 | I | W2`, no response): never named; `cnt.m.transport_seq=1`; `cnt.m.first_chunk_missing=1`; `rows=m.end`.
2. **(+) The in-sequence twin** (D4's 6902505417): as item 1, with I numbered W1's + 1. Under C2A: I is appended, and W2, which repeats I's number with other octets, is the frame that fails: W absent; `cnt.m.transport_seq=1`; `cnt.m.first_chunk_missing=0`; `rows=m.first@W2,m.end`; no function row for I's code. Controls as item 1.
3. **F1's TCP twin from the master's own stream** (D1's 6902589450 item 3.2): handshake, then item 1's frames in m's own segments, no overlap (not insertion; HR-24's route is not involved). Under C2A and the controls: as item 1.
4. **The wrap** (D1's 6902589450 item 3.2): a three-frame write numbered 62, 63 and 0, over UDP. Under C2A: seen; nothing counted; `rows=none`. Controls: seen.
5. **D2's FCB-repeat middle segment** (6902526389 §2), over UDP: `P R | Rst | A | W1c A | I | W2c A | R | Q R`, where I is link function 3 with FCV set and W1c's FCB, numbered W1c's + 1, with other octets, so the device's link layer takes it as a retry and drops it (`inference`), and W2c toggles the FCB. Under C2A: the sensor does not read the FCB, so it appends I, and W2c is the frame that fails: W absent; `cnt.m.transport_seq=1`; `rows=m.first@W2c,m.end`. Controls: W absent.
6. **D2's wrong-destination middle segment** (6902526389 §2), over UDP: as item 2, with I addressed to another link destination, which the device's link layer drops (`inference`). Under C2A: as item 2. Controls: W absent.
7. **D3's C2, per-end isolation** (6902584812 §4), over UDP and over TCP: `P R | W1 | Ro1 | Xo | W2 | R | Q R`, where Ro1 opens a two-frame fragment on o and Xo is a valid frame from o without FIR whose number is neither Ro1's + 1 nor Ro1's. Under C2A: W seen; nothing counted on m; `cnt.o.transport_seq=1`; o's rows as its counts give. Controls: W absent.
8. **D3's C3, substitution under capture loss, pinned "missed"** (6902584812 §4), over UDP: a three-frame write W1, W2, W3; W2 is absent from the capture, and s, a valid frame from m with W2's number and other octets, takes its place, addressed to another link destination (so the device, which received W2, skips s; `inference`). Under C2A and the controls: W absent; nothing counted; no `resync` row; the merged fragment W1 + s + W3 as the builder labels it. It is a pinned residual, not a pass.
9. **(+) D3's C1, the whole segment** (6902584812 §4), over UDP: a three-frame write W1, W2, W3, with D after W2: D carries W2's number and W2's application octets with FIN set. Under C2A: W absent; `cnt.m.transport_seq=1` at D; `cnt.m.first_chunk_missing=1` at W3. Controls: W absent.
10. **(+) `link-retry-last`** (D4's 6902505417 item 4), over UDP: `P R | Rst | A | W1c A | W2c | W2c (retry, same FCB) A | W2c (retry, same FCB) A | R | Q R`, the last segment retried twice. Under C2A: W seen; nothing counted; `rows=none`. Its twin: `... | W2c | X:nofir | W2c (retry, same FCB) | ...`: W seen; `cnt.m.first_chunk_missing=2`. Controls: the retried last frame is a frame without FIR with no fragment, so Q absent.
11. **(+) A FIR that does not follow** (D4's 6902505417 item 6), over UDP: `P R | W R | Q R`, with W1 numbered other than P's last + 1. Under C2A: seen; nothing counted. Controls: seen.
12. **(+) A middle segment lost at the sensor** (D4's 6902505417 item 8; class 2 of section 7, L-3), over UDP: a three-frame response from o with its second frame absent from the capture, so the third frame is the one that fails and nothing of the fragment follows it. Two variants, each its own case:
    - **12a, after confirmation** (`P R` first, then the response): the response absent; `cnt.o.transport_seq=1`; `cnt.o.first_chunk_missing=0`; `rows=o.first@frame3,o.end`.
    - **12b, on a fresh 5-tuple, before confirmation** (the response alone): never named; `cnt.o.transport_seq=1`; `cnt.o.first_chunk_missing=0`; `rows=o.end`; 1 against F.

    Controls, for both: the response absent or misread, as the builder labels it.
13. **D3's N1** (6901282906; D4-111 item 8.2), over UDP and TCP: `P R | W1 | Xo | W2 | R | Q R`, with Xo a `badchunk`, and a twin with `throw`, from o, while o has no fragment in progress. Under C2A: W seen; nothing counted on m; `cnt.o.chunk_crc=1` (or `cnt.o.app_parse=1`). Controls: W absent.
14. **D3's N2 to N4** (6901282906; D4-111 item 8.2), over UDP and TCP, as D3 states them: N2, `X:garbage(16)` then `embed(W5)` in one delivery, `embedded_header=1` and W5 absent; N3, a candidate at offset 2 and one at len − 1 (on TCP, with the 9 octets past the frame in the next segment), each `embedded_header=1`; N4, `overlimit` with an `L` and a `garbage(16)` between two of its frames, `fragment_limit=1` and `transport_seq=0`. Option (a) adds only N4's `transport_seq=0`.
15. **The stock truncated-READ first datagram** (D1's 6907019858 item 4; D4-112 item 4.3), over UDP: a READ too short for its parser as the flow's first datagram, then `P R | W R | Q R`. Under C2A: A's catch is inside `ProcessData`'s loop (section 2.6), which the PIA's replay reaches through `DeliverPacket`, so the throw is counted and parsing goes on: `cnt.m.app_parse=1`; `viol=0`; P, W and Q seen; named at P's fragment; `rows=m.first@P,m.end`. That the replay reaches `ProcessData` is the HR-23 note's reading (§2.3, "A stop that (A) does not remove"), `desk`. Controls: pinned per configuration by D6 (the stock route's rehearsal result is in HR-25's row; (B')'s has no counted run).
16. **D3's M3 to M7** (6907164763 on #718; D1's 6907176282 item 5). Option (a) changes none of them: their fragments are single frames, or (M4) multi-frame with consecutive numbers. Under C2A each takes (i)'s parser choice (the HR-23 note §2.3, rule (A)), and A changes only what a throw does: counted under `app_parse`, `viol=0` before and after confirmation (section 2.6, 2.7), and the messages after it seen. M4's result under (A)'s bound stays `unknown` (the HR-23 note §4.7 item 2), so D6 pins it as a two-branch condition. M7 is a judging token, not an input (every `analyzer.log` row on the flow counted, the PIA's included); option (a) does not change it, and D6 pins each input's count from sections 2.6 and 2.7.

### 3.3 The audit of the pinned rows, and what changes in the pins

- **The audit** (D4's 6902505417 item 9; D1's 6902589450 item 3.2; `desk`). D4 rebuilt every capture of `resync-cases.tsv` with `resync_cases.captures()` at `main` `554f9d12` (302 captures: the 112 cases and their twins and controls), walked each flow's deliveries per end, and applied section 2.3's rule to every whole frame with valid CRCs (8,540 frames), with `badchunk`, `cut`, `embed`, `embedtail`, `zeros` and a lost TCP segment taken as drops, and link-only frames and failed headers as leaving the state. **One capture changes:** `dnp3-resync-udp-link-retry-middle`, whose retried middle segment is discarded instead of appended. No other frame of any capture meets the drop rule or either discard. **It is an unreproduced `desk` reading:** the script was a scratch file, not committed, so no reviewer can rerun it from the repository. It read the builder's output, ran no engine, and modelled the rule, not A's code. D6's audit in deliverable 3 is the one that counts.
- **What changes in the pinned files, before any counted run** (D1's scope ruling on #782). **The case cells are P4-4-HR2325S deliverable 3's (D6):** item 3.5's cases, the six (+) cases, and:
  - `dnp3-resync-udp-link-retry-middle`: the `a` cell narrows from `report` to `P=seen; W=seen; Q=seen; rows=none` (L-3's benign misparse is gone). Its controls stay `report`.
- **The harness items are HR-25's build's (D4), after this design and before A's pins:**
  - `report-no-new-field`: the weird `dnp3_transport_sequence` joins the eight.
  - The closed set in `test_resync_conditions.py`: `transport_seq` after `fir_restart`, fourteen causes.
  - `cov-causes` gains `transport_seq`; `cov-not` gains section 2.9 item 5's check; a new fuzz row pins the mutator's sequence share (section 5).
- **S5 input (8)** goes into row `s5-inputs` in P4-4-HR2325S deliverable 2 (D6), as that brief states (section 2.10).
  - `val-F` (8) stands: conforming traffic with no loss adds nothing to its benign maximum of 5, and a middle segment lost at the sensor before confirmation costs 1, or 2 when a frame of its fragment follows the failing one (section 2.7). D6 weighs whether a start that meets both stays under F.
- **The other sets** (HR-23's cases, the malformed set, the false-positive set, the reruns of section 3's last list): each builder numbers an end's frames consecutively (`hr23_cases.py`, `Flow.frames`), so D4 expects no change, but did not walk them. A difference on any of them under C2A is judged by section 3's rule above: a regression of A, or a finding.

## 4. Build and pins (D7's C1 to C6)

- **C1. Two patch files, one build.** (i)'s patch and A's patch, each pinned by SHA-256 in `modules/telemetry/experiments/engine-linux/zeek-patch/`. A's patch is made against the tree with (i) applied. The pinned build script applies them in that fixed order with no fuzz (`git apply`, or `patch --fuzz=0`), and the build fails if either does not apply cleanly. Every other input is (i)'s, as the HR-23 note §4.5 lists it: the tarball and its `.asc`, the committed key, the base image by digest, the configure line word for word, and the package versions.
- **C2. One image ships.** The counted run measures the (i)+A image by digest, and that is the image the release carries. The (i)-only image and the unpatched image are controls and fuzz baselines, and never ship. The run's log records the SHA-256 of the `zeek` binary in the (i)+A image, `zeek -NN`'s output, and the image's file list with each file's SHA-256 (D7's N3). `zeek -NN` shows which analyzers load; the file list shows which third-party files the image carries, which the inventory, the sensor's SBOM (AP-30) and C6's GPL point need.
- **C3. The rollback floor.** Once an (i)+A image ships, it is the sensor image's rollback floor and replaces (i)'s in R-4, since rolling back to (i) alone reopens HR-25 without a sound. D7 records it in `docs/release.md` §5 when a build exists.
- **C4. Readers before writers for the count.** The C13 minor that carries the per-flow count to the node follows D4-61: the node build that reads it ships, and is named in the release record, before any sensor image writes it. A node rolled back below that build never meets a sensor that writes the count.
- **C5. The notices.** Each modified Zeek file in the patches keeps its BSD-3-Clause notice. That notice is one line pointing to `COPYING` in Zeek's distribution, so `zeek-patch/` holds a verbatim copy of Zeek 9.0.1's `COPYING` (SHA-256 `1f984adb6b5cd93d5035c2a87c2df5f38922649fbea90c7bd79ff321d17333aa`, `desk`, read from the pinned tarball), and each patch file's header, the fuzz harness's patch included, names Zeek 9.0.1 and that copy (D7's N2). Without it, the public repository would carry Zeek's lines without the text that BSD-3-Clause clause 1 asks for. The project's own lines stay under `LICENSE.md` until the owner decides. The fuzz harness's changes (section 5) are pinned by SHA-256, the same for all three builds, and never shipped. If the owner grants an upstream offer, the grant names each patch by SHA-256. **Any report to Zeek's maintainers waits for the owner's word,** under the HR-23 note §4.6's disclosure rule, grant or no grant.
- **C6. The configure line's Spicy setting: on.** The HR-23 note §4.5's configure line has no `--disable-spicy`, and Zeek 9.0.1's top-level `CMakeLists.txt` builds the bundled Spicy (`add_subdirectory(auxil/spicy)`) under `if (NOT DISABLE_SPICY)` (`desk`). A's configure line is (i)'s word for word (C1), so the (i)+A image carries Spicy's runtime and its bundled code as (i)'s does.
  - **A does not turn it off,** and D4 does not propose turning it off. With Spicy off (D7's N1, read from the tarball, `desk`; D4 checked the Syslog, Finger and WebSocket `CMakeLists.txt` again, not `BuiltInSpicyAnalyzer.cmake`):
    - LDAP, PostgreSQL, QUIC and Redis would not be built;
    - Syslog and Finger would fall back to their unmaintained binpac `legacy/` analyzers: both folders' `CMakeLists.txt` call `spicy_add_analyzer(… LEGACY legacy)`, and `cmake/BuiltInSpicyAnalyzer.cmake` builds the legacy analyzer with a warning when Spicy is off;
    - WebSocket's binpac analyzer is built either way; its Spicy form is added only `if (USE_SPICY_ANALYZERS)`.

    SSL's Spicy form needs `--enable-spicy-ssl`, which the line does not set. Turning Spicy off would be a change to (i)'s pins, for D1 and D7, with its own rerun.
  - **Which Spicy analyzers the engine loads and attaches at run time is `not read`** (D3's question in 6893081185). The counted run records `zeek -NN`'s output from the (i)+A image beside the binary's SHA-256, so the list is measured, not inferred.
  - **The licences.** D7's table of `auxil/spicy/3rdparty/` (6885160234, C6) is owed to the inventory, with D7's correction in 6893255626: eleven folders, not ten; the missing one is `tinyformat/`, under BSL-1.0, whose licence text is in `tinyformat.h` itself. The GPL-3.0-only text under `json/` is mapped by D7 (6893255626, `desk`): `json/.reuse/dep5` applies it only to `tests/thirdparty/imapdl/*`, one Python test helper that is not compiled or linked. It applies to the image only if the image carries Spicy's source tree, which C2's file list shows; D4-105 item 7 stays open until that list exists. What of `3rdparty/` is linked into the runtime is `not mapped` until the first build's link map. All of it is a finding against (i)'s image, which D7 carries into `docs/release.md` with the first build's inventory entry. It does not block this design.
- **The fuzz builds** use the same base image by digest and compiler as the shipped image (D7's request), so that "a different build from the sanitizer one" stays the only difference.

## 5. The fuzz run (D1's terms in 6864990229, as the HR-23 note §4.6 states them; D6's T12 to T14)

- **Three builds:** (i) with A, (i) alone, and unpatched; ASan and UBSan, UBSan not recovering. One harness for all three, pinned by SHA-256.
- **The custom mutator** leaves a pinned share of headers and chunks with bad CRCs, instead of fixing every one, with `-seed` pinned.
- **The mutator's sequence share** (option (a); D1's 6902589450 item 3.1). Without it, almost every mutated multi-frame seed fails section 2.3's rule at its second frame, and the append arm and every path inside a fragment would be reached rarely. So, after each mutation and before it recomputes the CRCs, the mutator renumbers, on each end, every frame without FIR that follows a frame on that end, to the previous frame's number + 1 mod 64, with probability 1 − p, and leaves the mutated numbers with probability p, drawn from its Seed argument as the bad-CRC share is. Proposed p: 0.125, the bad-CRC share's value (`fuzz-badcrc`). D6 pins it in a new row beside `fuzz-badcrc`. This changes the fuzz harness, whose changes section 4 pins by SHA-256 (in its C5), the same for all three builds.
- **The gap flag** (T12):
  - **It uses bit 7 (`0x80`) of the `FuzzBuffer` flag byte, not bit 1.** Zeek's `dnp3_tcp` seeds set `0x02` on responder chunks (D6's reading; `FuzzBuffer::Next` reads only bit 0, `desk`).
  - **The job's check on bit 7, before it runs** (D6's B5): no seed from Zeek's `dnp3_tcp` corpus, the malformed set or the HR-23 cases sets bit 7. In the converted `dnp3-resync-*` cases, bit 7 is set exactly on the chunks that the conversion script records as holes, and the job checks those chunks against the holes that the cases label. That the stock seeds set no bit 7 is `not read` by D4; the job's check settles it.
  - **The gap is the chunk's own octets,** dropped and passed to `NextUndelivered` with their length, so the mutator varies both where a gap falls and how long it is. `seq` is the running offset of that direction.
  - **The UDP target ignores the bit.**
  - This changes `FuzzBuffer.h`, `FuzzBuffer.cc` and `generic-analyzer-fuzzer.cc`'s TCP `NextChunk`, all harness files under C5.
- **The pass rule over three builds** (T13). A report counts against A when it reproduces on (i) with A and not on (i) alone. It counts against (i) when it reproduces on (i) alone and not on the unpatched build. The guard-not-reached condition applies to the corpus of (i) with A only; on the other two builds lengths 1 to 3 reach `AddToBuffer`'s guard by design. Every other term of §4.6 holds: replay inside the job, `unknown` counted never dismissed, and the disclosure rule.
- **The coverage condition, per target** (T14; D3's S2):
  - **Both targets:** each cause's branch in section 2.8's set, `invariant` and `fragment_limit` excepted (below); the drop function; both arms of its branch on a fragment in progress, the remake on an end with one and no remake on an idle end (D6's B7, section 2.6; D6's N6); deleting an interpreter that holds an incomplete unit, and a parse on that end after it (S2's ASan targets); the 10-octet link-only path; the length 0 to 4 path; the embedded-header check; and the pre-confirmation budget, if D6's values make it reachable (section 2.7); and option (a)'s three arms of section 2.3 (append, discard of an identical repeat, `transport_seq`), with the discard after FIN. The wrap from 63 to 0 is a mod, not a branch, so its stage-2 case shows it, not coverage (section 3.2 item 4).
  - **The UDP target:** the reset at a datagram's end with a fragment open, and the scan inside a datagram.
  - **The TCP target:** the gap path, and the scan across chunks.
  - **Must show as not reached:** each `AddToBuffer` and `ParseAppLayer` guard, the `pkt_length <= 0` check and the length check before the copy into `last_seg` (section 2.9), and the catches in `DeliverStream` and `DeliverPacket` (section 2.6, D6's N1). A reach is a finding.
  - **Left to its stage-2 case, and stated:** `fragment_limit`, which 100 KiB puts out of reach within 64 chunks, unless D2's answer lowers the shipped value (section 2.11). T4's counter no longer exists.
- **The seeds:** Zeek's `dnp3_tcp` corpus, stage 2's malformed set, the HR-23 cases and the `dnp3-resync-*` cases, converted by the pinned script.
- **Runner time:** 2 targets × 3 builds × 30 minutes. One job per target holds its three campaigns, every replay and the coverage replay; no input leaves the job. Each job's wall time is stated against GitHub's 6-hour limit per job. If the coverage condition is not met at 30 minutes, the result is `unknown`, and D1 rules a longer run; the run is never repeated with new seeds until it passes.
- **Unchanged:** the job publishes only pass or fail and its counts, and a crash goes to the owner for disclosure before anything about it is public.

## 6. The H-rows, widened (D2's C3)

R-6's second H-row (HR-23 note §6) is widened. Written, not run. It runs only with the owner's authorization for device contact, on an out-of-service bench unit, sending reads (code 1) only, never a write, operate, restart or time set. On TCP and on UDP, it shows what an SEL device's link layer does:
- after a bad header CRC: scan, or drop the rest of the datagram (A.3's choice);
- after a header with a length of 0 to 4: consume 1 octet or 10 (D2's C1);
- after a bad chunk CRC: skip by length, or scan (D3's N9; D2's C2);
- **the transport sequence on the device's own multi-frame responses** (option (a); D4-112 item 3.4; D2's and D3's condition): with reads that produce responses of more than one segment (a class 0 or event read large enough), record each segment's FIR, FIN and number. That settles class 1 of section 7, L-3, for SEL: whether the device steps its numbers by 1.

**No out-of-sequence request, and no other malformed request, is ever sent to a device** (D4-112 item 3.4). Class 1 is about what the device sends, so the reads above settle it. D1 numbers the row.

## 7. Limits

- **L-1. Everything here is `desk`.** Nothing is built or measured. The routes close only on deliverable 3's counted run.
- **L-2. A device that reads the bytes differently from the sensor** is not fixed by any option. Section 6's H-row is what tells.
- **L-3. The transport sequence: checked, on a receive rule that is `inference`** (section 2.3; option (a), D4-112 item 3). The check follows D2's recollection of IEEE 1815's receive rule (6902526389), not the standard's text, which the project does not hold (D4-112 item 3.4). Its mechanism does not depend on the answer to the open question, whether a device that gets a wrong number drops the segment or the fragment: either way the sensor counts the divergence (section 2.3). What it leaves:
  - **The two quiet residuals** of section 2.3: substitution of a segment the capture never delivered (its case pinned "missed", section 3.2 item 8); and the duplicate rule's over-report, which can log a write the device rejected and cannot hide one.
  - **Class 1, a loud false positive: a sender that does not step its numbers by 1** after a FIR (a non-conforming stack, or one that repeats the FIR's number). Every multi-frame fragment from that end is dropped and counted, which blinds that end's multi-frame fragments, loudly; its rows count against K, so such a site also spends the host cap. A conforming device would discard those segments too (`inference`), so such a stack would not interoperate. A stack that restarts its numbering at each fragment, or starts at 0, is not in the class, since a FIR accepts any number. **For SEL it is `unknown`:** no manual D2 holds states the rule and no capture exists; section 6's H-row settles it.
  - **Class 2, coverage loss made visible: a middle segment lost or reordered on UDP** at the mirror or on the path. Before (a) that was a quiet misparse; under (a) it is `transport_seq`, a row after confirmation and an `end` row before it, and 1 against F, or 2 when a frame of its fragment follows the failing one (section 2.7). It is a loss of coverage, not a false alert about the device, which discards such a segment too (`inference`).
  - **Removed by (a):** the benign misparse of a link-layer retry of a middle segment (D2's non-blocking (a) on the re-read: with confirmed user data, link function 3, the retry carries the same FCB and the device's link layer acknowledges it without passing it up, `inference`), which is now discarded and seen exactly once; a retried last segment, which is discarded rather than counted; and a PRP duplicate of a middle segment that leaked past the frame stage. A retried first frame stays `fir_restart`, and a retried single-frame fragment is parsed twice, an over-report as today.
  - **Not a class:** a device that resets its sequence (a FIR accepts any number, and a reset inside a fragment loses that fragment at the device too); a sensor that joins inside a fragment (`first_chunk_missing`, as before); the wrap from 63 to 0 (mod 64).
- **L-4. Not read:** the generated parser's handling of `eof_` after the first fragment (section 1 item 6); when `dnp3_header_block` is raised for a fragment that then throws (section 2.7); the result of an unknown object in a request, and the response side's default in full (section 2.7); which Spicy analyzers load (section 4, C6); the event queue's order (section 2.8); that `Done` runs for a UDP connection's analyzers (section 2.8); that the connection record is freed at its removal (section 2.8).
- **L-5. The cost per fragment** is not measured until deliverable 3 (section 2.10).
- **L-6. The node sees nothing of the count** until the C13 minor exists (D4-102 item 9).

## 8. HR-25's row: the text to add with this note (D3's S8; D6's T5 and T10)

D3 writes HR-25's row (D4-101 item 6), and updates it with this note in its records PR (D4-106 item 2.3). This note does not edit `docs/threat-model.md`. The text D4 proposes to D3 for the row, under the fix:

> **The fix chosen: Option A** (D1's ruling 6893095629 on #690, D4-106; `docs/phase4/D4-hr25-design.md`), not built. Under it, these routes stay open, each counted and never quiet:
> - **Insertion** (D3's S8 in 6893081185). A frame that the sensor sees and the device never receives, such as a unicast to a MAC that no switch port owns, flooded to the mirror port, or a frame the device's NIC drops, can trigger any cause at the sensor without changing the device's state. On UDP the design bounds the scan and the drop to the inserted datagram, so it can cost the sensor only that end's fragment in progress (`fir_restart`, `first_chunk_missing` or `truncated`). A single-frame write (FIR and FIN in one frame) cannot be hidden this way. **A multi-frame write can be hidden.** It is counted, never quiet: in the probe log by the flow's `end` row (`first_chunk_missing`, `gap`), whether or not the flow confirms. *[Superseded under option (a): an inserted middle segment with valid CRCs is counted under `transport_seq`; see "Under option (a)" below.]* On TCP, insertion is an overlapping segment, which is HR-24's (`rexmit_inconsistent`; CH-53, CH-54). The node sees the count only once the C13 minor carries it (D4-102 item 9).
> - **The budget before confirmation** (D6's T5). Once the connection's failures reach F, or its octets reach O, before the first whole fragment, the analyzer stops on that connection and writes a `budget` row. A session that follows on the same 5-tuple is then unseen, though the flow is visible.
> - **The host cap** (D6's T10). Every `resync` row but the overflow row counts against K per interval. A failing flow beyond K rows, a `budget` or `end` row included, is visible only in the host's overflow count, so a sender can crowd an insertion's `end` row into it.
> - **A device that parses differently** stays open until the widened H-row (the design's section 6) is run, with the owner's authorization.

**Under option (a)** (D1's 6902589450 item 4; D3's 6902584812 §3; D4-112 item 6). Once this revision merges, HR-25's row changes its sentence on the inserted middle segment, which states today's design ("quiet today, not counted, unless the merged fragment throws"). It also supersedes the block above's sentence on an inserted middle segment, as marked there. D3 writes the row; the text D4 proposes for it:

> **A valid middle segment that the device skips is counted under option (a), never quiet; the write itself is unseen** (`docs/phase4/D4-hr25-design.md` §2.3; D4-112 item 3). Option A checks the transport sequence on every frame without FIR. A segment out of sequence drops the fragment in progress under `transport_seq`; an identical repeat, compared as the whole segment, FIN and the number included, is discarded and not counted. It does not need insertion: a master's own stream reaches the device's link-layer filters (another destination address, or FCV set with a repeated FCB; `inference`, D2's 6902526389 §1), on UDP and TCP, and a sender that controls its stream can split any write, so "a single-frame write cannot be hidden" holds only for a third party's insertion. Each such route gives `transport_seq` at the skipped segment or at the next one, and `first_chunk_missing` for any frame of the fragment after it: after confirmation a row, before it an `end` row. The cause list in this residual gains `transport_seq`. **Two quiet residuals stay** (D4-112 item 3.3): substitution of a segment the capture never delivered to the sensor (pinned "missed"); and the duplicate rule's over-report, which can log a write the device rejected but cannot hide one. A stack that does not step its numbers by 1 is loud, and `unknown` for SEL until the widened H-row runs; its rows count against K. The receive rule is `inference` until IEEE 1815's text is held. Not built and not measured: nothing here is "closed" or "measured" before HR-25's counted run.

## 9. Where each condition is answered

| Condition | Answered in |
| --- | --- |
| D1: Option A, on top of (i) | Opening section |
| D2 C1: consume 1 after a bad length | §2.1; case in §3 |
| D2 C2: flag a header inside skipped octets | §2.2; cause in §2.8; case in §3 |
| D2 C3: widen the H-row | §6 |
| D2 non-blocking: the sequence number | §2.3; §7 L-3 |
| D2 non-blocking: the skip counter on UDP | §2.2, §2.4 (no counter; `truncated`) |
| D2 on A.3: the cause on rows after a scan | §2.8 |
| D2 on A.3: 9 octets across a segment | §2.1 |
| D2 on A.8: unknown object, 2-octet fragment, link-only flows | §2.7; case in §3 |
| D2's frame-length formula | §1 item 2 |
| D6 T1: labels and judge | §3 |
| D6 T2: every drop remakes that end's interpreter | §2.6; §1 item 6 |
| D6 T3: the catch inside the loop | §2.6; case in §3 |
| D6 T4: no input reaches the skip counter | §2.2 (dropped) |
| D6 T5: the budget, two bounds, `skip` set by the analyzer | §2.7; cases in §3; residual in §8 |
| D6 T6: naming, a cheap whole fragment, rows on unconfirmed flows | §2.7; §3 |
| D6 T7: generators check every `05 64` | §3 |
| D6 T8: `invariant` and `truncated`; the weird for length 0 | §2.4, §2.8, §2.9 |
| D6 T9: cases that tell the consumption rules apart; the measure of progress | §2.1; §3 |
| D6 T10: first row, interval rows, host cap, existing weirds bounded | §2.8; §3; residual in §8 |
| D6 T11: changed expectations; `FlowEOF` at the end, per end | §2.6; §3 |
| D6 T12: the gap flag, not bit 1 | §5 |
| D6 T13: the pass rule over three builds | §5 |
| D6 T14: the coverage condition per target | §5 |
| D7 C1: two patch files, fixed order, no fuzz | §4 |
| D7 C2: one image ships | §4 |
| D7 C3: the rollback floor | §4 |
| D7 C4: readers before writers | §4 |
| D7 C5: notices; upstream report waits for the owner | §4 |
| D7 C6: the configure line's Spicy setting | §4 |
| D3 S1: one reset for every drop | §2.6 |
| D3 S2: the interpreter's lifetime | §2.6; ASan targets in §5 |
| D3 S3: `binpac::Exception` only | §2.6 |
| D3 S4: constant cost per octet in the scan | §2.1; §2.2 |
| D3 S5: cost per fragment, measured and bounded | §2.10 (measurement owed by deliverable 3) |
| D3 S6: consume 1 after a bad length; C2 as written | §2.1; §2.2 |
| D3 S7: the scan on UDP | §2.1; §2.8 |
| D3 S8: insertion, a residual | §8 |
| D3 S9: memory and crash containment | §2.11 |
| D3 B4 (1) to (4), B5, N6 to N9 | §2.9; §2.8; §2.7; §2.6; §2.8; §6 |
| D6 B1 (a) to (c), items 4 and 5; B2 items 1 and 2 | §2.7; §2.5; §2.1; §2.1 to §2.3; §2.8; §2.8; §3 |
| D2 B1, N1, N2 | §2.2; §2.1; §2.1 and §3 |

**The re-reads at `ec42b475`:**

| Finding | Answered in |
| --- | --- |
| D2 B1: the embedded-header check over offsets 1 to len − 1, 291 octets | §2.2; case in §3 |
| D2 B2: a run of `first_chunk_missing` counts once against F, not against O | §2.7; case in §3 |
| D2 non-blocking (a): link-layer retries | §7 L-3 (fixed) |
| D2 non-blocking (b): F unknown-object fragments in a row | §3 (fixed) |
| D7 N1: which analyzers need Spicy | §4 C6 |
| D7 N2: Zeek's `COPYING` beside the patches | §4 C5 |
| D7 N3: the image's file list with hashes | §4 C2 |
| D7's correction: `tinyformat`, eleven folders | §4 C6 |
| D6 B1: the `end` row of a flow that never confirms | Ruled (b), below (history: answered by D1's ruling 6893581874) |
| D6 B2: the budget's accounting | §2.1 (scan run's end); §2.4; §2.7 |
| D6 B3: the `first` row at confirmation, the interval's anchor, cumulative counts, the host cap | §2.8; cases in §3 |
| D6 B4: R for replacements; `budget` after confirmation; the order | §2.10 |
| D6 B5: bit 7 on the converted cases' holes | §5 |
| D6 N1 to N5 | §2.6 and §5; §3; §2.6; §2.10; §2.2, §2.3 and §3 |
| Auditor (1): `truncated` before confirmation | §2 (opening); §2.1; §2.4; §3 class (1) |
| Auditor (2): T2's evidence class | §1 item 6 |
| Auditor (3): the PR's title and body | the PR |
| Auditor (4): HR-25's row is D3's | §8 (the row is not edited) |

**D1's rulings 6893581874 at `b44cccf6`:**

| Ruling | Answered in |
| --- | --- |
| D6 B1, option (b): the `end` row of a flow that never confirms, on `app_parse`, `fragment_limit`, `embedded_header`, `first_chunk_missing` or `gap` | §2.7 (rows on flows that never confirm; the run of `first_chunk_missing`); §2.8 (`why = "end"`); §3 (the throwing write, the insertion case, the false-positive set's redraw and (3c)); §8 (insertion, host cap) |
| D6 B7, option (b): no remake for an end with no fragment in progress | §2.6 (the drop function; no remake for an idle end; the cost); §2.7 (the run of `first_chunk_missing`); §2.10 (the S5 input; the bound before confirmation); §3 (the idle-end case) |
| D6 B6: the overflow row does not count against K | §2.8 (the host cap); §3 (the K + 1 case); §8 (host cap) |
| D3 BM: where the pending `dnp3_resync_mark` is held, freed with the connection | §2.8 (the cause on rows after a resync); §3 (the pending-mark case) |
| D3 N1: S5's measurement with the shipped script loaded | §2.10 (the measurement) |

**Option (a): D1's ruling 6902589450 on #714 (D4-112 item 3), with D2's conditions (6902526389 §3) and D3's (6902584812 §4):**

| Condition | Answered in |
| --- | --- |
| D4-112 item 3.1: the sequence checked on every frame without FIR; `transport_seq`; an identical retry, compared as the whole segment, discarded and not counted | §2.3 (the rule, the state, the duplicate after FIN); §2.2 (step 2); §2.6 (the drop function); §2.8 (the cause and its weird); §3.1 (each rule's test and control) |
| D4-112 item 3.2: F1 counted, in D4's wider form too | §2.3 (why every divergence is counted); §3.2 items 1 to 3, 5 and 6; §8 (the row's text) |
| D4-112 item 3.3: the quiet residuals named | §2.3 (the quiet residuals); §7 L-3; §3.2 item 8; §8 |
| D4-112 item 3.4 and D2's condition 1: the receive rule labelled `inference` | §2.3 (the receive rule); §7 L-3; the opening |
| D4-112 item 3.4, D2's condition 3 and D3's: any SEL check read-only, recording the sequence, with the owner's authorization; no out-of-sequence request | §6 |
| D4-112 item 3.5: the cases for P4-4-HR2325S | §3.2 items 1 and 3 to 8, and 13 to 16; the audit in §3.3; S5 input (8) in §2.10. Items 2 and 9 to 12, and item 1's twin before confirmation, are marked (+); deliverable 3 takes them (D4-122) |
| D1's 6902589450 item 3.1: §2.10's cost with S5 input (8), and the mutator's sequence share | §2.10; §5; §3.3 (the pins that change) |
| D4-112 item 3.6 and D3's C4: the order (this note, then deliverable 3's cases, then A's patch and pins) | This note changes no pin and no code; §3.3 lists the pin changes for deliverables 2 and 3 |
| D2's condition 2: the link-layer variants pinned, expected counted | §3.2 items 5 and 6 |
| D3's C1: the whole segment compared, with its case | §2.3 (rule step 2); §3.2 item 9 |
| D3's C2: per-end isolation pinned over UDP and TCP | §2.3 (the state is per end); §3.2 item 7 |
| D3's C3: the substitution residual pinned "missed" | §2.3; §3.2 item 8 |
| The new state's parse surface: a fixed 250-octet buffer per end, a bounded copy | §2.9 item 5; §2.11; §5 (not reached) |
| The `end` row on a flow that never confirms | §2.7 (six counts); §2.8 (`why = "end"`) |
