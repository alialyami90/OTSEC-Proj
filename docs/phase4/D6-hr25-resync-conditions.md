# D6: HR-25's cases and pass conditions (P4-4-HR25, deliverable 2)

D6, 2026-11-15. Brief P4-4-HR25 (`docs/agent-handoffs.md`), deliverable 2: the `dnp3-resync-*` cases, each naming its transport, and their pass conditions, pinned before any counted run. D4 wrote the design, `docs/phase4/D4-hr25-design.md` on #690 at `a5fe07616775096e3910a5e5d9882856206e75e9`. No D6 instance wrote any of it, and this instance did not write any of the comments it answers.

- **The conditions are two files, and they decide; this note explains them.**
  - `tests/integration/gt_pcap/resync-cases.tsv`: 106 cases, one row each, with the configuration each expectation holds under, and 185 twins (section 3.3).
  - `tests/integration/gt_pcap/resync-conditions.tsv`: the judge, the values, the false-positive set, the changed expectations, the reruns, the reporting, the fuzz pins, the coverage condition, S5 and the static checks.
  - `test_resync_conditions.py` pins both by SHA-256 (LF line endings, as Git stores them), and checks the rules in section 10 against them. The cases file's SHA-256 is `2cc2cd0c979d284b9cad01f448fd47626f4a6aff4930f448698d461547b72c0b`, and the conditions file's is `92115208781ac125bd9ceeffd8913d7fcf9abf35b1e6c394f75eaed0b07eb5dd`.
- **Where they are pinned for the run** (row `pin-files`): D4 adds `RESYNC_CASES_SHA256` and `RESYNC_CONDITIONS_SHA256` to `modules/telemetry/experiments/engine-linux/pins.env` in deliverable 3, with the values the test holds. D6 does not edit D4's files. A run with other files is a rehearsal (row `judge-counted`).
- **Evidence class: `desk`.** Nothing was built, captured or run against any engine. No device or network was contacted, and no session content was read.
- **Zeek's code** is read from GitHub at the tag `v9.0.1`, by file, with these SHA-256s. The first six match the HR-23 note's table, and `FuzzBuffer.h` matches the HR-25 note's.

  | File | SHA-256 | Read for |
  | --- | --- | --- |
  | `src/analyzer/protocol/dnp3/dnp3-protocol.pac` | `497eeac4504d8d925d4b35ec9e5c8950b7d3309d2b7a96b644e1c500312279b1` | the arms (rows `arm-g0`, `arm-3bdata`) |
  | `src/analyzer/protocol/dnp3/dnp3-objects.pac` | `0ba3df0cab28933f6729d6cab06d9b5c0d88bb9554c9b4a89caeb5b6b24dc493` | hashed only |
  | `src/Reporter.cc` | `9bdb6c0597165da9476988e4768905c8ecf28e53b3f3ee5334e5663646b44dac` | `PermitNetWeird` (row `report-weird-sampling`) |
  | `scripts/base/protocols/dnp3/main.zeek` | `37f51eab720db2d744ef229c0a10b0fbcd90a131b859f5500f4665a51258d2cd` | `register_for_ports` names only `DNP3_TCP` |
  | `scripts/base/protocols/dnp3/dpd.sig` | `b2067b53fca4dff949c837928e94af647318cc4937d8a37fac3be5d62488a402` | `dpd_dnp3_server_udp`: a payload that starts `05 64` |
  | `src/fuzzers/FuzzBuffer.cc` | `49d59eb9abfbd409da32fe3847fbb57aeffa21ef943d6641dbac87b2c104e2b5` | hashed only |
  | `src/fuzzers/FuzzBuffer.h` | `1b44c833b085ec8b709360dbfa3ef2014af0454ab0603b7fdc2d8c74b6185742` | `MAX_CHUNK_COUNT` 64 |
  | `scripts/base/frameworks/notice/weird.zeek` | `a8b6e5253d06f88e00dd72204de9b87df75f39539ed29b9753239c47d6bcc40f` | `do_weird` and `weird_ignore` (row `report-weird-log`) |
  | `scripts/base/init-bare.zeek` | `05e960679cdc6832276c35f8dc2623bce3fa786555cbf80a4a4f19cd9cc4c675` | the sampling options, `udp_inactivity_timeout`, the fragment limit |

- **Inputs:** the design note's sections 2, 3 and 5; D1's rulings 6893095629 and 6893581874 on #690; D6's lists 6885310412 (T1 to T14), 6893379733 (section 4, twelve groups), 6893532533 (its additions) and 6893732701 (the `gap` case and the third count); HR-25's row in `docs/threat-model.md` (its "When it closes", from D1's 6879752967 item 5); `docs/phase4/D4-hr23-design.md` section 4, HR-23's stage 2, whose own pins D6 has not yet written; `docs/phase4/D6-engine-run-pass-conditions.md` and the GT-PCAP code.
- **What this PR is not:** the builder and the captures. Section 9 says what is owed before the counted run.

## 1. The configurations and the judge

**Four configurations, in one run** (rows `cfg-*`). C0, C1p and C2 are the HR-23 note's (section 4.1): the engine as on `main`, the project's build without a patch, and the option (i) build. C2A is the (i)+A image named by digest, the image that ships, with the shipped script. HR-25's row names the first three as the controls. C2 is also the baseline that A is judged against in the reruns.

**The judge** (rows `judge-*`):
- **Labels come from how a case was built** (T1). tshark is reported beside them, never used as the label.
- **Rule 6 of the engine run's conditions does not hold here.** A function row on a case's flows that the labels lack fails the case. Rule 9 holds with an exact count: a misparse after a drop shows as one more row than the labels hold.
- **Defaults under C2A.** Unless a case's cell names it: every cause is 0 on both ends, no `dnp3_` weird is in `weird.log`, no violation, no `budget` row, no reporter error, no crash. A cell's `rows=` lists every `resync` row of the flow.
- **The controls validate the case.** A route case is valid only when C0, C1p and C2 each show its `ctl` cell, which for the route cases is `W=absent`. If a control sees W, the case did not reach the failure, and it reads `unknown` for the fix, never `pass` (the HR-23 note's rule in section 4.2).
- **Route closure** (row `judge-route`). The run reports, per route, n of m cases that pass and are valid. HR-25 closes only if all do. A route with a failing or `unknown` case stays open in HR-25's row.

## 2. The values

| Value | Pinned | Why |
| --- | --- | --- |
| F, failures before confirmation | 8 | The benign maximum is 5. A TCP sensor start that lands inside a frame on each end, before a frame without FIR on each end, costs 4: two scan runs and two runs of `first_chunk_missing`, one of each per end (`dnp3-resync-tcp-r2-midstream-both`). A link-layer retry of the first frame costs 1 more (`dnp3-resync-udp-link-retry-first`). D2's join after the first frame of a 2,048-octet response costs 1 (`dnp3-resync-*-join-response`). A master that reads g0 first costs nothing if g0 parses, which `arm-g0` reads it does. |
| O, octets before confirmation | 2,048 | The benign maximum is 582: a scan of at most 291 octets per end at a TCP sensor start. Runs of `first_chunk_missing` do not count against O. |
| K, rows per interval across the host | 100 | The design's value. |
| `DNP3::resync_report_interval` | 60 s | The design's value. |
| The fragment limit | 102,400 | Zeek's value, kept by the shipped script until D2 answers S9. If it changes, the three fragment-limit cases are rebuilt from the new value by the same rules, in a new commit of both files. |
| S5's ratio | at most 5 | Section 8. |
| R, replacements per delivery per end | 16 | Only if S5's ratio is exceeded and the bound is added. |

The values are D6's choice, `desk`. Both of F and O are reachable by the fuzz harness: 8 failures fit in 64 chunks, and 2,048 octets plus a session fit in `-max_len` 4,096.

## 3. The cases

### 3.1 How a case is written

- **The `build` column** is a sequence of messages. `|` separates datagrams (UDP) or segments (TCP), and `+` joins messages within one. Every message is in its own datagram or segment unless joined. Row `builder-msgs` names every message (P, R, W, Q, G and the rest), the endpoints and the link addresses. Row `builder-failures` defines every failure (`garbage(n)`, `badhdr`, `len(k)`, `badchunk`, `nofir`, `firopen`, `throw`, `cut`, `holds`, `embed`, `embedtail`, the link-only frames). The other `builder-*` rows hold the solved headers and the arithmetic.
- **The write is W,** the master's direct operate: code 5, g12v1, as the design's section 3 sets. Each route case has two master fragments after the failure, W and Q, so a remade interpreter parses twice (6893379733 item 2).
- **The failure is on W's own end** (T2), unless the case says otherwise.
- **The `a` column** is the expectation under C2A, as `;`-separated assertions:
  - `W=seen` or `W=absent` (row `judge-seen`);
  - `cnt.m.chunk_crc=1`, a cumulative count from the flow's last `resync` row, with `m` the master's end and `o` the outstation's;
  - `scanned.m=8`;
  - `rows=m.first@X,m.end`, every `resync` row with its time (row `judge-times`);
  - `named@P` or `named=no`, under `conn.log`'s reading;
  - `weird.<name>=n`, rows in `weird.log`;
  - `viol=n`;
  - `cause@P2=chunk_crc`, the `resync_cause` field on that message's `fc` row.

  `note:` tokens explain and are not judged.
- **The `ctl` column** is expected under each of C0, C1p and C2.

### 3.2 The cases, by route

| Route | UDP | TCP | What |
| --- | --- | --- | --- |
| R1, a failed frame then a write | 24 | 25 | One case per cause, after confirmation: `magic`, `header_crc`, `link_length` (0, 1, 3, 4), `chunk_crc` on an idle end and with a fragment in progress, `first_chunk_missing`, `fir_restart`, `fragment_limit`, `app_parse`, and over UDP `truncated`. The failure and W in one datagram or segment, for `chunk_crc` and for a throw (D2's B1, T3). D2's C1 at each length 0 to 4. T9's false `05 64` across a segment. D3's embedded frame, whose `nowrite` twin is D2's C2. D2's B1 on the re-read, in one datagram, in one segment, and in the next segment. D2's N2. A burst of 2,000 garbage datagrams, and 64 KiB of garbage across 45 segments. |
| R2, a bad header before confirmation then a session | 3 | 3 | At the capture's start, after an idle spell longer than `udp_inactivity_timeout`, after the TCP handshake, and a TCP sensor that joins inside a frame on one end. F − 1 failures, and O − 1 octets in one failure. |
| R3, a TCP gap that splits a frame then a write | | 3 | A gap inside a header, inside a frame's data, and before the octets past a failed frame whose tail starts a header (D2's B1, the gap twin). Each is valid only under R3's rule (row `judge-r3`). |
| R4, a link-only frame then a write | 3 | 4 | In two deliveries and in one, over each transport; the relay's TCP heartbeat, its link-status request and the master's link status; a link-only frame between two frames of one fragment (D6's B1 (c)). |
| No quiet failure | 1 | 1 | One throwing write alone on a fresh 5-tuple (D6's B1, ruled (b)): never named, the master's `end` row with `app_parse`. Its control names the flow and raises a violation. |
| Insertion | 4 | | S8's residual: a multi-frame write with a datagram inserted between its frames, under 10 octets and with a bad chunk CRC, on a fresh 5-tuple (never named, the `end` row with `first_chunk_missing`); the same answered by the device, which confirms the flow at its response; and the same after confirmation, where W is unseen, counted, and Q is still parsed. |
| Budget | 4 | 1 | F reached on one end, and split across the two ends with F − 1 beside it; O reached in one failure; F reached above 10 KiB, reached with link-only frames that spend no budget, so that only the analyzer's own `skip` hides the session. |
| Benign | 5 | 3 | D2's join after a response's first frame, over each transport; a TCP sensor start inside a frame on both ends; D2's unknown object, once and F times in a row; a link-layer retry of a first frame and of a middle frame (L-3); a lost TCP segment whose edges fall on frame boundaries. |
| Invariants | | 10 | T9's `tpflags` case, and W's header split across two segments at each of its 9 split points. Seen under every configuration. |
| Changed | 3 | | One frame split across two datagrams (T8). The fragment limit, at the limit and one octet over (D6's N5). The controls parse both of the last two, because Zeek 9.0.1 checks only the octets already buffered, with `>`, before each chunk. |
| Reporting | 4 | | The interval rows over three intervals; the host cap with K + 1 flows and a `budget` row in one interval and K in the next; `resync_cause` on the next `fc` row only, after a drop and after a scan; D3's BM, the pending mark. |
| S5's bound | 2 | 2 | R − 1 and R throws before W in one delivery. Judged only if the bound is added. |
| A `gap` row on a flow that is not DNP3 | | 1 | 6893732701: exactly one `end` row, on the end with the hole. |

That is 49 cases on R1, 6 on R2, 3 on R3 and 7 on R4, and 41 others.

### 3.3 The twins

Every case whose `twins` cell names them also has these captures (row `judge-twins`):
- **`nofail`:** the case without its failure. P, W and Q are seen under all four configurations, and C2A writes no `resync` row.
- **`nowrite`:** the case without W. No code-5 row under any configuration, and under C2A the case's own counts and rows.
- **`otherend`:** the failure built from the outstation's side, so that W's end is untouched (D3's N7). Under C2A, W and Q are seen and the counts move to `o`. Under the controls W is absent, because `skip` covers both ends, except on R4, where only the outstation's next delivery is lost.

Every route case has `nofail` and `nowrite`. It has `otherend` unless its failure and W share one datagram or segment, which then cannot be split between the ends: D2's C1, T9's false `05 64`, D2's N2, and the cases that join the failure and W on purpose. The test checks that rule both ways.

### 3.4 Points that this pin settles

- **D2's unknown object** (6893379733's N2 on the note). The object is g0v254 with qualifier 06h in a read. `dnp3-protocol.pac` at the tag takes `default -> objects: empty` in `Request_Objects` for a type it does not list, and a qualifier of 6 reads no range. A read's object carries no data, so nothing is left to misread, and the read parses (row `arm-g0`). The two cases pin that branch: if it throws, they fail and the reading is wrong. That `Request_Objects`'s array ends at the end of its record is generated code, not read.
- **UDP attaches by content.** `main.zeek` registers port 20000 for `DNP3_TCP` only, and `dpd.sig` enables `dnp3_udp` on a payload that starts `05 64`. So every fresh UDP 5-tuple in these cases starts with a datagram that starts `05 64`. The budget cases on UDP use `badhdr`, not garbage, for that reason.
- **Rows before and after confirmation.** A failure before confirmation raises no weird and writes no row of its own. Its count reaches the `first` row at confirmation, stamped with the confirming fragment's time (R2's cases), or the `end` row under the five-cause rule, or the `budget` row.
- **The device answers.** In the insertion case on a fresh 5-tuple, the design's section 3 expects the flow never named. That holds only if no response follows. A device that acted on W answers, its response is a whole fragment, and the flow confirms there. Both are pinned: the case without a response, as the design states it, and `dnp3-resync-udp-insert-truncated-answered`. Either way the write is counted, never quiet.

## 4. The false-positive set

Rows `fp-*`. The set is HR-23's UDP classes (1) to (5) with the expectations A changes, plus class (6), non-DNP3 TCP flows on tcp/20000, which `DNP3_TCP` reaches by port. HR-25 needs class (6) because a TCP flow that is not DNP3 is where a `gap` row and a `budget` row fall with no attacker.

| Class | Floor | Under C2A |
| --- | --- | --- |
| (1), (2), (4), (5) | 300 each | Never named under either reading; no `end`, `budget` or `gap` row; no `dnp3_` weird. Zero in 300 bounds the rate at about 1% per class at 95%. |
| (3a) | 30 | Never named under `conn.log` (C0 names it); `chunk_crc` counted; no row. |
| (3b-data) | 30 | Named at its first fragment, as under C0. Its codes come from the arms (row `arm-3bdata`), and it is a false positive recorded under HR-23 (3c) and R-1. |
| (3b-link) | 30 | Never named; no row. |
| (3c) | 30 | Never named, no violation, `app_parse` and one `end` row per item. |
| (6), no hole | 100 | Never named; no `end` row; `budget` rows exactly on the flows the generator labels as reaching O or F. |
| (6), one hole | 30 | Never named; exactly one `end` row, on the end with the hole, with `gap` 1. |

**The redraw** (row `fp-redraw`; T7, D6's B1). The generators of (1), (2), (3a), (4), (5) and (6) compute the header CRC at every offset where `05 64` occurs, and draw again when one passes. Then the classes with no frame whose header and every chunk CRC pass, and no gap, write no row under the five-cause rule, exactly.

**What is reported** (row `fp-counts`): per class and configuration, the flows named under each reading, the `end` rows, the `budget` rows, and the `gap` rows on unnamed flows (6893732701's third count), each with the class's size, never netted out. C1p is the control for the three row counts, since it writes no `resync` row.

HR-23's stage-2 pins, which D6 has not yet written, set the floors of the same UDP classes for HR-23's run. Where they set a larger floor, the larger holds for both runs.

## 5. Changed expectations and the reruns

- **HR-23's malformed set under C2A** (row `chg-malformed`): each input judged against A's rule for it, not against C2. A length of 6 passes on either branch: `app_parse`, or no count, with no crash and no reporter error.
- **The four TCP inputs held at the connection's end** (row `chg-eof`). A chunk failure, or a length of 4, leaves nothing held at the FIN. The other two pass on either branch, `app_parse` on that end or no count, with no crash, no reporter error and no violation.
- **The reruns** (rows `rerun-*`). No row of E-D4-03's conditions that C2 passes may fail under C2A, which is the brief's acceptance test.
  - Per flow, the verdicts and the probe's `link` and `fc` rows are compared with C2.
  - Allowed to differ: a `link` row's time where its frame spans segments, the time of confirmation, and `resync` rows and `resync_cause` where C2A counts a cause.
  - No GT-PCAP DNP3 case starts inside a flow, and HR-23's three cases that start mid-session do so at a whole fragment.
- **Any reporter error under C2A** fails its input (row `judge-reporter-error`), because the design makes every guard unreachable (section 2.9).

## 6. The reporting

- **The host cap** (row `report-k-grid`) is pinned by `dnp3-resync-udp-report-cap`. 101 flows fail in the first interval, and a fresh flow spends its budget there too. 100 rows are written. Flow 100's `first` row and the `budget` row are held, and the interval's overflow row says 2: the residual that K rows can hold back a `budget` row. The next interval has exactly 100 failing flows, all written, with no overflow row. That shows the first overflow row was charged to no interval (D6's B6). In the last interval, the `end` rows written plus the overflow count are 201.
- **The weird bound has two parts, and only one shows in `weird.log`** (rows `report-weird-sampling`, `report-weird-log`).
  - `Reporter::PermitNetWeird` lets through a weird on the global list while its host-wide count is at most 25, then once per 1,000, for 10 minutes.
  - Separately, `weird.zeek`'s `do_weird` logs a name at most once per connection per 10 minutes (`weird_ignore`).
  - So a burst on one flow shows one `weird.log` row, whatever the sampling (`dnp3-resync-udp-weird-burst`: 2,000 weirds, 26 events, 1 row).
  - The global bound shows only across connections (`report-cap`: 201 connections, 25 rows).
  - The test computes both numbers from the sampling rule.
- **No new field** (row `report-no-new-field`): C2A against C2 gains exactly the design's two events, eight weirds, `resync` rows with their five fields, and `resync_cause`.
- **D3's BM** (`dnp3-resync-udp-report-mark-state`). It runs 1,000 flows, each with a drop and then a throwing fragment, so no `fc` row ever takes the mark.
  - **Pass:** at `zeek_done`, every global container that the shipped script declares has the size it has on the one-flow control.
  - **Control:** a mutant of the shipped script that keeps the mark in a global table reports at least 1,000.
  - **What it shows:** that the script keeps no global state for the mark. That Zeek frees the connection record stays `inference` (the design's L-4).

## 7. The fuzz run: its pins and the coverage condition

Rows `fuzz-*` and `cov-*`, on the design's section 5.
- **The settings:**
  - `-max_len` 4,096;
  - `-timeout` 10 s, which is the check on progress;
  - `-rss_limit_mb` 2,048;
  - LSan on, so that an interpreter not freed on remake is a report;
  - `-seed` 20261115;
  - a bad-CRC share of 1 in 8 per CRC;
  - 30 minutes per target per build.
- **The seeds.** A seed that does not fit 4,096 octets and 64 chunks is listed as not converted, never cut. The job checks bit 7 against the seeds and the labelled holes before it runs.
- **The coverage condition is judged on a site map.** D4 commits it with A's patch: each `cov-` site by file, function and line at the patch's SHA-256. D6 reviews it before the run. Without it, the condition is `unknown`.
- **Required on both targets:**
  - each cause's branch, `invariant` and `fragment_limit` excepted, with `budget` included, since F and O are reachable;
  - the drop function, and both arms of its branch: remake and keep (D6's N6);
  - the remake of an interpreter that holds an incomplete unit, followed by a parse on that end. Coverage cannot show order, so this is shown by the converted `chunk-crc-open` and `fir-restart` seeds, replayed under ASan;
  - the link-only path, the length 0 to 4 path, both arms of the embedded-header check, and the catch inside the loop.
- **Required on one target only:** UDP, `truncated`, the reset with a fragment open, and the scan in a datagram; TCP, `gap` from `Undelivered`, and the scan and the embedded check holding octets across chunks.
- **Must show as not reached:**
  - the four guards and the `pkt_length <= 0` check;
  - `invariant`;
  - the catches in `DeliverStream` and `DeliverPacket`.

  A reach fails the run.
- **Left to its stage-2 case, and stated:** `fragment_limit`.

## 8. S5's measurement

Rows `s5-*`.
- **The metric:**
  - the `zeek -r` process's user plus system CPU time, minus that of a run on a capture that holds only its file header;
  - the median of 7 runs, on the counted run's runner image;
  - with the shipped script loaded (D3's N1).
- **The inputs:** 16 MiB each, against valid DNP3 of the same transport and size:
  1. the smallest throwing fragment;
  2. pairs that remake an interpreter without an exception;
  3. frames without FIR after confirmation;
  4. the same before confirmation (D6's B7);
  5. `05 64` repeated;
  6. a chain of the solved length-4 header, in which every header's CRC octets start the next.
- **Each input is valid only if its counts match how it was built.**
- **The ratio is at most 5.** Above it on any input, the bound R = 16 is added before the image is fixed, and its four cases are judged.

Why 5: valid DNP3 also costs a parse per fragment, so a well-behaved A should stay within a small factor of it. The number is D6's choice and rests on no measurement.

## 9. The static checks on the patch

Rows `static-*`:
- no `catch (...)`;
- no `Interpreter()`;
- every binpac call through the per-end accessor, and no `NewGap`;
- the two patches apply in order with no fuzz.

Each check is run once on a copy of the patch with its defect planted, and must fail there.

## 10. What the test checks, and what is not pinned here

**`test_resync_conditions.py`** runs in `ci.yml`'s `python` job, and this PR's path also triggers `a6-gt-pcap`. It checks:
- both files' SHA-256;
- every case id: the prefix, then its transport, and none of the strings that `table.py`'s summary columns key on;
- HR-25's four routes: R1 and R4 over both transports, R3 over TCP, and the keep-alive among R4's;
- every route case's twins and its control;
- every cause of the closed set but `invariant` in some case, and `invariant` in none; `gap` only over TCP and `truncated` only over UDP;
- every count and weird named by the design's names;
- the conditions' values;
- the solved headers' CRC octets;
- the false `05 64`'s failing CRC;
- the builder's arithmetic;
- the two weird counts, from the sampling rule.

Seven planted mutants were each killed: a route moved, a transport mismatched, a cause misnamed, a solved header changed, a twin dropped, a weird misnamed, and `-max_len` lowered. Each ran on a copy of the files with the hash test deselected, on the owner's PC, `desk`.

**Not pinned here, and owed before the counted run:**
- **The builder and the captures** (row `pin-builder`). `resync_cases.py` must write every case and twin frame by frame with `dnp3.py`. Their hashes and labels go in `tests/fixtures/network/gt-pcap/resync/`, and `a6-gt-pcap` must rebuild and check them. The brief gives D6 the GT-PCAP paths, so D6 writes it, in its own PR under this brief. Until it merges, no run counts.
- **D4's site map** for the coverage condition (row `cov-where`).
- **D4's two `pins.env` lines** (row `pin-files`).

**Limits:**
- **Every expectation here is `desk`.** It comes from the design and from Zeek's source as read, and the run settles it. A case that fails on a correct implementation is raised with D1 before the run, and changes both files in a new commit, never after.
- **What C0, C1p and C2 do on each case** rests on the HR-23 note's and HR-25's row's readings of Zeek 9.0.1. A control that sees W makes its case `unknown`, never `pass`.
- **Three expectations rest on code that was not read:**
  - that `Done` runs for a UDP connection's analyzers, which every UDP `end` row measures;
  - the event queue's order, which `resync_cause` measures;
  - that the last interval's overflow row comes after the connections' `end` rows at `zeek_done`, which `report-cap` measures.

  If one fails, the design's claim is wrong. That is a finding, never a reason to edit the pin.
- **The synthesized captures** say nothing about a real relay's traffic, live capture, or how a SEL device's link layer treats any of these inputs (the design's section 6 H-row, not run).

## 11. Where each item is answered

| Source | Item | Rows |
| --- | --- | --- |
| HR-25's row, "When it closes" | the four routes, the three controls | `judge-route`, `judge-ctl`; R1 to R4 cases |
| 6893379733 section 4 | 1. ids | every case id, as the brief's prefix |
| | 2. the failure on W's end, the other-end twin, two fragments after the failure, five controls | `judge-twins`, `judge-ctl`; every route case |
| | 3. builder's facts: solved headers, `tpflags`, 9 split points, pairs of checks | `builder-c1-*`; `dnp3-resync-tcp-tpflags`; `dnp3-resync-tcp-split-header-*`; `chunk-crc-open`, `insert-chunk-crc`, `budget-split-ends` |
| | 4. the budget: F − 1 and F, O − 1 and O, one failure for O, both ends, above 10 KiB, the benign maximum, the fuzz reach | `val-F`, `val-O`; the budget cases; the benign cases |
| | 5. the reporting | `report-*`; the R2 cases' `first` rows; every UDP `end` row |
| | 6. the weird burst | `report-weird-sampling`, `report-weird-log`; the two burst cases; `report-cap` |
| | 7. insertion | the four insertion cases; the R1 UDP cases are the inserted datagram of each cause before a one-frame write |
| | 8. the reruns | `rerun-*` |
| | 9. (3b-data)'s labels from the arms | `arm-3bdata`, `fp-3bdata` |
| | 10. S5 | `s5-*`, `val-ratio`, `val-R`; the bound cases |
| | 11. the fuzz pins | `fuzz-*` |
| | 12. static checks | `static-*` |
| 6893532533 | B6, B7, B1's insertion and redraw, the fragment limit's "one over" | `report-cap`; `cov-drop`, S5 input (4); the insertion cases, `fp-redraw`; `dnp3-resync-udp-fragment-limit-over` |
| 6893732701 | the five-cause `end` rule; the idle end with N6's arms; BM's probe; the `gap` case and count | the `end` rows of every case; `chunk-crc`, `first-chunk-missing`, `cov-drop`; `report-mark-state`; `dnp3-resync-tcp-gap-non-dnp3`, `fp-6`, `fp-counts` |
| The design's section 3 | every listed case | section 3.2 |
| The design's section 5 | the coverage condition | `cov-*` |
