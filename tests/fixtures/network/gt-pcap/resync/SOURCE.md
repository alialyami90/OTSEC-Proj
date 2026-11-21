# GT-PCAP: the dnp3-resync-* captures (D6, brief P4-4-HR25, deliverable 3)

These are the captures and labels for HR-25's counted run, owed under row `pin-builder` of `tests/integration/gt_pcap/resync-conditions.tsv` (D4-107 item 1.5; D4-108 item 2). The cases and their pass conditions are `resync-cases.tsv` and `resync-conditions.tsv` in that folder, pinned by `test_resync_conditions.py`, and explained in `docs/phase4/D6-hr25-resync-conditions.md`. Every result on these captures is `simulated`.

| Output | Origin | Nature | Terms |
| --- | --- | --- | --- |
| `<capture>.pcap` for each name in `resync.sha256`: 358 captures, which are the 168 cases, their 189 twins, and `dnp3-resync-udp-report-mark-state--control` (that case's control capture, flow 0 only) | Written by D6, 2026-11-15, and for the 56 cases of brief P4-4-HR2325S deliverable 3, 2026-11-21, with `tests/integration/gt_pcap/resync_cases.py` (stdlib only: `dnp3.py`, `synth.py`, `pcapfile.py`), from the build cells of `resync-cases.tsv` and the `builder-*` rows of `resync-conditions.tsv` at their pinned SHA-256s | Synthesized frame by frame, never recorded through a kernel and never sent. TEST-NET-1 addresses and locally administered MACs, as in builder-msgs: over UDP, M5 192.0.2.14:20000 (link 5) and O1 192.0.2.20:20000 (link 10); over TCP, M1 192.0.2.10 (link 1), from port 41100 up in the cases' order, to O1:20000 | This project's own. Not committed: `resync_cases.py` rebuilds them byte for byte, and `resync.sha256` pins them |
| `<case>.tsv`, one per case | The same run of `resync_cases.py` | The builder's labels for the case and its twins, from how each was made (row `judge-labels`): every link-layer unit as `valid` or as the damage it carries, and every message as `seen`, `absent` or `lost`, with the reason. Each file's header lines say what the columns mean | `desk` until D4 (labels) and D2 (protocol reading) review them. The labels hold addresses, ports, counts and packet numbers, and no capture bytes |
| `tshark-beside.tsv` | The `resync` job's artifact `gt-pcap-resync-tshark` of run 43756742929 (tshark 4.2.2, the pinned reader, at `f30fecff`), with a `cause` column added by D6 as D4 sorted the rows on #714; and the 20 rows of deliverable 3's cases, from a scratch run with tshark 4.2.3 on the owner's PC (`desk`), sorted by D6 and checked by the `resync` job's pinned 4.2.2 | The 76 messages where the pinned tshark's DNP3 reading differs from the builder's label, each with its cause; the header lines say what each cause means. A reading beside the labels, never a label (row `judge-labels`) | `CI-Linux` for the reading, `desk` for the causes. It holds capture names, packet numbers and function codes, and no capture bytes |

A capture is named after its case, as `<case>--<twin>` for a twin (`nofail`, `nowrite` or `otherend`, section 3.3 of the note), or as `<case>--control`.

## How they are checked

- **`test_resync_builder.py`**, in CI's `python` job, rebuilds every capture and checks:
  - that the hashes and labels are the committed ones, and every case and twin is there;
  - that every packet's IPv4 and UDP or TCP checksum is valid, and the ends and ports are builder-msgs';
  - that each TCP stream opens and closes as builder-msgs says and holds no hole but the labelled ones;
  - that the solved headers, the false `05 64`, and S5 input (7)'s frame are the rows' octets;
  - that every failure is made as builder-failures says, from its own bytes, against `dnp3.py`;
  - the application and transport sequences, the responses' echoes and the confirmed frames' FCB;
  - builder-limit's and builder-join's arithmetic;
  - that each twin differs from its case only as judge-twins says: a `nowrite` twin keeps the case's TCP holes, and every failure unit of an `otherend` twin is o's;
  - that `tshark-beside.tsv` names one of its eight causes for each of its rows;
  - the times of the timed cases;
  - for deliverable 3's cases (row `builder-seq`): every token's octets against the frame it copies or the number its cell gives; the three-frame unconfirmed W; `m numbered from n`; the labels of a retry after a primary link-only frame and of `fc`; that every retry repeats confirmed user data, which the builder refuses otherwise (D3's N3 on #787); and that 18c's repeat after the reset carries FCB 0 and W3c FCB 1, the cell's counted miss (D2's N1 on #787);
  - design 3.3's audit: design 2.3's transport rule over every capture changes only `dnp3-resync-udp-link-retry-middle` of the 112 pinned rows, by discarding its retry, and gives each new cell's `transport_seq` and `first_chunk_missing` per end. A compare over less than the whole segment, in either arm, changes some new cell's count (D3's N1 on #787). It models the rule, not A's code, and runs no engine.

  Each check has a named control, a mutant that the check must fail. `resync_cases.py` itself refuses a capture in which any offset holds a candidate (`05 64`, a passing header CRC, a link length of 5 to 255) that the case does not name, which is builder-failures' last sentence made exact for the whole capture.
- **The `resync` job of `.github/workflows/a6-gt-pcap.yml`** rebuilds the captures, checks them against `resync.sha256`, diffs the labels, and has the pinned tshark 4.2.2 check every packet's checksums. It lists the messages where tshark's DNP3 reading differs from the label, and fails when that list is not `tshark-beside.tsv` without its cause column: a difference not in the file is a regression or a new one to be classed on review, and one in the file that is no longer read is a change too. The list is uploaded as the artifact `gt-pcap-resync-tshark`. tshark's reading is never used as a label (row `judge-labels`).

## Choices the rows leave open

`resync_cases.py` makes each of these in one place, with a comment there.

1. **Time.** Case k (from 0, in the cases file's order) starts its clock at 2025-11-15T09:46:40Z plus k hours, and its twins at the same time. A packet follows the one before by 1 ms unless the build gives a time. `~90s` and `~130s` are exactly 90 s and 130 s.
2. **TCP.** Every data segment is followed by the peer's bare ACK, as in `dnp3_cases.py`. The initial sequence numbers are 1000 and 51000. "In N segments" fills segments to 1,460 octets, which gives 45 segments for 65,536 octets.
3. **Transport sequence.** A message's frames take consecutive numbers when the message is built, at its first frame. So in `W1 | I | W2` the master's W2 follows W1, and the inserted datagram takes the next number after both. W thus stays in sequence for a device that drops I, which `dnp3-resync-udp-insert-truncated-answered` needs. A link-layer retry repeats its frame's octets.
4. **Application sequence.** Every request APDU the builder writes takes the next number in the order built. That includes a failure built from a request (`badchunk`, `open+badchunk`, `firopen`, `throw`, `cut`, `overlimit`), `I:P`, and the W5 inside `embed` and `embedtail`. `nofir` holds no application header and takes none.
5. **badhdr's "six header octets of the sender"** are those of the sender's own P (link length 11, from m) or empty R (link length 10, from o). Its header CRC fails with its first octet inverted, as does `holds'`.
6. **nofir's "6 octets of object data"** are `3C 02 06 3C 03 06`.
7. **The two-frame read** of `open+badchunk` and `firopen` is P's read, split as W1 and W2 are, with the application control octet in frame 1.
8. **Three-frame splits** (W1c to W3c, G3a to G3c, and o's R in the `gap-middle-frame` other-end twin) put the application control octet in frame 1, then the rest in two halves, the first rounded up.
9. **Embed's "00 elsewhere"** holds for `embedtail` too. Its first two chunks are `00` with valid CRCs.
10. **The frames before a midstream capture's first whole frame** are numbered just before 0. In `tcp-r2-midstream` the 7-octet tail is the end of a P from m (application 15, transport 63), or, in its other-end twin, of an empty R from o. In `tcp-r2-midstream-both` the tails are the ends of frame 1 of a Q split as Qa and Qb (application 15, transport 62 and 63), and of an empty R so split (application 14). The capture's own numbering then starts at 0. Rbig's application sequence is 15.
11. **report-cap.** T0 is the capture's start plus 30 s. Flow i's P is at T0 + 5 s + 30 s × k − (200 − i) × 10 ms − 1 ms for k from −1 (the confirming poll, before T0) to 4, and its R is 1 ms later. So the last packet, flow 200's last R, is at T0 + 125 s. As a result, 42 packets share a timestamp with a packet of another flow. File order is the order given, and Zeek reads them in that order.
12. **report-interval.** Each P is answered 1 ms later. **weird-burst.** X_i is at X1 + i × 50 s / 1999, so X2000 is at X1 + 50 s exactly.
13. **Garbage** is SHA-256 in counter mode over `<case>:<unit>:<end>`, with every `05` octet dropped, so it is the same on every run and every Python.
14. **Deliverable 3's tokens** (row `builder-seq`). `seg` and `sub` carry one application octet, 22h (code 34, in the request parser's default arm). Link 11 is the other destination; no endpoint here uses it. `octet` inverts the first application octet and `more` adds 00h. `fc` fills with 00h. `embedhead`'s candidate at offset 3 has link length 11, CTRL 44h and DEST low octet 05h, and the frame's first data octet, the candidate's SRC high, is 00h. In `per-end-seq`, Ro is numbered 5 and Xo 7. `other-dest-middle` places the device's response to W after W2, as items 5 and 8 do. A token that gives a number does not move its end's count; `firopen(n)` and `m numbered from n` set it.
15. **Labels for deliverable 3.** A message read by the request or response parser takes rule (A)'s choice, C2A's: `fc` is labelled absent only where that parser's object arm meets 1 or 2 object octets. A retry that follows a primary link-only frame of its end (Reset Link States, a link status request) is no link-layer retry (design 2.3), so it interrupts its message. `sub` and `read` are labelled seen with the code of the fragment they complete; `seg` and the copies are labelled absent.

## The other end's twins, where judge-twins leaves it open

These are readings of judge-twins. On #714, D2 and D4 confirmed the readings of nofir, of embed and embedtail, and of R3, and the keep-alive's is now as they both read it there.

- A failure from o that carries a response does so in the sequence of the most recent request.
- **throw from o** is `badobj`, a 129 of 5 application octets with one object octet, which the response parser rejects (D1's ruling 2 on #787). It replaced C0h 81h 00h, a 129 of 3 octets, which rule (A) sends to the request parser's default arm, where it parses. That rebuilt the two `app-parse--otherend` twins and their label rows (16 octets to 18); no other capture changed.
- **nofir from o** is the empty response's APDU in a frame with FIN set and FIR clear ("empty responses of the same framing").
- **embed and embedtail from o** carry the response to a direct operate at index 5, which echoes its g12v1 and is 37 octets, not W5's 35. So embed's frame holds it at octets 20 to 56, and embedtail's after-octets are 33.
- **R3 from o.** G is sent whole, in the same segments, and the hole moves to G's response R(G), split at the same offsets. R(G) is 17 octets, so in `gap-data` the last piece is 1 octet. In `gap-middle-frame`, R(G) goes in three frames with the middle one lost.
- **The keep-alive from o's side** is `Lo | Ls`: O1's link-status request `Lo` (function 9), which is already o's and stays itself, then O1's link status (function 11) in place of the master's `Lm`. builder-msgs does not name the latter; the labels call it `Ls`. So both link-only frames are O1's and none is on W's end, which is what lets the twin meet judge-twins' expectation on R4 under the controls, W seen and the outstation's next delivery lost (D2's B2 and D4's B1 on #714). As D2 notes there, a link layer ignores a secondary frame it did not request, so `Ls` is a valid 10-octet link-only frame and not an exchange.

## Limits

- **The expectation under C2A is each case's `a` cell, not the label.** A label's `seen` is how the message was built. Where the budget or the bound blinds a whole message, the cell says so.
- **What tshark reads.** The pinned tshark 4.2.2 (run 43756742929, `CI-Linux`) read 56 messages differently from the labels, and found no checksum error. Each difference is a known one, and `tshark-beside.tsv` names its cause (D4 sorted them on #714; D6 the 20 of deliverable 3, from tshark 4.2.3, `desk`, until the `resync` job's 4.2.2 reads them):
  - `no-resync`, 22: tshark does not resynchronise after a failed header (`crc-magic`, `holds`, `false-magic`, the midstream tail);
  - `throw-code`, 24: it reads a throwing fragment's function code;
  - `no-limit`, 9: it has no fragment limit;
  - `insert-rebuild`, 8: it rebuilds W across an inserted datagram that it discards, as a device would;
  - `seq-rebuild`, 9: it rebuilds W from W's own frames, passing over a frame that repeats or skips a number;
  - `retry-last`, 2: W's last labelled packet is a retry after its FIN, where tshark reads no code;
  - `merged`, 1: s is a middle segment, and tshark reads the fragment it joins at that fragment's last frame;
  - `no-wrap`, 1: tshark does not reassemble `seq-wrap`'s W, numbered 62, 63 and 0 (a scratch probe with tshark 4.2.3 reassembles the same fragment numbered 61 to 63, or 0 to 2).

  The fixes for D2's B1 and B2 on #714 changed four twins (the three R3 `nowrite` twins and the keep-alive's `otherend` twin). A scratch run of `resync_tshark.py` with tshark 4.2.3 on the owner's PC, its version check bypassed (`desk`), read the same 56 on the rebuilt captures, with no checksum error. After D1's rulings on #787 (the two `app-parse--otherend` twins rebuilt, two cases added), the same scratch run read the same 76, with no checksum error.
- **Not built here.** S5's inputs are measurements, not cases: `resync_cases.s5_7_frame` gives input (7)'s frame, and no S5 capture is written. The false-positive set (rows `fp-*`), HR-23's malformed set and the reruns are not built here either.
- **Real devices.** These captures say nothing about a real relay's traffic, a live capture, or how a SEL device's link layer treats any of these inputs. That is the design's section 6 H-row, which is not run.
