# A4 Phase 0 findings: telemetry feasibility and IDS engine evaluation

- Task: P0-A4 (brief in `/mnt/project-files/phase0/task-briefs.md`, issued by A1 2026-10-23)
- Author: A4 (Telemetry, Event Processing, and IDS Engineer)
- Date: 2026-10-23
- Branch: `claude/project-thread-ix2tu3` (the session's fixed branch; the CLAUDE.md convention would be `agent/telemetry-phase0`)
- Status: draft for A1 consolidation; cross-review requested from A6 (detection accuracy) and A2 (protocol interpretation)
- Companion: [A4-event-schema-draft.md](A4-event-schema-draft.md) holds deliverables (1) to (3): event schema, duplicate handling, Syslog forwarding profile.

No device, network, or credential was touched. All experiments ran in the container against public captures and local processes. Every result below is `simulated` in the project's evidence classes: recorded or synthesized traffic and stock software, never this project's equipment.

## 0. Answers in brief

1. **Q3, can different vendors' SER records be accurately normalized?** The envelope can, the meaning cannot in general. Across four native time encodings (SEL ASCII text, DNP3, IEC 60870-5-104 CP56Time2a, IEC 61850 UtcTime) one schema holds every field losslessly, provided it keeps the native timestamp verbatim, declares resolution and accuracy separately, allows offset "unknown", and scopes time quality (section 2). What an event *means* ("51P1P Asserted" vs DNP3 binary input 1 = 1) is not normalizable without per-device mapping tables derived from settings, SCL, or point lists. Cross-device ordering is only trustworthy when both clocks report synchronized with a known offset.
2. **Q4, can passive monitoring observe enough for reliable IDS?** For DNP3 and Modbus over IP, yes in principle. For the protocols that define a modern substation (IEC 61850 MMS, GOOSE, SV, and IEC 60870-5-104), not with stock open-source engines: neither Zeek 8.0.4 nor Suricata 7.0.3 decodes them (section 3). Visibility is further limited by PRP/HSR, SPAN behaviour, encryption, serial links, and process bus rates (section 4).
3. **Engine recommendation (provisional, IDS is Phase 4):** Zeek as the primary passive sensor, run as a separate supervised process whose JSON logs the platform ingests (matches A5's proposal), with substation protocol coverage added through Spicy analyzers or our own decoders. Suricata is optional later for signature rules on DNP3 and Modbus. No proprietary engine.
4. **The forwarder is an injection path** unless framing and escaping are designed for hostile input: with newline framing a single device record forged a second message at a stock rsyslog receiver. The draft profile closes it (0 forged in 10 hostile cases).
5. **Acknowledged Syslog is only as reliable as the receiver's queue configuration.** With RELP and rsyslog's default queues, about 98% of acknowledged messages were lost when the receiver crashed; with Direct queues and confirmed writes, none were.

No hard language requirement for A5 follows from this work (section 7).

## 1. Evidence base

| ID | Source | Version / commit | Use | Class |
| --- | --- | --- | --- | --- |
| E1 | Public OT captures, manifest and provenance in [`tests/fixtures/network/public-ot-captures/`](../../tests/fixtures/network/public-ot-captures/SOURCE.md) | SHA-256 pinned | Engine coverage, timestamp bytes | recorded or synthesized traffic |
| E2 | Suricata (Ubuntu package) | 7.0.3 | Coverage, rules | stock software |
| E3 | Zeek (`zeek/zeek` container image) | 8.0.4 | Coverage | stock software |
| E4 | Wireshark tshark (Ubuntu package) | 4.2.2 | Reference dissector | stock software |
| E5 | rsyslog with imtcp, imrelp, omprog | 8.2312.0 | Independent Syslog receiver | stock software |
| E6 | Zeek package registry `zeek/packages` | `342bec8`, 2026-10-22 | Which OT analyzers exist for Zeek | registry index |
| E7 | Suricata source `OISF/suricata` | `bea218e`, 2026-10-22 (9.0.0-dev) | Which app-layer parsers exist upstream | source tree |
| E8 | libiec61850 `mz-automation/libiec61850` | `6e265c5` | UtcTime quality bits, report options (EntryID, BufOvfl) | open-source implementation of the standard |
| E9 | lib60870 `mz-automation/lib60870` | `7a388e3` | CP56Time2a fields (IV, SU, substituted) | open-source implementation |
| E10 | A2 findings section 7 (SEL-751 SER), PR #2 commit `9a84ef8` | 2026-10-23 | SER format | `documented-untested` via A2 |
| E11 | A6 verification draft, A6 cross-review, A3 threat model draft | 2026-10-23 | Requirements on schema and forwarder | project drafts |

Update 2026-10-23: the owner supplied SEL manuals and datasheets (SEL-751 IM 20260910, SEL-400 series IM 20260730, SEL-311L, SEL-2488 IM 20260918, SEL-3355-2, SEL-2731, SEL-2741, SEL-5033, SEL-5056, and others). SER format, time model, and Syslog facts from them are in the schema draft section 3 and section 4 and are `documented-untested`.

Limits: OEM documentation sites, IETF, Zeek and Suricata documentation sites are blocked by the environment's egress policy. RFC and IEEE 1815 statements below are from the standards as I know them and are marked "not re-read". No second vendor's proprietary SER text export could be read; the multi-vendor check therefore uses standard protocol encodings that several vendors implement. GE, Siemens, and ABB native SER exports remain `unknown`.

## 2. SER-to-Syslog normalization (Q3)

The full schema and the mapping are in the companion document, section 3. Summary of what the four encodings taught:

| Finding | Evidence | Consequence |
| --- | --- | --- |
| Tools invent offsets. tshark renders CP56Time2a and DNP3 times as "UTC"; neither encoding nor the bytes say so. | E1 `iec104.pcap` frame 25 (`c75d170884070d`), E4 | `offset` defaults to "unknown"; only a format that defines UTC (IEC 61850) or a recorded configuration may set it. |
| Nominal UTC is not actual UTC. All 14 DNP3 absolute times in one capture are 4 h plus 0.06 to 5.1 s behind the capture clock. | E1 `dnp3-digitalbond-part1.pcap` frames 7 to 61 | Even DNP3, whose standard says UTC, needs `offset_basis`; the platform should compare device time to receive time and raise `time.offset_suspect` when they disagree by more than a threshold. |
| Rendered digits are not precision. GOOSE `t` with accuracy 10 bits (about 1 ms) prints as `.513999998`; truncating to ms gives `.513`, the intended value is `.514`. | E1 `goose-normal.pcapng` frame 1, E8 | `resolution_ns` and `accuracy_ns` are separate fields; decoded values are rounded to the declared accuracy, never truncated, never padded. |
| Quality has different scopes. SEL: report-level "Time Source"; IEC 61850: per-value quality byte; DNP3: IIN bits per response; CP56Time2a: per-value IV bit. | E10, E8, E9, E4 | `quality.scope` field. |
| Two-digit years (CP56Time2a) need a recorded century assumption. | E9, E1 | `flags: two-digit-year:century-assumed-2000`. |
| Some formats have native record identity (IEC 61850 EntryID), most do not (SEL rows are positional, DNP3 events vanish on confirm, Syslog has none). | E8, E10 | Snapshot alignment for ring buffers, EntryID resume for 61850, no content dedup for Syslog (companion section 4). |
| Native-side loss is signalled differently or not at all: BufOvfl, IIN2.3, SER C with no marker. | E8, E4, E10 | Distinct `telemetry-health` events; SEL gap detection below the overlap size stays a documented limitation (C-06). |

Answer to Q3, with its conditions: **yes for lossless structural normalization of envelope, identity, time, and raw evidence; no for vendor-independent semantics without mapping tables; ordering across sources only within stated clock quality.** This is `documented-untested` for SEL (no real output exists, B-01) and `simulated` for the three protocol encodings.

## 3. IDS engines: Zeek vs Suricata vs protocol libraries

### Experiment E-A4-01: engine coverage on public OT captures

Reproduce: `modules/telemetry/experiments/ids-coverage/fetch_captures.sh` then `run_all.sh`. Output: [`results/coverage.md`](../../modules/telemetry/experiments/ids-coverage/results/coverage.md), [`results/goose-seq-check.txt`](../../modules/telemetry/experiments/ids-coverage/results/goose-seq-check.txt), versions in `results/versions.txt`. Suricata ran with its packaged configuration plus the DNP3, Modbus, and ENIP parsers enabled (they ship disabled), and a second time with `stream.midstream=true`. Zeek ran with `-C` and `policy/misc/unknown-protocols`. tshark is the reference.

| Protocol | tshark decodes | Suricata 7.0.3 | Zeek 8.0.4 | Zeek packages (E6) | Suricata upstream (E7) |
| --- | --- | --- | --- | --- | --- |
| DNP3 / TCP | yes, 6 captures | 4 of 6 by default; the other 2 (`dnp3-malformed`, `dnp3-digitalbond-part2`, captured without the TCP handshake) only with `stream.midstream=true` | yes, all 6, including midstream | ICSNPP-DNP3 extends logging | built in |
| Modbus / TCP | yes, 3 captures | 1 of 3 by default, 2 of 3 with midstream; `modbus-digitalbond-part2` not identified either way | 2 of 3 as a service; `modbus-digitalbond-part2` logged 45 Modbus rows but also an analyzer violation | ICSNPP-Modbus | built in |
| IEC 60870-5-104 | yes (64 ASDU frames, including C_SC_NA_1 single commands) | no (`failed`) | no | none | none |
| IEC 61850 MMS | yes (163 frames) | no | no | none | none |
| IEC 61850 GOOSE (Ethertype 0x88b8) | yes (about 31,800 frames per file; tshark 4.2.2 also hits a dissector assertion "recursion_depth <= 100" on some frames) | not seen (not IP) | logged only as an unknown protocol `0x88b8` | none | none |
| IEC 61850 SV, C37.118, vendor engineering protocols (SEL Fast Message, others) | not tested (no capture) | none built in | none built in | ICSNPP-Synchrophasor (C37.118) exists | none |

Findings:

- **The substation-specific protocols are the gap.** Neither engine decodes IEC 104, MMS, GOOSE, or SV, and no package exists in the Zeek registry for them. Notably `iec104.pcap` contains single commands (C_SC_NA_1, an unauthorized-command technique in ATT&CK for ICS terms, T0855) that both engines are blind to.
- **Suricata's default stream handling misses long-lived SCADA sessions.** Polling sessions often run for months, so a sensor started after the handshake sees only midstream traffic. With defaults, Suricata labelled those flows `none` and its DNP3 rules did not fire (`dnp3-digitalbond-part2`: 0 alerts by default, 5 SELECT alerts with midstream). Any Suricata deployment needs `stream.midstream=true`, with its own false-positive cost to be measured.
- **Naive "write = bad" rules alert on routine traffic.** The only DNP3 WRITE in `dnp3-write.pcap` is a write of object g50v1 (time and date), which is ordinary time synchronization from a master. Explainable rules must key on function code and object group and on who sends it, against a baseline of authorized masters.
- **Deterministic GOOSE checks work on this dataset.** A per-control-block state machine over stNum, sqNum, and `t` (`goose_seq_check.py`, about 60 lines over tshark fields) flagged 10 of 11 labeled attack frames, with 0 alarms over 4 benign captures (normal and three protection-disturbance scenarios, about 127,000 GOOSE frames). The miss is CompositeAttack frame 792, a well-formed state change (stNum 1 to 2, sqNum 0, new `t`) with a forged breaker value; it is caught only indirectly, 0.28 s later, when the real publisher's next frame regresses stNum (frame 822). Value-level forgery needs either GOOSE authentication (IEC 62351-6) or cross-checks against other measurements. Each injected frame also produced one follow-on alarm when the genuine publisher resumed, which the alert explanation must group with the cause. Dataset is synthesized; real IEDs' retransmission timing may differ.
  - **A6 broke it (R-A4-4, PR #6 `tests/integration/reviews/A4/goose_seq_cases.py`): 8 of 8 hand-labeled adversarial cases fail.** False alarms on sensor frame loss, PRP duplicate copies, a publisher restart, and sqNum rollover; misses on a well-formed stNum+1 injection (the alert lands on the next legitimate frame), a takeover where the real publisher falls silent (no TTL/heartbeat check), and a new gocbRef. So the 10-of-11 result reflects how that dataset's attacks were built, not general detection ability. A1 ruled this Phase 4 input, not a slice blocker. Needed before any GOOSE claim: PRP duplicate discard before sequencing, TTL-based silence detection, rollover and restart rules, an SCL-derived allowlist of gocbRefs and publishers, and attribution of an injection to the injected frame.

### Comparison

| Criterion | Zeek | Suricata | Protocol libraries / own decoders |
| --- | --- | --- | --- |
| DNP3, Modbus | built in, midstream by default, ICSNPP adds detail | built in, signature keywords (`dnp3_func`, `modbus: access write`), needs midstream config | many (opendnp3, stepfunc dnp3, Go and Rust Modbus) |
| IEC 104, MMS, GOOSE, SV | none; Spicy can add TCP analyzers, and Zeek's packet analysis framework accepts custom Ethertype analyzers for GOOSE and SV (capability from the Zeek design, not tested here) | none; IP-only design, L2 GOOSE and SV are outside its model | lib60870 and libiec61850 (GPLv3 or commercial licence, a constraint to record), Wireshark dissectors (GPL, not robust: assertion above) |
| Baselining (who talks to whom, function codes per pair) | strong: conn and protocol logs are the baseline input | weak: alert-centric; flow events exist | must be built |
| Explainability | log rows are directly citable evidence | signature id plus packet | as designed |
| Operational | separate process, JSON logs, scriptable | separate process, EVE JSON | in-process; at GOOSE and SV rates still fine for a compiled language |

Recommendation for A1 (provisional, an ADR in Phase 4): Zeek as the passive sensor; decode IEC 104 and GOOSE through Spicy or small own decoders against the captures above; keep Suricata as an optional add-on for signature rules. Before writing any analyzer, re-check upstream (ICSNPP and Zeek packages change).

Ownership note: the GOOSE checker is a throwaway experiment, not an IDS implementation (brief exclusion respected).

## 4. Network visibility limits (Q4)

| Limit | Effect on detection | What the platform must do | Evidence |
| --- | --- | --- | --- |
| PRP (IEC 62439-3): every frame sent on LAN A and LAN B with a redundancy control trailer | A sensor on one LAN sees one copy; a sensor on both sees duplicates; a fault on one LAN looks like loss | Capture both LANs or state which; de-duplicate by PRP sequence number; treat one-LAN loss as a network-health signal, not an attack | standard (not re-read); tshark has a PRP trailer dissector |
| HSR rings | Traffic carries HSR tags and circulates both directions | Sensor must strip HSR tags and de-duplicate | standard (not re-read) |
| SPAN vs TAP | SPAN drops under oversubscription, may drop errored frames, may reorder, may alter VLAN tags, and is configured on the switch the platform should not depend on; TAPs are passive and fail open | Prefer TAPs on station-bus uplinks; when SPAN is used, record it as a limitation of every baseline and measure drop counters | general practice; not measured here |
| Encryption | IEC 62351-3 TLS on MMS, SSH, HTTPS, vendor encrypted tools hide content; IEC 62351-6 GOOSE authentication adds integrity but not secrecy | Metadata only (who, when, volume, certificate) for encrypted flows; never claim content inspection | standard |
| Unsupported protocols | IEC 104, MMS, GOOSE, SV not decoded by stock engines | Coverage table per sensor build; alerts must say "protocol not inspected" instead of silence | section 3 |
| Process bus | SV at multiple thousand frames per second per merging unit on dedicated VLANs or physical networks | Separate sensor sizing; out of first slice | standard (not re-read) |
| Serial links | Many SER, SCADA, and engineering connections are serial or serial over IP | Invisible to a network sensor; covered only by collection (A2) and audit (A3) | A2 section 5 |
| Midstream sessions | Long-lived TCP sessions start before the sensor | Engine must pick up midstream | E-A4-01 |
| L2 multicast scope | GOOSE is VLAN-scoped multicast, not routed | Sensor must sit on each relevant VLAN | E1 (VLAN-tagged GOOSE seen by Zeek's VLAN analyzer) |

Answer to Q4: passive monitoring can support reliable, explainable detection **only where sensor placement, protocol decoding, and redundancy handling are known and stated per site**. The platform should publish a per-sensor coverage statement (protocols decoded, LANs seen, SPAN or TAP) and attach it to every alert and baseline. Without IEC 61850 and IEC 104 decoding, an IDS for an IEC 61850 substation would be blind to its most important traffic.

## 5. Evidence preservation requirements

Proposed for A1 to carry into Phase 1 contracts. EP-1 to EP-4 map onto V-S8 directly.

| ID | Requirement | Verification idea |
| --- | --- | --- |
| EP-1 | Raw bytes of every collected record (adapter transcript, Syslog datagram or frame, packet slice) are written to the evidence store and made durable before parsing. | A6 V-S8: forced parser failure still leaves raw evidence with matching hash |
| EP-2 | Normalized events reference raw evidence by SHA-256 and byte span; report-level context (headers) is referenced, not copied and edited. | Hash and span resolve to the same bytes the simulator sent |
| EP-3 | Raw evidence is never modified. Redactions (credentials, A3 HR-3) are markers with offset, length, reason, and component, never a hash of the secret. | Canary secret absent; marker present; lengths add up |
| EP-4 | Parser id and version are recorded; any event can be re-derived from raw by re-running that parser version. | Re-parse equals stored normalized event |
| EP-5 | Parse failures, alignment gaps, native loss indicators, and time-quality changes are platform events (`telemetry-health`), never log lines only. | Each injected fault yields exactly one event |
| EP-6 | Under storage pressure (A5 V-S9), normalized data is never kept while its raw evidence is deleted; any shedding is itself an event. | Fill the store; check the invariant |
| EP-7 | IDS alerts reference the packets that triggered them (time window and flow key into a retained capture ring), plus the sensor coverage statement. | Alert evidence opens in tshark and contains the triggering frame |
| EP-8 | Collector receive time and the collector clock's sync state are recorded with every event. | Field present, clock state changes produce EP-5 events |
| EP-9 | Forwarded messages never carry secrets or configurations (A3 AP-9); device bytes travel only in escaped or base64 SD values. | E-A4-02 profile cases; A6 V-S15 |

## 6. Architecture-critical risks from A4's area

Offered to A1 for the Phase 0 exit gate's list of five.

1. **Substation protocol blindness.** Stock IDS engines decode none of IEC 61850 MMS, GOOSE, SV, or IEC 104 (E-A4-01). R6 for substations needs decoder work that the brief's "evaluate before building" rule now justifies.
2. **Delivery guarantees depend on the far end.** RFC 5425 gives none (A6 E-01); RELP gives one only with a specific receiver configuration (E-A4-03). R4.7 can be met only with at-least-once replay, `event_id` dedup, and a documented receiver configuration or unconfirmed window.
3. **Timestamp fidelity.** Offsets are absent or wrong in practice (DNP3 capture 4 h off nominal UTC), tools mislabel them, rendered digits overstate precision. Normalizing to UTC by default would violate R4.4.
4. **The forwarder as an injection and exfiltration path.** Newline framing let a device forge upstream messages (E-A4-02). Mitigated by the profile; must stay under test (V-S15).
5. **Device-side loss is often invisible.** SEL SER has no sequence counter (A2), buffers wrap and can be cleared; snapshot alignment detects most gaps but not all (C-06, C-13).

## 7. Notes for A5 (toolchain and buffering)

- No hard language requirement. Zeek and Suricata run as separate processes with JSON logs, as A5 proposes. Own GOOSE or IEC 104 decoders at substation rates are fine in Go; Spicy analyzers would live inside Zeek in Spicy's own language.
- Outbox semantics I rely on: durable append before ack to the collecting side; per-(node, stream) monotonic `stream_seq`; a forwarder cursor per destination; replay from cursor; `event_id` stable across replay. A5's note proposing exactly this matches; no conflict.
- Licences to record in the toolchain ADR: libiec61850 and lib60870 are GPLv3 or commercial; Zeek is BSD; Suricata is GPLv2 (separate process, so no linking question).

## 8. Unsupported assumptions and open items

| Item | Status |
| --- | --- |
| SEL-751 SER row layout | Resolved from the owner-supplied manual (Figure 10.16): `#`, `DATE`, `TIME` (hh:mm:ss.mmm), `ELEMENT`, `STATE`; date format follows `DATE_F`. `documented-untested`; real Telnet bytes still unknown (B-01) |
| SEL relay time offset | Resolved from the manuals: relays keep local time; SEL-751 applies `UTC_OFF` only under SNTP; SEL-400 series derives local time from `UTCOFF` and DST settings. The SER output never carries the offset, so the adapter must read settings to state one |
| SEL relays emitting Syslog | None found: no Syslog in the SEL-751, SEL-400 series, or SEL-2731/2741 manuals, and the SEL-311L manual states "The SEL-311L does not support Syslog functionality." Device Syslog in this portfolio comes from the SEL-2488 clock (RFC 3164 over UDP 514 only), the SEL-5056 (RFC 3164 or 5424, UDP or TCP/TLS, also on behalf of SEL SDN switches), the RTAC (RFC 3164, facility 23, 1024 bytes), and SEL-2731/2741 switches in RSTP mode (RFC 3164 over UDP, per A2 from the RSTP user's guide). Per-device table: schema draft section 5, "SEL telemetry sources by device type" |
| Whether SEL Telnet echoes password characters (affects HR-3 redaction) | `unknown`; A2 |
| GE, Siemens, ABB proprietary SER exports | `unknown`; OEM sites blocked |
| IEEE 1815 DNP3 time defined as UTC | recollection, not re-read; capture evidence shows deployments using local time anyway |
| RFC 5424/5425/6587/3164, RELP grammar | from the specifications as known and from rsyslog behaviour, not re-read here |
| Zeek packet-analysis framework handling GOOSE via a custom analyzer | design capability, not tested |
| Detection results on GOOSE | synthesized dataset only; real IED timing and retransmission may differ |
| RELP result under host crash or power loss | not tested (process crash only) |
| Suricata midstream false-positive cost | not measured |

## 9. Handoff P0-A4 — A4 — 2026-10-23

**Completed:** Telemetry feasibility and engine evaluation (this document); draft event schema, snapshot-alignment duplicate handling, and Syslog forwarding profile ([A4-event-schema-draft.md](A4-event-schema-draft.md)); four experiments: E-A4-01 engine coverage plus GOOSE checks, E-A4-02 Syslog framing and escaping against rsyslog, E-A4-03 RELP acknowledgement vs storage under receiver crash, and the schema mapping with snapshot alignment tests.

**Evidence:** `modules/telemetry/experiments/ids-coverage/results/` (coverage table, GOOSE check output, tool versions); `modules/telemetry/experiments/syslog-framing/results/framing.md`; `modules/telemetry/experiments/relp-ack/results/relp-ack-trial{1,2,3}.md`; `modules/telemetry/experiments/schema-mapping/results/examples.json` (now including all 8 rows of the SEL-751 manual example in `documented/`) and `test_align.txt`. Captures are fetched by hash from the sources in `tests/fixtures/network/public-ot-captures/`. All `simulated`.

**Interfaces:** Proposed (draft, not contract): event record `otsec.event/0.1-draft`; forwarding profile `otsec-syslog/0.1` with modes A (RELP/TLS) and B (RFC 5425 with replay window); `telemetry-health` event names; evidence preservation requirements EP-1 to EP-9. Uses A2's adapter result envelope (`transcript`, byte spans, `invocation_id`) and A5's outbox position.

**Limitations:** No real SEL output, so the SER mapping covers only the documented header and one row's element and state. Protocol timestamp mappings use public captures, not project devices. Engine results are specific to the versions listed. Section 8 lists the rest.

**Risks:** Section 6. Most important: substation protocol blindness of stock engines, receiver-dependent delivery guarantees, and timestamp offsets that tools silently invent.

**Dependencies:**
- A1: decide the forwarding mode policy (A preferred, B allowed with documented window W) and carry EP-1 to EP-9 and the schema into Phase 1 review; obtain an IANA PEN before any production SD-ID.
- A2: SEL row layout and date format setting; whether Telnet echoes passwords; IEC 61850 log EntryID behaviour after device restart for the contrast family.
- A3: confirm the TB5 wording in the schema draft section 5 (ack-only grammar); confirm HR-3 conditions (no secret hash in markers; echoed bytes redacted too).
- A5: outbox per section 7; receiver-side configuration tests if the platform runs its own relay; storage-pressure invariant EP-6.
- A6: independent tests for snapshot alignment (C-13, V-S4), V-S3 timestamp cases from section 3 of the schema draft, V-S15 against the profile, and a RELP variant of E-01 on your own harness; detection-accuracy review of E-A4-01.

**Files changed:** `docs/phase0/A4-telemetry-feasibility.md`, `docs/phase0/A4-event-schema-draft.md`, `tests/fixtures/network/public-ot-captures/{MANIFEST.tsv,SOURCE.md}`, `modules/telemetry/experiments/{ids-coverage,syslog-framing,relp-ack,schema-mapping}/`.

**Reviewer(s) and outcome:** A4 has not reviewed its own work as independent evidence. The cross-reviews are complete:

- **A6** (detection accuracy, verification; `docs/phase0/A6-cross-review.md`, "A4 findings", reviewed at `74ae579`, re-checked at `7c7fa49`):
  - R-A4-1, must fix: the SER alignment key included the SEL-751 row number, which renumbers on every new event. With that key, 3 of A6's 6 consecutive-read cases reported false gaps. Fixed in `74a64eb`: `alignment_key` excludes the row number. A6's harness passes 6 of 6 (`schema-mapping/results/a6-ser-alignment.txt`), and A1 accepted the change for C5. **Closed.**
  - R-A4-2: on an ambiguous overlap, keep the most rows and flag possible duplicates. Adopted in `74a64eb` (`align_full`). **Closed.** A6's re-check ran end to end with A4's `parse_report` and `alignment_key` and added a seventh case. All 7 pass, and the old whole-line key fails 4 of 7.
  - R-A4-3: A6 reproduced E-A4-03 independently. 12 of 12 runs with Direct queues lost nothing. Power loss is untested, and that limit is recorded in the schema draft section 5. **Closed for Phase 0.**
  - R-A4-4: the GOOSE checks failed all 8 of A6's hand-labeled adversarial cases. Recorded in section 4 as Phase 4 input, not a slice blocker (A1). **Closed for Phase 0.**
  - R-A4-5: the RTAC HEADER-versus-MSG time case was added to V-S3, and the V-S3 cases in schema draft section 3 were found consistent. The DNP3 4 h offset remains an inference. **Closed.**
- **A2** (protocol interpretation; `/mnt/project-files/phase0/A2/A2-review-A4-schema-mapping.md`): the CP56Time2a, DNP3 CTO plus relative time, and IEC 61850 UtcTime decoding were judged correct. Five findings were addressed in `4d73987`:
  - Silent row loss on an unexpected layout or `DATE_F`: every line is now a row, a relay message, or a parse error, and `DATE_F` is a required input.
  - Relay power-up and settings-change rows are matched explicitly.
  - `accuracy_ns` is null under `Time Source: Internal`.
  - `stream_seq` is assigned at durable write, not per report.
  - `SOURCE.md` notes that A2's and A4's copies of Figure 10.16 came from the same tool.
  
  `test_sel_ser.py` has 12 tests, all passing. **Closed.**
- **A3**: the HR-3 conditions and the TB5 ack-only grammar were accepted (A1 rulings). AP-22 added `source.sender` and `source.origin_auth`; A4 proposed the value set `none | tls-server-only | tls-mutual | session`.

A1 decided the forwarding mode policy at the exit gate and tightened it afterwards: only RELP over TLS may serve a `required` destination, and every other mode is `best-effort`.
