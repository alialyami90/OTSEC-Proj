# HR-24 stage 1: judging a tied Telnet or SNMPv3 session (D4)

Brief P4-4-HR24, stage 1 (`docs/agent-handoffs.md`), under D4-95. D4, 2026-11-13.

- **Evidence class: `desk`.** Nothing here is built or run. Every source is cited at `main` `650a62be` unless another commit is named.
- **Reviewers:** D3 reviews the security design, D2 what the collector's sessions look like on the wire, and D6 testability.
- **Contract changes:** §7 lists what the rule needs from a contract. Each item comes back to D1 before stage 2 (brief: "If the note needs a C13 or C4 change, it comes back to D1 first").

## 0. The problem in one paragraph

A `flow` that intake ties to one of the node's own collector runs (`node.platform_session`) skips every base rule (`modules/detection/netdetect/detector.go` l.262: `if r.base && (d.base == nil || o.Node.PlatformSession != nil)`). Only `node-address-spoofed` still looks at it, and only at the flow's first frame on the node's own segments (`own.go` l.177 to l.183). So a spoofed session that ties is hidden whole, writes included (HR-24). Today nothing compares a tied flow with the run it is tied to. This note proposes that comparison: one new rule that judges each tied flow against the profile of the run it tied to, taken from the collector's own result. The rule reads no session content.

## 1. Every route by which a spoofed flow can tie

The routes come from HR-24's row, AP-35 (`docs/threat-model.md`), SL-17 (`docs/phase4/D3-sensor-link.md`) and the baseline note §5. Each route below is checked against what the detector would see.

| # | Route | Source | What the detector sees for that invocation |
| --- | --- | --- | --- |
| T1 | **Move branch.** The sensor's clock moves after the last sampled tick, so a record captured after the move ties to an earlier window: live, or through the late index (one flow per entry, then spent) | HR-24; SL-17; D5 §1.6 | The run's own flow, tied, **and** a second flow tied to the same invocation. Where the spoofer reuses the run's exact 5-tuple, both flows share one key. |
| T2 | **Eviction branch.** Across a node start, records numbered before the tied one are evicted after the last sampled tick, so the capture floor has not yet risen when the tie is decided | HR-24; SL-17; CH-20 | As T1, or, where the run's own records are among those evicted, **only** the spoofed flow, tied. |
| T3 | **Forged exact 5-tuple** inside the run's window, from the node's MAC on its segments, or from any MAC across a router (`node-address-spoofed` does not fire then) | AP-35; D4-73 | One key tied to the invocation, carrying the run's own traffic **plus** the spoofer's. TCP cannot hold both sessions at once, so in practice this means a connection right after the run's, inside `ended_at` + *g*. |
| T4 | **The `window` tie on a C2 0.8 result** (no `local_addr`): an attacker's connection that starts inside the window before the platform's is tied in its place | AP-35; baseline note §5 | Only the spoofed flow, tied. The platform's own flow is untied and already alerts as `own-session-outside-record`, so this route is noisy, not hidden. |
| T5 | **Injection into an open tied flow** (or one whose `end` was lost) before its open-flow entry expires | AP-35 residual (D4-73) | The run's own key, with more packets and bytes, and a later `last_utc`, than the run produced. |
| T6 | **Into the next reuse:** an SNMPv3 run that reuses an open conversation's 5-tuple re-points the entry, and the forger's later records tie to the new run | AP-35 residual (D4-73) | The new run's key, with more datagrams and bytes than that run sent and received. |
| — | The midstream reply, with the device as `ip.src` | AP-35 residual | **Not a tie.** Neither own-session rule judges it. The base rules do, once the baseline is acknowledged. Out of scope here. |

**What every route shares:** on each one, the traffic tied to an invocation is either more than the run produced (T1, T3, T5, T6, and T2 when the run's own flow survives) or different from it (T2 with the run's records evicted, T4). That is the property the rule tests.

## 2. What is known about a collector run's session, and when

**Before the run** (the C3 register and the collector's limits) the node knows the protocol, the endpoint (address, transport and port), the approved commands, and the bounds (deadline, maximum received bytes, step limits). That gives limits, not a profile: what the relay sends back (SER rows, varbind values) is not known until it arrives. **So the rule judges after the run's result, never before.**

**After the run**, the collector's C2 result (`contracts/adapter/result.go`) gives the node the following. The node already reads these in `configread.go`, `snmp.go` and `identity.go`.

| Item | Field | Telnet | SNMPv3 |
| --- | --- | --- | --- |
| The session's local end and connect time | `session.local_addr`, `session.connected_at` (C2 0.9) | yes | yes |
| Start and end | `started_at`, `ended_at` | yes | yes |
| Whether it connected | `session.connected` | yes | yes |
| Every chunk sent or received, with direction, phase, time and length | `transcript.segments[]` | the NVT data stream only. Telnet commands are removed (`modules/ied/telnet` package doc), and the client's 3-octet refusals are not in the transcript: `Stats` counts them, and the C2 result does not carry `Stats` | one segment per datagram sent or received, every retry included (`modules/ied/snmpv3` `Segment`), in its stored form: the scoped PDU in plaintext in place of `encryptedPDU`, the digest zeroed |
| Credential sent | `session.credential_sent` | once per session (`SendSecret`) | n/a (USM) |
| The agent's engine ID | `session.snmp.engine_id` | n/a | yes, pinned |

**What the collector does, from D2's facts in the baseline note §5:** the SEL-751 adapter opens at most one established connection per run, and retries the dial only when it fails before any byte is sent. The collector never runs two sessions to one asset at once. An SNMP run is one UDP conversation. **So each invocation owns exactly one established flow.**

**What the sensor's records show of a flow** (C13 0.1 §4.1 and §4.3, unchanged in 0.2):

- `flow` `start` and `end`, with `packets` and `bytes`. `bytes` is the wire length summed over both directions, TCP retransmissions included.
- `first_utc` and `last_utc` on the sensor's clock.
- The `end` reason and `syn_only`.
- For Telnet, an `insecure` record with `login.user` and `login.attempts`.
- For SNMPv3, an `encrypted` record with `engine_id`, `user`, `level`, `boots` and `time`. It is emitted **once per flow, at the first message**, which is the run's noAuthNoPriv discovery. So `level` and `user` show the discovery, never the authPriv steps.

## 3. What the detector can compare from sizes, counts and timing

The rule is one new rule, working name **`own-session-mismatch`** (§7). It judges each `(invocation_id, flow key)` that intake tied, once the invocation's result is known and the flow has ended, or its open-flow entry has expired.

| # | Comparison | Telnet | SNMPv3 | Routes it catches |
| --- | --- | --- | --- | --- |
| M1 | **One established flow per invocation.** A second established flow tied to the same invocation (`syn_only: false`, or carrying any other observation), by any tie path, the late index included, is a mismatch. So is a second `client-server` `start` of the same TCP key after that key's `end: fin` or `end: rst`. | yes | yes (a second conversation) | T1, T2 when the run's flow also tied, and T3 |
| M2 | **Packets.** | lower bound only: 3 for the handshake, plus at least one per segment of the transcript in each direction; ACKs and coalescing make it loose | **exact:** the number of transcript segments, one datagram each, with each retry recorded. The only exceptions are IP fragments of a datagram larger than the path MTU, which the sensor counts as more packets (inference; D2 to say whether a relay's responses ever exceed it) | T5, T6, and T1 and T3 on a shared key |
| M3 | **Bytes per direction.** | needs per-direction TCP payload (§7 item 2). With C13 0.2's combined wire `bytes`, the slack is per-packet header variance, padding and retransmissions: about 6 to 18 octets per packet. Over a 30 to 100 packet run that is hundreds of octets, enough to hide a short command, so it is not proposed as the Telnet measure | **near exact:** each segment's wire length is its stored length minus the change the stored form makes to the outer lengths (inference; D2 to confirm, §7 item 3), plus 8 + 20 + 14 octets per datagram, + 4 with a VLAN tag (`l2.vlan`). The PRP trailer is not counted, because `bytes` is after the discard | T5, T6, and T1 and T3 on a shared key |
| M4 | **Duration.** `last_utc` − `first_utc` of the tied key against `ended_at` − `connected_at`, + 2*g*. A difference within one sensor clock is unchanged by a constant move (T1). A move during the flow can only shorten it (§5). | yes | yes | T5 (a flow kept alive past the run) |
| M5 | **Login attempts.** `login.attempts` ≠ 1 on the tied Telnet flow, while the run sent its credential once | yes | n/a | a second login on a shared key |

**Not proposed:**

- `level` and `user` of the SNMPv3 `encrypted` record: they show only the discovery message (§2).
- `engine_id`: a spoofer talking to the real relay gets its real engine ID, so it never differs.
- Telnet `login.user`: a spoofer with the credentials types the same user name.
- Each of these reads only what C13 already carries, and none of them separates a spoofer who holds the credentials, which HR-24 assumes.

**T2 with the run's records evicted, and T4:** only the spoofed flow is tied, so M1 is silent. M2 to M5 then compare the spoofed flow with a run it did not carry, and they catch it unless it was shaped to the run's profile (§5). T4 also raises `own-session-outside-record` on the platform's own flow today.

**Evidence and alert.** The rule cites the tied flow's `start` and `end` (C13 §7.1). The alert says what was seen and nothing more, for example "flow from 192.0.2.x:p to the relay's 23/tcp tied to run R: 2 established flows, 1 expected" or "… 1,912 octets to the relay, the run sent 318". It never says "spoofed" (D4-68 ruling 10).

**What the node must keep.** The profile of each run (per-direction totals, segment count, `connected_at`, `ended_at`, connected or not) must be kept with the run's tie state: in the hold, and in the late index entry, until that entry is spent or expires. T1 and T2 tie after the result has committed, so the profile must outlive the result in memory. That is node state, D5's, not a contract (§7 item 4).

## 4. False-positive risk on the platform's own runs

Each of these must give no alert, and stage 2 builds a case for each:

| Source of a false positive | Answer in the rule |
| --- | --- |
| A sensor drop, or a run under degraded coverage, gives fewer packets or bytes than the run | M2 and M3 alert only on **more** than the run produced, never on less. A flow observed with any `degraded`, or with a seq gap or declared loss in its stretch, is judged on M1 only. The gap is visible elsewhere (`own-session-unseen`, coverage) |
| TCP retransmissions, duplicate ACKs, window updates | Not counted, if Telnet's M3 uses the sequence-number span (§7 item 2). Telnet's M2 is a lower bound only |
| PRP duplicates | `packets` and `bytes` are counted after the discard (C13 §4.3) |
| VLAN tags, Ethernet padding, TCP options | M3 for SNMPv3 takes the VLAN from `l2.vlan`. Padding and options do not touch a payload measure |
| Telnet option negotiation | Each direction's tolerance is bounded by `MaxCommands` × 3 octets plus `MaxSubnegotiation`, unless the C2 result carries Telnet's `Stats` (§7 item 3) |
| A Telnet dial retried before any byte | Gives `syn_only` flows, which M1 does not count (§3) |
| SNMPv3 retries and the time-window resend | Each is a transcript segment, so M2 and M3 count it |
| A run that fails (refused login, timeout, deadline, engine ID mismatch) | The transcript holds what was sent and received, so the profile is still exact. A run that never connected expects no flow |
| A run longer than `flow_idle_s`, cut by `idle` | Several `start`/`end` pairs of one key are summed by key (C13 §4.3), and an `idle` restart of the same key is not a second flow for M1. Only a new `client-server` `start` after `fin`/`rst` is |
| The sensor restarting during a run | A `midstream` `start` of the same key on a new sensor `run_id` is not a second flow for M1. Counts from before the restart are summed |
| Collector and sensor clocks apart | M4 compares durations, never absolute times, with 2*g* |

**How many own runs stage 2 needs.**

- At least **200 own runs per protocol**, spread over that matrix.
- **Telnet:** SER collections with 0, 1 and many rows; an `ID`-only run; a refused login; a slow device that hits step timeouts; a run at its deadline; a wake sent; with and without a VLAN; PRP duplicates; 1 % loss with retransmissions; reordering.
- **SNMPv3:** discovery, time sync and 1 to N steps; a lost response and its retry; a response near the message-size limit; an engine ID mismatch; a time-window Report.
- With 0 alerts in 200 runs, the false-positive rate per run is below 1.5 % at 95 % confidence (rule of three). D6 sets the number in stage 2; this is the floor I propose.
- These are `simulated` runs. A real relay's own-run false-positive rate stays unverified until a device is authorized.

## 5. What an attacker who knows the rule can still hide

1. **A session shaped to the run's profile, on a route where the run's own flow is not counted.** That means T2 with the run's records evicted, or T4 on a 0.8 result, which is noisy anyway. The attacker matches M2 to M5: packets, per-direction payload within the tolerance, and duration.
   - **Telnet:** the run's approved reads are replaced by commands of the same total length, in a session with one login. On a SEL relay a write needs `2AC` and the level-2 password, an exchange the run does not have. The attacker must drop some of the run's reads to make room, and must predict the relay's reply sizes. That is feasible for someone who has seen earlier runs.
   - **SNMPv3:** a `SET` at authPriv of the same encrypted size as the run's `GET` is invisible to any size measure. The collector never sends `SET` (`snmpv3` package doc), but the attacker can.
   - This is the **known miss** stage 2 labels and reports. It is not counted as a pass.
2. **Anything within the tolerance.** Injection (T5) of fewer octets than the tolerance per direction, in a flow kept alive within `flow_idle_s` + *g*. With M3 on payload, the tolerance is the Telnet negotiation bound, or zero for SNMPv3.
3. **Anything while the flow's coverage is degraded,** since M2 to M4 are then skipped (§4). The attacker can cause degradation by flooding the monitored segment (HR-21, AP-30). The degradation is visible, but it does not alert on this flow.
4. **A move of the sensor's clock during the spoofed flow** shortens its apparent duration, which helps M4 only. M1 to M3 are unaffected.
5. **The route preconditions stay as HR-24 states them:** spoofing the node's IP and MAC, control of the clock or the sensor host, and the relay's credentials. The rule does not remove a precondition. It removes "hidden whole" from every route where the run's own flow is also tied or where the session is not shaped.

So HR-24 would narrow from "hidden whole on every route" to "hidden only when shaped to the run's profile, on the eviction branch with the run's records lost (or T4, which alerts on the run's own flow)". Whether that is enough to close it is D1's call at stage 3, on the measurement.

## 6. The measurement that would close HR-24

Stage 2 is D6's. This section is what I propose to D6 and D1.

- **Where.** In process, over synthesized C13 observation streams paired with synthesized C2 results, through intake's tie and the detector, the way `modules/detection/netdetect` and `platform/node` are tested today (`simulated`). The tie routes are produced by building the stream that each route leaves: for T1, a record whose capture time lies inside the earlier window, read after the result; for T2, the run's records declared lost. The sensor's clock move and the node start are modelled by their outcome, not reproduced. A rig leg on a real sensor follows with the sensor's brief.
- **Spoofed cases, each of which must raise `own-session-mismatch`**, for Telnet and for SNMPv3 (D6 assigns the ids):
  1. T1: a second flow tied to one invocation, on a new 5-tuple.
  2. T1 and T3: the same 5-tuple reused after the run's `fin`, carrying a write-sized session.
  3. T2: the run's records evicted, a spoofed flow with more payload than the run, tied.
  4. T5: injection of more than the tolerance into an open tied flow.
  5. T6 (SNMPv3): datagrams after the run's on a re-pointed entry.
  6. Telnet: a second login on a shared key (M5).

  Each case has the node's IP and, on the node's segments, the node's MAC, so `node-address-spoofed` stays silent (brief).
- **Own runs: none may alert.** The matrix of §4, at least 200 per protocol.
- **Known miss, reported and not counted:** a T2 session shaped to the run's profile (§5 item 1), for each protocol.
- **Control:** the detector as on `main` at `34201bfd`, with the base-rule skip and no new rule. It must raise nothing on any spoofed case. That shows the measurement can fail.
- **Pass conditions, pinned by D6 before the counted run:**
  - every spoofed case alerts with `own-session-mismatch`, citing the tied flow;
  - no own run alerts;
  - the control raises nothing on every spoofed case;
  - the known miss is reported.

## 7. What this needs from contracts and from other roles (for D1)

| # | Need | Contract or role | Why |
| --- | --- | --- | --- |
| 1 | A new alert rule token, `own-session-mismatch` | C13 (`Rules` is closed: `contracts/netobs/alert.go` l.43) | No existing rule means "tied, but not the run's traffic" |
| 2 | Per-direction TCP payload octets on the `flow` `end` record, from the sequence-number span, so retransmissions do not count | C13 (a new field on `flow`) | Telnet's M3. Without it, Telnet's byte test is too loose to catch a short write (§3). Under option (b) the sensor is D4's own code, so it can compute this |
| 3 | Telnet's negotiation octets per direction (`Stats`) in the C2 result, or D2's statement of what a SEL relay sends; D2's confirmation of the SNMPv3 wire length from the stored form | C2 (D2), or D2's evidence | Sets the Telnet tolerance and makes SNMPv3's M3 exact |
| 4 | The run's profile kept with the hold and the late index entry, until the entry is spent or expires | D5's node design (§1.6), node state, no contract | T1 and T2 tie after the result has committed |
| 5 | The detector receives the profile per invocation | `modules/detection/netdetect` (D4), in process | No stored observation changes: `node.platform_session` stays `{invocation_id, tie}` |

**Not needed:** no C4 change, no content read (brief exclusion), no change to the collector's sessions, and no SSH (D4-95).

**If D1 refuses item 2:** the Telnet half of stage 3 measures M1, M2's lower bound, M4 and M5 only. The note then states that a short Telnet write on a shared key, on T3 or T5, is not caught.
