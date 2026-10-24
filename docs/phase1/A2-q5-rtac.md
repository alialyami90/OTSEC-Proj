# Q5: the SEL RTAC against C1 and C2

- **Owner:** A2. **Date:** 2026-10-24. **Brief:** P1-A2 Q5 test (`docs/agent-handoffs.md`).
- **Question (architecture.md, Q5):** can one adapter framework cover vendor behaviour without excessive complexity?
- **Test agreed in Phase 0:** express a second SEL device class, the RTAC, against the contracts on paper, and count every special case. "More than a couple means the abstraction is wrong" (`A2-device-feasibility.md` section 9).
- **Evidence:** documentation only.
  - S23 is the *ACSELERATOR RTAC SEL-5033 Software Instruction Manual*, date code 20260925, owner-supplied text. Page numbers are S23's.
  - The fixture is `tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt`.
  - No RTAC was contacted, and no RTAC capture exists.
  - Everything below is `documented-untested` or `inferred`.

## Answer

**Yes, if the framework is understood as C1 plus C4, with C2 used only for sessions the platform starts.**

- The RTAC fits C1 with no new field. Its asset record and capability profile are committed C1 examples, and the C1 tests validate both.
- It never reaches C2. Its profile has no adapter operation, so no invocation is ever built for it. C1 enforces this: there is no firmware allowlist, no `session_limits` and no `max_read_rows`.
- Its events land in C4, which already separates the sender from the subject and records how the sender was authenticated.

The count is three special cases, all in C1 and none in C2:

- **S1** is a one-sentence rule, now in C1.
- **S2** is a firmware caveat that 0.1 carries as a capability note.
- **S3** waits until a site turns on the RTAC's Syslog relay.

That is at the edge of the Phase 0 threshold. None needs a second envelope or a change to C2, so I read it as a pass.

Forcing the RTAC through C2 instead would take about nine special cases (section 5), which is why push collection stays out of C2.

**One correction to my own Phase 0 wording.** `A2-sel-portfolio.md` section 3 said "if the envelope only fits command/response, Q5 fails". That framed the test wrongly. C2 only fits command/response, by design. The question is whether the framework as a whole covers a push source without special-casing the envelope that does fit. It does.

## 1. What RTAC collection is

| Fact | Evidence |
| --- | --- |
| No device shell for monitoring. SSH carries engineering-access tunnels, and `AcRtacCmd` runs on the engineering PC. | `A2-sel-portfolio.md` section 2 (S24 Section 1) |
| Syslog is RFC 3164 with a 1,024-byte packet limit. The facility is fixed at 23, so PRI is 184 plus severity. | S23 p. 635 |
| The header carries the RTAC system time when the message is sent, with a year that RFC 3164 lacks, and the RTAC hostname. The MSG part carries the tag time stamp to the millisecond. In the manual's example the two times are 9.4 s apart. | S23 p. 636, Table 8.16; fixture |
| Destinations are configured by IP address and a severity threshold. The only transport offered is UDP, with a custom destination port in later firmware. | S23 pp. 636–637; Table A.1 (custom UDP port enhancement) |
| Only tags the project logs are sent. `User_Logged_On` and `User_Logged_Off` are logged by default, and 11 User Sessions tags exist. `Unsuccessful_Log_On_Attempt` names the user only from the third consecutive failure. | S23 p. 633; Table 12.2 |
| The RTAC keeps up to 10,000 Syslog messages and overwrites the oldest, and the platform cannot ask for a resend. | S23 p. 637 |
| From project version R153, the Syslog Collector extension receives other devices' Syslog over UDP or TCP. It can log those messages in the RTAC SOE, and the RTAC then forwards them with its own Syslog. | S23 p. 844, Syslog Collector overview |
| Firmware fixes that affect evidence: "syslog messages were issued with an incorrect time stamp" was fixed in R153-V0, R152-V2, R151-V6 and R150-V8. An "incorrect hostname following a firmware upgrade or RTAC hostname change" was fixed in R150-V0, R149-V2, R148-V5, R147-V4 and R146-V5. | S23 Table A.1, the rows for those versions (A2 reading of the text; each row was attributed by the FID block it sits in) |
| The FID is per hardware platform, for example `SEL-3530-R153-V0-Z000058-D20240918` and `SEL-3350-R153-V0-…`. Syslog does not carry it. | S23 Table A.1 |
| Risks D20–D23: account lockout after three failures, the web UI deletes logs, the watchdog under load, and logins mapped to OUT101. Each favours listening over polling. | `A2-sel-portfolio.md` section 4 |

## 2. The RTAC against C1

The committed examples are `contracts/asset/testdata/valid/sel-rtac-syslog.json` (the asset) and `valid/profile-sel-rtac-syslog.json` (the profile). Both validate (`TestValidExamples`), and the profile now cites S23.

| C1 element | RTAC value | Fits? |
| --- | --- | --- |
| Asset ID, node ID | Assigned at registration, as for every asset | yes |
| Attributes | `device_class` automation-controller, `vendor` sel, `product_family` sel-rtac and `ip_address` are operator-entered. `model` (SEL-3530 and others) and `firmware_id` can only be operator-entered, because Syslog carries neither. `hostname` may be observed with method `syslog-received`. | yes, no new attribute |
| Endpoint | `syslog-udp` to the node's listening port, labelled `plaintext-unauthenticated` with a `lab-only` acknowledgement | yes. In 0.1 this means RTAC Syslog is accepted for the lab only, exactly like Telnet to the relay. A production scope needs the same owner decision. |
| Identity binding | `address-only`, `spoofable`, no `pre_credential` | yes. Binding on `hostname` (device-reported) is possible, but not recommended: the hostname is operator-set, and older firmware sends a wrong one after an upgrade (section 1). A wrong hostname should show as a `conflicting` attribute, not as an identity mismatch. |
| Senders | `CheckSenders`: one asset per (node, transport, address) | yes, until the relay is turned on (S3) |
| Suspension | Only reason `operator` applies | yes, after S1 |
| Profile | `event-push` by `syslog-receive`. `identification` by `operator-entry`. `health` is `unknown`, because silence is not a signal. Allowlist `none`. No `session_limits` and no `max_read_rows`; both are now rejected on a listen-only profile (two invalid examples). | yes |

## 3. The RTAC against C2

No RTAC field reaches C2:

- A C2 invocation is built by the collector from an accepted C7 run, the C1 asset and the profile.
- The RTAC profile names no operation, so no run can be accepted for it. With allowlist `none`, C1 would reject any profile that did name one.
- C2's codes, transcript, session facts and limits are never exercised. C2 needs no change.

## 4. Special cases counted

| # | Case | Where | 0.1 action | Status |
| --- | --- | --- | --- | --- |
| S1 | **Suspension of a source the platform only listens to.** C1 said a suspension "stops collection". The platform cannot stop a device sending. Dropping what it sends would discard native evidence (EP-1). | C1 | Done: `Suspension` and `doc.go` now say a suspension stops adapter sessions, never reception, and that only `operator` applies to a listen-only asset. Whether events from a suspended asset carry a flag is A4's call in C4. | resolved in this change |
| S2 | **Firmware matters for evidence, not for safety.** With allowlist `none`, nothing gates the RTAC. Older firmware may send a wrong time stamp or hostname, and the firmware ID is only operator-entered. | C1 profile, C4 parser | A capability note in the profile. A4's RTAC parser should treat the event time from firmware below the fixed versions, or from an asset with no declared `firmware_id`, as of unknown accuracy. A structured "evidence caveat by firmware" field could come in a later minor if a second family needs one. | note only |
| S3 | **The RTAC relaying others' Syslog.** With the Syslog Collector on, messages about other devices arrive from the RTAC's address. A `sender-address` binding would attribute them to the RTAC. C4 already says a relaying sender is never the subject, but the receiver must know which senders relay. The relayed message format is not shown in S23. | C1 endpoint | None in 0.1, and no site in scope uses it. Proposed for 0.2: a per-endpoint `relays` marker. With it, the receiver does not bind by sender address unless the content names the RTAC itself. | deferred, `unknown` format |

**C2: zero cases.**

## 5. Forcing push into C2 (why not)

A "receive" invocation for the RTAC would need these exceptions to C2's rules:

1. An invocation with no C7 run.
2. An invocation with no credential.
3. An invocation with no register operation.
4. No session, and therefore no session facts, no `QUI` and no close.
5. No limits that mean anything (deadline, steps, interval).
6. A "transcript" of datagrams from an unauthenticated sender, in arrival order rather than exchange order.
7. Result codes that cannot occur: every `refused.*` and most `failed.*`.
8. No end, because the source never finishes.
9. Loss that C2 cannot see, because UDP drops datagrams silently.

That is nine special cases in the envelope every SEL-751 run depends on, which is what Phase 0 warned against.

## 6. Where the rest lands (for other owners, not counted)

| Item | Owner | Note |
| --- | --- | --- |
| Two device times per message | A4 (C4) | C4 has one `DeviceTime`. The MSG tag time is the event time. The header send time stays in the native bytes and is never used as the event time. If a consumer needs the send time as a field, that is a C4 question. |
| UTC offset of the tag time | A4 (C4) | Not stated in S23. `offset` stays `unknown` unless an operator records it (basis `operator`). |
| Origin authentication | A4, A3 | UDP gives `origin_auth` `none`. Such events may raise alerts but may not drive automated actions (C4). |
| Named users and roles | A3 (C7) | Not exercised: the platform holds no RTAC credential. An active RTAC read (web API, SNMP) would need a named account, and C7 0.1 is built around the relay's per-level passwords. Not proposed (D20–D22). |
| SNMP or web API reads | A1 (C3) | Out of scope. They would not fit C3's line format (`[A-Z0-9]+( [A-Z0-9]+)*`), so an RTAC adapter would need a register format for requests that are not lines. |

## 7. Follow-ups

- A4: confirm the S2 parser rule and the two-times note.
- A1: decide whether a production scope for UDP Syslog is in Phase 2. The owner accepted Telnet for the lab only. RTAC Syslog needs the same decision, and so do the SEL-2730M and SEL-2488.
- A6: when an RTAC or its Syslog is available, check the header and tag time difference, and the hostname after a hostname change.
- A2: propose the `relays` endpoint marker (S3) in C1 0.2 if a site enables the RTAC Syslog Collector.
