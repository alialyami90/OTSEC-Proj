# The SNMPv3 client checked against the RFC texts (D2, 2026-11-06)

**Why.** C2 wrote the collector's SNMPv3 client (`modules/ied/snmpv3`, P4-3-C2 deliverable 4) from memory of the RFCs, because the texts were not in the project then. GT-MIB's agent is now being built from the texts themselves (D4-58), so the client is checked against the same texts first. That way a V-M1 failure is not the first place a misreading shows up. This is task 1 in [D2-handoff.md](../../handoffs/D2-handoff.md).

**Sources.** The twelve texts in `reference/rfc/`. `sha256sum -c SHA256SUMS` gives `OK` for all twelve, and D4-58 records where they came from. D2 read the texts first and did not open GT-MIB's agent patch, so the two readings stay independent. D6's eight points (relayed through the coordinator) were checked as well, and each is answered below.

**Evidence class.** `desk` for every reading, and `simulated` for the tests (the Go-level fake agent in `agent_test.go`). No device or SNMP endpoint was contacted, and no RFC test vector exists in these texts for HMAC-SHA-2 or AES-CFB, so none was run. The only vector the texts give, RFC 3417 §8.1, is now a test.

## Result

The client matches the texts on every layout it encodes or decodes, except for the seven divergences below. Each one now has a test that failed on `main` at `a774a97` and passes with the fix, all in `modules/ied/snmpv3`. None changes a contract, a code or a wire layout the client sends, apart from the request-id range (item 4). One more divergence is recorded but left open (item 8).

| # | Text | What the client did | Fix | Test |
| --- | --- | --- | --- | --- |
| 1 | RFC 3416 §4.2.3: a GetBulk Response can hold fewer varbinds than requested, "possibly zero", when the full response would not fit the message size (reason (1)) | A GetBulk Response with no varbinds ended the walk as complete, so a truncated walk read as a full one | With max-repetitions at least 1 (C3 0.4) and one repeated varbind, an empty GetBulk Response can only mean reason (1). It now ends the run with `failed.response_too_large`, bytes kept | `TestGetBulkEmptyResponse` |
| 2 | RFC 3412 §7.2 step 12 b): a Response whose cached values (snmpEngineID, securityName, securityLevel, contextEngineID, contextName) differ from the request's is discarded | Engine ID, user and authPriv were checked. contextEngineID and contextName were not | A Response counts only with contextEngineID equal to the pinned engine ID and contextName `""`, which is what the client sends | `TestResponseContext` |
| 3 | RFC 3414 §3.2 step 7 b): the non-authoritative side first takes the boots and time from an authentic message that is newer than `latestReceivedEngineTime` (1)), then checks the window against its local notion (2)) | It checked first, and updated only when the message's time was ahead of its own running estimate. So an estimate that ran ahead of a slow agent clock was never pulled back | `latestReceivedEngineTime` is kept (it is the agent time last taken, which only a received message sets), and step 1) runs before step 2), as written | `TestTimeWindowLatestReceived` (the collector's clock runs 40 s for each request and the agent's 1 s for each Response; without the fix the agent refuses the third request), `TestTimeWindowBootsMax` |
| 4 | RFC 3416 §3 prints request-id's range as `-214783648..214783647` | request-ids were drawn from 0 to 2^31-1 | request-ids are drawn from 0 to 214783647, which fits the printed range and the intended 32-bit one, so an agent that enforces either accepts the request. The printed range looks like a dropped digit, but the texts here give no erratum, so the client stays inside it | `TestRequestIDRange` |
| 5 | RFC 3826 §3.3.2 step 1: `msgPrivacyParameters` that is not 8 octets is a decryption error | An authenticated message with a salt of the wrong length ended the run with `failed.snmp_scoped_pdu_unreadable`, though nothing had been decrypted | The message is discarded and kept in the transcript, as the RFC says. `failed.snmp_scoped_pdu_unreadable` stays for a message that decrypted but did not decode (D4-54, which keeps the decrypted bytes) | `TestPrivacyParametersLength` |
| 6 | RFC 3417 §8 (1): "it is permissible to use more than the minimum number of length octets" | Long-form lengths of more than four octets were refused | Any number of length octets is accepted (1 to 126; 0x80 indefinite and the reserved 0xff are refused), with an overflow guard. A length past the datagram is still refused | `TestLengthForms` (the five-octet row flipped, three rows added) |
| 7 | RFC 3411 §5: an SnmpEngineID "may not be all zeros or all 'ff'H" | Only the length (5 to 32) of the pinned ID was checked | A pinned engine ID that is all zeros or all `ff` is refused before anything is sent (`failed.internal`) | `TestPinnedEngineIDForm` |

**Left open:**

8. RFC 3416 §4.2.2 has a GetNextRequest answered varbind for varbind, so a `noError` GetNext Response with no varbinds comes from an agent outside the RFC. The client still ends the walk there as complete. Ending the run instead needs a C2 code that names a protocol violation, and none of the 0.8 codes fits. This is proposed for the next C2 revision, and D1 decides. The only SNMP walk in the repository today, in `contracts/adapter/testdata/snmp/register.json`, uses GetBulk, which item 1 covers. D1's ruling (D4-60): the code comes in the next C2 revision, and until it exists no signed register may declare a GetNext walk. Item 3's exit report lists this as a limitation.

## What matches, with the section for each

| Layout or rule | Text | Code |
| --- | --- | --- |
| `SNMPv3Message` and `HeaderData`: msgVersion 3, msgID 0..2147483647, msgMaxSize 484..2147483647, msgFlags one octet, msgSecurityModel 3 | RFC 3412 §6 | `msg.go` `decodeMessage`, `messageOf` |
| msgFlags bits: auth 0x01, priv 0x02, reportable 0x04. Priv without auth is refused. Other bits are ignored on receipt and zero on sending | RFC 3412 §6.4, §7.2 step 5 d) and e) | `msg.go` |
| reportableFlag set on every request (a Confirmed Class PDU) | RFC 3412 §6.4 | `session.go` `send` |
| A fresh msgID on each retransmission; Responses and Reports matched by msgID | RFC 3412 §6.2, §7.2 step 10 a) | `session.go` `newID`, `accept` |
| `UsmSecurityParameters`: the six fields in order, boots and time 0..2147483647, user name 0..32 octets | RFC 3414 §2.4 | `msg.go` |
| Discovery: noAuthNoPriv, empty user, empty engine ID, empty varBindList; answered by a usmStatsUnknownEngineIDs Report | RFC 3414 §4, §3.2 step 3 b) | `session.go` `discover` |
| Time synchronization: authenticated request with boots and time 0, answered by a usmStatsNotInTimeWindows Report at authNoPriv | RFC 3414 §4, §3.2 step 7 a); RFC 3412 §7.1 step 3 d) 1) | `session.go` `exchange`, `report` |
| The 150-second window | RFC 3414 §2.2.3 | `timeWindow` |
| The usmStats OIDs `1.3.6.1.6.3.15.1.1.1` to `.6`, each with the scalar instance `.0` | RFC 3414 §5 (usmStats ::= { usmMIBObjects 1 }, snmpModules 15); RFC 2578 §4 (snmpModules ::= { snmpV2 3 }) and §7 (a scalar's instance appends a zero) | `session.go` constants |
| HMAC over the whole message with the digest zeroed; N = 24 octets with SHA-256 (key M = 32) and N = 48 with SHA-512 (M = 64); a digest of another length fails before any HMAC is computed | RFC 7860 §4.1, §4.2, §4.2.1, §4.2.2 step 1 | `usm.go` |
| AES-128 in CFB with s = 128, no padding; the IV is boots, then time (4 octets each, most significant first), then the 8-octet salt, all from the message's own fields; the salt is incremented per message | RFC 3826 §3.1.1.1, §3.1.2.1, §3.1.3, §3.1.4 | `usm.go` `cfb`, `session.go` `send` |
| The localized keys come in already localized (C7 0.8): the client never localizes. The AES key is the first 16 octets of the privacy key localized with the user's auth hash | RFC 3414 §2.6; RFC 7860 §5; RFC 3826 §1.2, §3.1.2.1 | `usm.go` `Keys` |
| Receive order: decode, flags, engine ID and user, digest, window, decrypt | RFC 3414 §3.2 steps 3 to 8 | `session.go` `accept` |
| PDU tags `[0]`–`[3]`, `[5]`–`[8]` (`[4]` obsolete and refused); BulkPDU's non-repeaters and max-repetitions; the value types and their tags; exceptions `[0]`–`[2]` IMPLICIT NULL; OCTET STRING at most 65535 | RFC 3416 §3; RFC 2578 §2 and §7 | `ber.go`, `msg.go` `decodeScoped`, `checkValue` |
| The client sends GetBulk with non-repeaters 0 and max-repetitions 1 to 32 | RFC 3416 §4.2.3 (N, M, R) | `session.go` `walk`; C3 0.4 |
| Definite lengths only; primitive form for INTEGER, OCTET STRING and OID; the §8.1 example decodes, and encodes the same with a minimal length | RFC 3417 §8 (1), (2), §8.1 | `ber.go`; `TestRFC3417Example` |
| sysDescr.0 `1.3.6.1.2.1.1.1.0`, sysName.0 `1.3.6.1.2.1.1.5.0` | RFC 3418 (system ::= { mib-2 1 }); RFC 2578 §2 (mib-2) | `identity.go` |
| entPhysicalTable `1.3.6.1.2.1.47.1.1.1`: the index (column 1) is not-accessible, and columns 2 to 19 are accessible, so 18 in all | RFC 6933 §4 (entityMIB ::= { mib-2 47 }) | `identity.go` |

## Leniencies kept on purpose

The client accepts some encodings that the texts do not require it to refuse. These are recorded so that no one reads them as conformance claims:

- A non-minimal INTEGER (X.690's rule, not one of RFC 3417's). The client always sends minimal ones.
- A non-zero reportableFlag on a Response or Report. RFC 3412 §6.4 says to process it as zero.
- A Report's request-id. RFC 3412 §7.1 step 3 c) 4) makes it 0 when the request could not be decrypted, so it is not checked.

## For GT-MIB (sent to D6 through the coordinator)

- **H12:** more length octets than needed are permitted (RFC 3417 §8 (1)), so the case is not hostile. The client now accepts any count of them.
- **H16:** the client discards the message, and the run ends in `failed.timeout`, which matches `expect_outer`. RFC 3414 §3.2 puts authentication (step 6) before decryption (step 8). The client checks the salt's length before the HMAC, so the observable result is the same either way, a discard. "Discarded before authentication" describes the client's order, not the RFC's.
- **W4:** 18 accessible columns (RFC 6933 §4), so 720 varbinds for 40 rows.
- **Responses** must carry contextEngineID equal to the agent's engine ID and contextName `""`. Otherwise the client now discards them (item 2).
- **An empty GetBulk Response** now ends the run with `failed.response_too_large` (item 1).
- **Request-ids** stay at or below 214783647 (item 4).

## Not covered here

- Interoperability. Only V-M1 over GT-MIB, and later hardware, shows it.
- The collector's UDP socket, buffer size against msgMaxSize, and the egress check. Those are D3's (`modules/security`), checked in `docs/phase4/D3-snmpegress-rfc-check.md` (#494).
- Key localization from a password (RFC 3414 §2.6 and A.2). It happens outside this client, in the credential tooling and in GT-MIB.
