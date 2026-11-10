# D3: `modules/security/snmpegress` checked against the RFC texts

D3, 2026-11-06, at `main` `22b85a8`. This is D3-ack action 1, and D1-handoff line 42 makes role 3 responsible for any `snmpegress` layout error the texts reveal. The texts are the twelve in `reference/rfc/` (D4-58). All twelve pass `sha256sum -c SHA256SUMS`. Line numbers below are lines of those files. Evidence class: `desk` for the reading. The one code change is tested in Go (`go test ./modules/security/...`, Linux, local). Its CI result is on the PR.

The check was written from memory of the RFCs (D3-handoff §2). This note pins every layout it reads to a text. **Result:** one divergence, now fixed: OIDs had no 128-sub-identifier bound. The other rows match the texts. Where they don't, the check is deliberately stricter on our own outbound messages, which is policy and not an RFC claim, or it is lenient where the RFC makes the difference harmless.

## Layouts the check reads

| What the check reads | Text | Agrees? |
| --- | --- | --- |
| `SNMPv3Message`: version, `HeaderData`, security parameters as an OCTET STRING, then `msgData` | RFC 3412 §6, lines 1053 to 1101 | Yes. `msgVersion` other than 3 is refused first (`version`). |
| `HeaderData`: `msgID`, `msgMaxSize`, `msgFlags` of one octet, `msgSecurityModel` | RFC 3412 lines 1076 to 1089 | Yes. The check does not test `msgID`'s range (0 to 2^31-1). That is harmless: our client sets it, and the field carries no access. `msgMaxSize` must equal the register's `max_reply_bytes`, which C3 0.4 holds to 484 to 65,507 (`contracts/register/register.go:1036`, RFC 3412's floor). |
| Flag bits: auth `0x01`, priv `0x02`, reportable `0x04` | RFC 3412 lines 1080 to 1082 | Yes. Only auth+priv, or exactly the discovery shape, passes. |
| Reportable on a confirmed-class request | RFC 3412 §6.4, lines 1185 to 1199: "MUST always be one" for a Get. A receiver that sees zero "MUST process it as though" it were one. | **Lenient by design.** `TestAllowed` "authPriv not reportable" passes such a message. The receiver treats it as reportable, so letting it through gains an attacker nothing. Our client sets the flag (`modules/ied/snmpv3/session.go:227`). Left unchanged. |
| `msgSecurityModel` 3 is USM | RFC 3411 line 2490 | Yes (`security_model`). |
| `UsmSecurityParameters`: engine ID, boots, time, user name, auth parameters, priv parameters, in that order | RFC 3414 §2.4, lines 884 to 903 | Yes. Boots and time are bound to 0 to 2^31-1 on authPriv, as the text's ranges are. The user name must equal the session's, which C7 0.8 holds to 1 to 32 characters. |
| Engine ID 5 to 32 octets | RFC 3411 `SnmpEngineID`, line 2400 | Yes, through the pinned engine ID. C7 0.8 validates it (`contracts/authz/usm.go`, `usmEngineIDPattern`), and an authPriv message must carry exactly that one. |
| The discovery message: noAuthNoPriv, a zero-length user name, a zero-length engine ID, and an empty varbind list | RFC 3414 §4, lines 1722 to 1733 | Yes for each field the text names. **Stricter by policy** (C11 §4 rule 1): the reportable flag set, boots and time 0, empty auth and priv parameters, empty `contextEngineID` and `contextName`, and a `GetRequest`. The text says only "a Request message". |
| Time synchronization: authenticated, with the learned engine ID and boots and time 0 | RFC 3414 §4, lines 1742 to 1749 | Yes. It passes as authPriv with boots and time 0, which the check allows. |
| `msgAuthenticationParameters` length: 24 octets for HMAC-SHA-256, 48 for HMAC-SHA-512 | RFC 7860 lines 235 to 239 | **Not checked.** The egress check does not verify the MAC, so the field's length carries no access. A wrong length fails authentication at the agent, which then ends the session (HR-16). Left unchanged. |
| AES-128-CFB IV: boots (4 octets, big-endian), time (4), then the 8-octet salt from `msgPrivacyParameters` | RFC 3826 §3.1.2.1, lines 363 to 374 | Yes. The priv parameters must be 8 octets. CFB has no padding, so nothing may follow the scoped PDU (C6 on #449). |
| `ScopedPDU`: `contextEngineID`, `contextName`, then the PDU | RFC 3412 lines 1097 to 1101 | Yes. On authPriv, the context engine must be the pinned engine and the name empty (`context`). |
| PDU tags: Get `[0]` `0xa0`, GetNext `[1]` `0xa1`, Response `[2]`, Set `[3]`, GetBulk `[5]` `0xa5`, Inform `[6]`, Trap `[7]`, Report `[8]` | RFC 3416 §3, lines 372 to 399 | Yes. Only the operation's own read tag passes (`pdu_type`). |
| `BulkPDU`: request-id, non-repeaters, max-repetitions, varbinds | RFC 3416 lines 436 to 444 | Yes. Non-repeaters must be 0 and max-repetitions the register's value (1 to 32, C3 0.4). Both are inside the text's 0 to max-bindings. |
| A request's varbind value is `unSpecified` NULL | RFC 3416 line 460 | Yes (`varbind_value`). |
| BER length: definite form only | RFC 3417 §8 (1), lines 634 to 638 | Yes. Indefinite lengths are refused. |
| BER long-form length with more octets than needed | RFC 3417 §8 (1): "permissible" | **Stricter by policy.** The check refuses it on our own outbound messages, and D2's client writes minimal lengths. This matches D6-handoff fix (a) for GT-MIB's H12: the client's decoder accepts the form inbound, as the RFC allows. |
| Primitive form for INTEGER, OCTET STRING and OID | RFC 3417 §8 (2), lines 640 to 644 | Yes. The check matches tag bytes exactly, so a constructed OCTET STRING (`0x24`) is refused. |
| INTEGER in its shortest two's-complement form | X.690 §8.3.2 (BER itself; not among the twelve texts) | Yes. Integers are at most 8 octets with no redundant leading octet. |
| OID: each arc below 2^32, **at most 128 sub-identifiers** | RFC 2578 §3.5, lines 839 to 844 | **Diverged; fixed.** The arc bound was there, but nothing limited how many arcs an OID had. A `getbulk` or `getnext` continuation of 129 arcs inside the subtree passed. D2's client caps OIDs at 128 (`modules/ied/snmpv3/ber.go:45`), so the client's own check stops it. But the egress check has to hold the bound on its own (AP-5), or one client bug lets a malformed OID reach the device. Now `oid()` refuses more than 128 arcs (`ber`). |

## The fix

- **Failing test first.** `TestDenyCorpus` "a walk continuation of 129 arcs" (`entityTbl` extended to 129 arcs, inside the subtree) returned `""` (allowed), when `ber` was expected. `TestAllowed` "continuation of 128 arcs" pins the boundary.
- **Fix.** `maxArcs = 128` in `ber.go`, and `oid()` refuses an OID with more arcs.
- **After the fix:** `go test ./modules/security/...`, `./modules/ied/snmpv3` and `./tests/integration/gt_mib/egress` pass on Linux. `go vet ./...`, `GOOS=windows go vet ./modules/security/snmpegress` and GOROOT `gofmt -l .` are clean. CI on the PR gives the Windows result.

## For other roles (through the coordinator)

- **D6:** the deny corpus in `tests/integration/gt_mib/egress/deny_test.go` has no case of more than 128 arcs. Whether to add one is D6's call.
- **D2:** nothing to change. The client's 128 bound and minimal lengths are what this check assumes.
