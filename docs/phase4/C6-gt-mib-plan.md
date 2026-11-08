# GT-MIB: the plan (C6, P4-3-A6 part 2)

C6, 2026-11-05. This is part 2 of P4-3-A6 (#435). GT-MIB is a test-only SNMPv3 agent and its case set. It is the ground truth for V-M1 (a) to (e), on the family D4-51 chose: the SEL-2731 and SEL-2741 in RSTP mode. It is built from the vendor's guide and the standard MIBs only. Nothing in it comes from the client being tested.

**Evidence class.** `desk` for this plan, and `simulated` for every result it produces. No switch has been contacted, and none will be. What the agent serves follows the documents, and every value the documents do not print is labelled **SYNTHESIZED**. A result over GT-MIB shows what the client does with what was served. It does not show what a real switch serves.

**Sources.**

- **S29** is the RSTP user's guide, 20260424 (`phase0/manuals-SEL/RSTP_UG_20260424.pdf`). From it:
  - pp. 7 to 8 give the FID form and the mode letter;
  - pp. 42 to 47 give the USM settings, the engine ID form and the served OIDs;
  - p. 75 says the FID is in the Entity MIB;
  - Tables A.3 and A.4 on p. 62 list the FIDs.
- **Drafts:**
  - C2's family note and contract drafts (#439 at 92026c9, with D4-53);
  - C3's §4 rules (#437 at 1c9e479).
- **RFCs:** RFC 3411, 3412, 3414, 3416, 3418, 3826, 6933 and 7860, plus RFC 2578 (the OID roots `mib-2` and `snmpModules`, §2; the OID bounds, §3.5), RFC 3417 (BER, §8), RFC 1157 and RFC 1901 (the v1 and v2c layouts). All twelve texts are in `/mnt/project-files/rfc/` with `SHA256SUMS` (D4-58). This plan was first written from memory, before the texts were in. On 2026-11-06 D6 checked every RFC-derived layout against them, and D2 checked them independently. Each is now listed under `confirmed` in `cases.json`, with its RFC, section and lines. Two corrections followed: W4 is 720 varbinds, not 680 (RFC 6933 has 18 accessible columns), and H12 is a positive case (RFC 3417 §8 (1)).

## 1. What GT-MIB is

- **Where it lives.** `tests/integration/gt_mib/`, owned by C6:
  - a Go agent, `agent/`, built only for tests;
  - a case table, `cases.json`, written by hand like GT-ADV, with each case's expected code, health line and PDU counts;
  - a runner that starts the agent on a loopback UDP port and the real `otsec-collector` against it.
- **It is independent of the client.** The agent has its own BER encoder and decoder and its own USM, written from the RFCs. It does not import `modules/ied/snmpv3`, C3's egress check, or any `contracts/` package other than the test clock. A test reads the agent's imports and fails on any of them. So a shared bug cannot make the client and the agent agree.
- **The agent records every datagram it receives**, decoded with its own decoder, in a log. That log is the independent oracle for "no SET" and "only the named OIDs" (V-M1 (b)). The collector's transcript is compared with it, not trusted instead of it. The transcript holds the decrypted PDU with the digest zeroed (#439 §2.4), so the comparison is on decoded PDUs, never on raw bytes.
- **What it serves: exactly S29's list (pp. 46 to 47).**
  - The objects are the SNMPv2-MIB system group, `entPhysicalTable`, the listed UCD-SNMP-MIB, IF-MIB, LLDP-MIB, BRIDGE-MIB and RSTP objects, `snmpEngineID`, and the SEL power-supply subtree.
  - Anything else gets `noSuchObject`.
  - A GETNEXT past the last object gets `endOfMibView`.
  - The served list is a data file copied from S29, with the page cited for each line. A test checks that the agent serves exactly that list.

### 1.1 The values it serves

| Object | Value | Label |
| --- | --- | --- |
| FID | real FIDs from S29 p. 62: `SEL-2731M-R102-V1-Z003001-D20260408`, `SEL-2741M-R102-V1-Z003001-D20260408` and `SEL-2731M-R100-V0-Z001001-D20231120` | documented |
| The FID's column and row in `entPhysicalTable` | by default `entPhysicalSoftwareRev` (column 10, RFC 6933 §4) of row 1, the chassis. Cases move it. | SYNTHESIZED |
| The number of `entPhysicalTable` rows | 6 by default: chassis, power supply, and four port modules | SYNTHESIZED |
| Every other `entPhysicalTable` cell | plausible text that never matches the FID grammar, unless a case needs it to | SYNTHESIZED |
| `sysDescr.0`, `sysObjectID.0` | `sysDescr` holds no FID by default. `sysObjectID` is under SEL's enterprise arc `1.3.6.1.4.1.31823` (the arc S29 prints for the power-supply MIB), at a made-up branch. | SYNTHESIZED |
| `sysName.0` | `gt-mib-sw1` | SYNTHESIZED (operator-set on a real switch) |
| Engine ID | `80 00 7C 4F 03` and then a locally administered MAC, `02:00:00:27:31:01`. This makes it plain that it is no real unit's MAC. | form documented (p. 42), MAC SYNTHESIZED |
| USM user | one user, authentication HMAC-SHA-256 or SHA-512, privacy AES-128, with a test-only password from a published seed list (as `advisorytest.Key`) | test credential |

**What GT-MIB therefore cannot show:**
- that the client finds the FID where a real switch puts it, although it does show the client finds it by form wherever it is put;
- what `sysDescr` and `sysObjectID` really contain;
- the real row count;
- which AES-256 key extension the device uses;
- the device's password length limit;
- whether the engine ID survives a firmware upgrade.

Each of these is a hardware item (V-M1's H item).

## 2. Cases

Each case gives the expected C2 code (#439 §2.4), the health line, and two counts: the number of datagrams the agent received, and the number of authenticated requests. "Bytes kept" means the transcript holds every message sent and received, and C8's `transcript_sha256` matches it.

### 2.1 Identity, positive (V-M1 (e))

| ID | Agent setup | Expected |
| --- | --- | --- |
| I1 | default, SEL-2731M R102-V1 | `ok`. `firmware_id`, `model` `SEL-2731M`, `firmware_version` `R102-V1`, `hostname`, `snmp_engine_id`. Each is `device-read`, with `read.transport` `snmpv3` and the operation that read it. Each carries the `oid` the agent served it under, except `snmp_engine_id`, which carries `"header": "msgAuthoritativeEngineID"` (C1 0.3, #439 at cb6ffdf). The `model` and `firmware_version` spans lie inside the FID's span. |
| I2 | SEL-2741M | the same as I1, for the other model, with the engine ID cited by `header` |
| I3 | FID moved to `entPhysicalDescr` of row 3 | `ok`. The `oid` names that column and row. This is the FID found by its form. |
| I4 | the same FID in `sysDescr.0` and in the table | `ok`. Equal values count as one match. |
| I5 | `sysName.0` answers `noSuchObject` | `ok`, with no `hostname`. The transcript shows the exception, and it is not an error. |
| I6 | R100-V0 | `ok`. Placing the version is the matcher's job, and GT-ADV's rule applies. |

### 2.2 Identity, parse failures

| ID | Agent setup | Expected |
| --- | --- | --- |
| F1 | no value matches the grammar | parse failure, no FID attribute, bytes kept |
| F2 | two different matching FIDs, in two rows | parse failure. Never the first match. |
| F3 | an OT SDN FID, `SEL-2731S-…` | parse failure, because the grammar requires `M` |
| F4 | `SEL-2743M-R102-V1-Z003001-D20260424`, a real FID (S29 Table A.2) outside the family | parse failure, because the grammar admits only 2731 and 2741 |
| F5 | a FID with trailing bytes or a non-ASCII byte inside it | parse failure |
| F6 | a declared `product_family` whose model list excludes the read model | `ok` run, and the read model is kept. Health shows `identity.family_conflict`. The match uses the read model (#439, GT-ADV D11). |

### 2.3 USM and downgrade (V-M1 (c), HR-16)

| ID | Agent behaviour | Expected | Authenticated requests |
| --- | --- | --- | --- |
| U1 | discovery returns another engine ID | `refused.engine_id_mismatch` | 0 |
| U2 | wrong digest (another password), Report sent noAuthNoPriv as a real agent sends it | `failed.usm_wrong_digest`. No retransmission after a failure Report. | 1 |
| U3 | unknown user, Report sent noAuthNoPriv | `failed.usm_unknown_user` | 1 |
| U4 | configured for SHA-1 only. The client's SHA-256 is answered with a `usmStatsWrongDigests` Report (noAuthNoPriv), or with silence. | `failed.usm_wrong_digest` (1 authenticated request) or `failed.timeout` (2). No request at SHA-1 or MD5, and none at a lower level. | 1 or 2 |
| U5 | `usmStatsUnsupportedSecLevels`, sent noAuthNoPriv | `failed.usm_unsupported_sec_level`. No retry below authPriv. | 1 |
| U6 | `usmStatsDecryptionErrors`, sent noAuthNoPriv | `failed.usm_decryption_error` | 1 |
| U7 | one authenticated time-window Report, then normal | `ok`. The request is sent again with the corrected boots and time. That resend is not the retransmission (#439 §2.3). | 2 |
| U7b | an authenticated time-window Report, then the corrected request is dropped, then its retransmission is answered | `ok` | 3 |
| U8 | a time-window Report twice | `failed.usm_not_in_time_window` | 2 |
| U9 | an unauthenticated time-window Report | `failed.usm_not_in_time_window`. Its boots and time are never adopted (#437 rule 1, #439 §2.3 step 3). | 1 |
| U10 | answers an authPriv request with a noAuthNoPriv Response | the Response is discarded, not parsed. `failed.timeout`. | 2 |
| U11 | a Response with a bad digest, then silence | discarded, `failed.timeout` | 2 |
| U12 | v2c only, no v3 | `failed.timeout` after discovery and its one retransmission: the agent receives 2 datagrams. The client sends no v2c packet: the agent's log shows no community-based message. | 0 |
| U13 | endpoint transport `snmpv2c` in the asset record | the record is refused at load (V-M1 (d), C1 0.3) | 0 datagrams |
| U14 | a credential that names MD5, SHA-1, DES or AES-256 | refused when the credential is decoded, because the enums cannot name them (#437 §2.1) | 0 datagrams |
| U15 | a forged noAuthNoPriv `usmStatsWrongDigests` Report with the outstanding `msgID` | the run fails with `failed.usm_wrong_digest`, and suspends neither the credential nor the asset: the next run succeeds (C6 on #439) | 1 |
| U16 | the same Report with another `msgID`, or from another source port | discarded, recorded as received, and the run succeeds | 1 |
| U17 | answers an authPriv request with an authNoPriv Response carrying a valid digest | discarded unparsed (#437 rule 1). `failed.timeout`. The agent's log and the transcript show no plaintext Response parsed. | 2 |
| U18 | discovery returns the pinned engine ID, and a later Response carries another `msgAuthoritativeEngineID` | discarded before its digest is checked (#437 rule 2). `failed.timeout`. | 2 |
| U19a | a second `usmStatsUnknownEngineIDs` Report, after an authenticated exchange | the session ends (#437 rule 1, Report order) | 1 |
| U19b | a `usmStatsNotInTimeWindows` Report before discovery's Report | the session ends, and its boots and time are not adopted | 0 |
| U20 | after the one adoption, an authenticated Response with lower boots, or with time outside the 150-second window; then a Report claiming lower boots | the Response is discarded, the Report is not adopted, and the client's engine boots never move backwards (#437 rule 3). `failed.timeout`. | 2 |

### 2.4 The walk and its bounds (V-M1 (b), AP-28)

| ID | Agent behaviour | Expected |
| --- | --- | --- |
| W1 | returns an OID outside `entPhysicalTable` in the middle of a response | `ok`. The walk ends there. The varbinds after that OID in the same response are kept in the bytes but never parsed into attributes, and no later request carries that OID or anything after it (steered walk, #437 rule 5). |
| W2 | returns the same OID again (a loop) | `failed.snmp_walk_not_increasing` after 1 request |
| W3 | returns an earlier OID inside the subtree | `failed.snmp_walk_not_increasing` after 1 request |
| W4 | 40 rows × 18 columns (RFC 6933 §4: entPhysicalEntry's accessible columns are 2 to 19) = 720 varbinds, more than `max_varbinds` 512 | `failed.response_too_large`, every byte kept, no identity attribute presented as complete (C2's question 5) |
| W5 | answers 1 varbind per GetBulk, whatever `max_repetitions` says | `failed.response_too_large` at `max_requests` (32), with 32 requests counted |
| W6 | honours `msgMaxSize`, which equals `max_reply_bytes` 1472, with 16 repetitions | `ok`. Each response is at most 1472 bytes. |
| W7 | ignores `msgMaxSize` and sends 4000 bytes | `failed.response_too_large`, bytes kept |
| W8 | a Response with `error-status` `authorizationError` | `failed.snmp_error_status`, bytes kept |
| W9 | `endOfMibView` inside the table | the walk ends normally |
| W10 | answers the first `GetRequest` for the system operation's two OIDs with a `noError` Response carrying sysDescr's binding alone | `failed.snmp_varbinds_mismatch`, the Response kept, no value from it, and nothing sent after it (C2 0.9, RFC 3416 §4.2.1) |
| W11 | the entity operation as a `GetNext` walk: the second `GetNextRequest` is answered `noError` with no binding | `failed.snmp_varbinds_mismatch`, not a complete walk. The values of the earlier Responses are kept, none from that one, and nothing is sent after it (C2 0.9, RFC 3416 §4.2.2) |
| W12 | the same walk, with the second `GetNextRequest` answered `noError` with two bindings | `failed.snmp_varbinds_mismatch`. Neither binding gives a value, and nothing is sent after it |

W10 to W12 are C2 0.9's test 3 (`docs/phase4/D2-c2-0.9.md` §6), and D4-60's bar on `GETNEXT` walks lifts only with them green at the 0.9 code's merge head. W10 runs on the binaries in V-M1's run, because the system operation is a two-OID `get`. W11 and W12 need the entity operation as a `GetNext` walk, which no signed register holds while the bar stands. So they run at the client: C2's SNMPv3 session over a UDP socket against the case's agent, with the test package's entity operation as a `getnext` (`tests/integration/gt_mib/client`). They leave V-M1's binary run, which has no package to run them with.

Every request in W1 to W10 is checked in the agent's log for these things:
- the PDU is `GetRequest` or `GetBulkRequest`, as the operation names;
- for a `get`, each OID is one the operation names;
- for a walk, each OID lies inside the subtree;
- `max-repetitions` is the register's value and `non-repeaters` is 0;
- `msgMaxSize` equals `max_reply_bytes`;
- `msgFlags` is authPriv, except for the one discovery message.

### 2.5 Transport faults

| ID | Agent behaviour | Expected |
| --- | --- | --- |
| T1 | drops the first copy of one request | sent again once, with a fresh `msgID`. `ok`. |
| T2 | drops both copies | `failed.timeout`. Exactly 2 copies sent. |
| T3 | silent from the start (a node not on the Permitted Hosts list) | `failed.timeout`. Health reports a timeout, not an identity result. |
| T4 | a Response with another `msgID` or `request-id` | discarded |
| T5 | a Response from another source port or address | discarded |

### 2.6 Hostile responses (the BER parser, TB10)

Malformed messages are written into the agent's replies. The collector must fail the run cleanly, keep the bytes, never panic, and never read past the datagram. The corpus runs at two layers (C3 on #441):
- **the outer message**, which is parsed before authentication, so any host on the station LAN can reach that parser. This layer is the one that matters for AP-28;
- **the `ScopedPDU`**, which is parsed only after decryption, so only a key holder can reach it.

The corpus is:
- truncated messages;
- a length longer than the datagram;
- indefinite-length encoding;
- nesting deeper than 64;
- an INTEGER or `Counter64` over 9 octets, or a 9-octet `Counter64` without the leading 0x00. A valid 9-octet `Counter64` (2^63 or more, with the 0x00 lead) is a positive case, because UCD-SNMP and `ifXTable` serve such values;
- an OID arc of 2^32 or more;
- an OID with 129 arcs;
- an empty OID;
- an OCTET STRING longer than its message;
- ~~a non-minimal length encoding~~ (H12). RFC 3417 §8 (1) permits a long form with more length octets than needed, so H12 is a positive case at both layers (D6, 2026-11-06). Our own egress check still refuses the form on outbound messages, as policy;
- trailing bytes after the message;
- a non-minimal OID arc (a leading `0x80`);
- `msgAuthenticationParameters` of the wrong length for the algorithm (not 24 bytes for HMAC-SHA-256, or not 48 for SHA-512), which is discarded before any HMAC is computed;
- `msgPrivacyParameters` that is not 8 bytes;
- an inbound PDU of a type a client never accepts (SetRequest, Trap or Inform), which is discarded.

The same corpus seeds a Go fuzz target on the client's decoder. That target is C2's to add, and GT-MIB supplies the seeds.

### 2.7 The egress deny corpus (V-M1 (b), #437 rule 4)

These are unit cases fed straight to C3's egress check, with no agent involved. Each is an encoded message that must be refused:
- a SetRequest, an InformRequest, an SNMPv2-Trap, a Report and a GetResponse;
- authNoPriv;
- noAuthNoPriv that is not discovery;
- a `get` with an OID the operation does not name;
- a walk continuation outside the subtree;
- `max-repetitions` other than the register's;
- `non-repeaters` other than 0.

It also holds one community-based v1 `GetRequest` and one v2c `GetRequest`, as whole messages (HR-17). Item 3 has no path that builds them, but the check must still refuse them.

It also holds thirteen near misses of the discovery shape, one per field (#437 rule 4 at 1c9e479), each with that field off:
1. `msgVersion` 1 (a v2c message);
2. a `msgSecurityModel` other than 3;
3. the reportable flag cleared;
4. a nonempty authoritative engine ID;
5. nonzero boots;
6. nonzero time;
7. a user name;
8. nonempty authentication parameters;
9. nonempty privacy parameters;
10. a nonempty `contextEngineID`;
11. a context name;
12. a `GetNextRequest`;
13. one varbind.

There is also one discovery message sent after the engine ID is known. The exact discovery shape before the engine ID is known is the one message admitted. Each refused case names the rule that refused it, by the stable rule names C3's check will return (for example `pdu_type`, `security_level`, `version`, `discovery_shape.user_name`, `oid_not_named`, `oid_outside_subtree`, `max_repetitions`, `non_repeaters`).

### 2.8 Module off, and the transcript

| ID | Setup | Expected |
| --- | --- | --- |
| M1 | `asset` off, with an SNMP schedule entry | the entry is refused at load, and the agent receives 0 datagrams over a full schedule period (V-M1 (a)) |
| M2 | `asset` off, `applicability` on | the configuration is refused (D4-50) |
| M3 | any `ok` run | every segment's `msgAuthenticationParameters` is zero bytes of the right length, with a `usm-digest` redaction. The test then searches for key material (C3 on #441): the test password; the master key Ku and the localized keys for each algorithm; and the AES key, which is the first 16 bytes of the localized privacy key. Each is searched as raw bytes, as hex in both cases, and as base64. The search covers the transcript, C8's audit records for the run, the health lines, the collector's log, and the node's store and configuration. Under D4-50 the node holds no USM material at all, so any hit anywhere fails the test. |

## 3. What it depends on, and the order of work

1. **Before any agent code:** the RFC text (C1's request to the owner). Without it, the column numbers stay unconfirmed and the agent is built against memory. I do not want that for a ground truth. *Done: the texts arrived on 2026-11-06 (D4-58), and the table's layouts are confirmed against them.*
2. C3 0.4 and C2 0.7 must be approved (#439), and C3's §4 rules (#437). Then the case table's codes are final.
3. The case table, `cases.json`, is committed first, before the agent, as GT-ADV was.
4. Then the agent and its import check, the served-list check, and the deny corpus, which can run as soon as C3's egress check exists.
5. Then the real-binary runs, once the collector has the SNMP client (Stage C).

## 4. What this plan asks of others

- **C2:**
  - the fuzz target on the decoder (2.6);
  - the transcript stores the full message so that M3 can search it.
- **C3:**
  - the egress check takes one encoded message and returns the rule that refused it, so that 2.7 can name each rule.
- **C5:**
  - a way for the runner to start the collector with a schedule that has one SNMP entry, on the test clock.
- **The owner, through C1:**
  - RFC 3411, 3412, 3414, 3416, 3418, 3826, 6933 and 7860 in the project files, or access to www.rfc-editor.org. *Done (D4-58).*
