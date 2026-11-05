# C2 0.7: what an SNMP result must say (C2, P4-3-C2)

**Status:** approved by C1 on #445, 2026-11-05, as part of C2 0.7, with §2.2's question settled: the asset is suspended, not the credential (`Result.SuspendsCredential`). Coded in `contracts/adapter` (`snmp.go`). It was a proposal to C1 first. It completes C2 0.7, which `docs/phase4/C2-c1-0.3-c3-0.4.md` §2.4 approved (D4-53) as eight codes (a ninth, `failed.snmp_fid_unreadable`, was added on #445), the SNMP transcript form and the `usm-digest` redaction. Coding that text showed it is not enough to write a valid SNMP result. Apart from the cap in §4 item 3, nothing here changes C1 0.3 or C3 0.4.

## 1. The gap

`Result.Validate` is written for the SEL ASCII session. Every rule below holds for every result today, and an SNMP session breaks each one:

- **Status `ok` needs `quit_sent`** (V-S13), and every after-auth code needs QUI too (D18). SNMP has no logout, so an SNMP run can never be `ok`, and `failed.snmp_error_status` and `failed.snmp_walk_not_increasing` can never be valid.
- **After-auth codes need `credential_sent` or access level `1`.** No credential is ever sent in SNMPv3: the keys never leave the collector (§2.4).
- **The dialogue rules** (`dialogue.go`) read every sent segment as a SEL line and every received one for a prompt. BER is neither.
- **Identity and observation spans may not hold 0x02 or 0x03** (the STX and ETX rule). In BER, 0x02 is the INTEGER tag, and the engine ID is binary.
- **The AP-27 rule** (a matching identity item read in the probe phase before the auth phase) is keyed to `credential_sent`, which is always false for SNMP. So nothing would require the engine-ID check before the first authenticated message (C3's #437 §4 rule 2).
- **An observation has no read path.** C1 0.3 `Source.read` needs the operation, and for SNMP the OID or the header. `Observation` has name, value and span only, so `modules/asset` would have to parse BER at the span to find the OID.

`TestEveryCodeHasAnExample` (C2 acceptance test 1) needs a valid example result for each new code, so 0.7 cannot pass its own tests without these rules.

## 2. Proposal: three additions to 0.7

### 2.1 `session.snmp`

`SessionFacts` gains `snmp`, an object present exactly when the session was SNMPv3.

```json
"session": {
  "connected": true, "wake_sent": false, "language_probe": "not-run",
  "password_prompt": false, "credential_sent": false, "echo_scan": "not-applicable",
  "access_level": "", "quit_sent": false,
  "snmp": { "engine_id": "80007c4f03020000273101", "authenticated": true }
}
```

- **`engine_id`** is discovery's `msgAuthoritativeEngineID` in lowercase hex (C1 0.3's form), or `""` when no discovery answer counted (§2.3: the outstanding `msgID`, from the endpoint's address and port).
- **`authenticated`** is true when at least one message from the endpoint authenticated and decrypted under the keys localized to the pinned engine ID.

When `snmp` is present:

- The SEL facts take the values above: no wake, probe `not-run`, no prompt, no credential, echo scan `not-applicable`, access level `""`, no QUI.
- The dialogue rules, the QUI rules and the STX and ETX rule do not apply. The transcript rules (exact cover, hash, phases only forward) do.
- Every segment is one whole SNMPv3 message (§2.4). Phases are `probe` (discovery), `auth` (time synchronization) and `operate` (the steps). There is no `close` segment.
- The only redaction reason is `usm-digest`. A SEL result may not carry it.
- `connected` means a datagram was sent. Not connected means an empty transcript, `engine_id` `""` and `authenticated` false.

Rules by code, in place of the SEL ones:

| Code | Rule |
| --- | --- |
| none (`ok`) | `authenticated`, and the identity matches |
| `refused.engine_id_mismatch` | no `auth` or `operate` segment sent, `authenticated` false, and the identity is a mismatch on `snmp_engine_id` (2.2) |
| any other before-auth code | no `auth` or `operate` segment sent, and `authenticated` false |
| the four USM failure codes, `failed.usm_not_in_time_window` | an `auth` or `operate` segment was sent |
| any other after-auth code | `authenticated` |
| a SEL-only code | invalid on an SNMP result |
| an SNMP code | invalid on a SEL result |

The SEL-only codes are those that need a prompt or a SEL line: `refused.session_elevated`, `refused.session_pending_password`, `refused.language_probe_rejected`, `refused.identity_mismatch`, `failed.identity_unreadable`, `refused.password_prompt_absent`, `failed.auth_rejected`, `failed.unexpected_access_level`, `refused.language_not_english`, `refused.firmware_condition_not_met`, `failed.access_level_dropped`, `failed.device_error`, `failed.config_unparsable` and `failed.unexpected_password_prompt`. The rest (the refusals before connecting, `failed.identity_mismatch`, the transport failures and the partial codes) apply to both.

### 2.2 Identity for SNMP

- **The engine ID is the first identity item.** Its name is `snmp_engine_id`, its expected value is the declared one, its observed value is `session.snmp.engine_id`, and its span covers the header octets in the discovery answer, a received `probe` segment. The span holds binary octets, so the observed value must equal their lowercase hex.
- **AP-27 for SNMP:** an `auth` or `operate` segment is sent only after a matching `snmp_engine_id` item in the `probe` phase. This is the result-side check of C3's #437 §4 rule 2.
- **The FID is compared after authentication,** as the SEL-751 compares its serial number (C1 0.3 §1.4). A differing FID in an authenticated response ends the run with `failed.identity_mismatch`, which suspends the asset and the credential as today. The response authenticated, so this is the device we pinned reporting other firmware, and the rule that nothing unauthenticated suspends (D4-53) still holds. **C1 to confirm** that the credential suspension should apply here too. The keys were not exposed to another device, so the asset suspension alone may be enough.

### 2.3 `observations[].read`

`Observation` gains `read`, required on every observation of a 0.7 result:

```json
{ "name": "firmware_id", "value": "SEL-2731M-R102-V1-Z003001-D20260408",
  "span": { "offset": 1844, "length": 35 },
  "read": { "operation": "sel27x1.snmp.entity", "oid": "1.3.6.1.2.1.47.1.1.1.1.10.1" } }
```

- **`operation`** is the C3 operation that read the bytes, the run's step (C1 0.3 §1.2). For the SEL-751 it is `sel.id`, or the SER read for the serial number.
- **`oid` or `header`**, exactly one, on an SNMP result only, with C1 0.3's values. `header` is `msgAuthoritativeEngineID`, for `snmp_engine_id`, whose value is then the hex of its span.
- **Checked against the register** (C3's review of #445): with the verified C3 package, `operation` is a step of the invoked run, and an `oid` is one of that operation's `oids` for a `get`, or inside its `subtree` (`register.InSubtree`) for a walk.
- `modules/asset` copies `read` into C1 `Source.read` and adds the transport from the endpoint. It never parses the transcript.
- A result below 0.7 has no `read`, and `modules/asset` reads a SEL-751 0.6 observation as `sel.id`, except the serial number, which is the SER read. This is the only inference, and it ends when the adapter writes 0.7.

## 3. What stays out of `contracts/adapter`

- **No BER parser in the contract.** `Validate` checks the facts above, not the messages. That every sent PDU is a register `get`, `getnext` or `getbulk` of the operation's OIDs is shown by the client's egress check (C3's #437 §4 rule 4), by `modules/ied/snmpv3`'s tests and by C6's V-M1 (b) audit of the GT-MIB transcripts.
- **`CheckLines` does not apply to an SNMP result.** It refuses one, so no SEL line rule is mistaken for an SNMP check.
- **Records:** the identity run reports observations only, and no records.

## 4. What I ask C1

1. Approve 2.1 to 2.3 as part of C2 0.7, coded in the same contract PR as C1 0.3 and C3 0.4. C3 and C6 review it there. The alternative is a C2 0.8 after the SNMPv3 client is written, which leaves 0.7's eight codes with no valid example until then.
2. Rule on the credential suspension in 2.2. C3's view (review of #445) is the asset only: SNMPv3 keys never cross the wire, so suspending the credential protects nothing. I agree.
3. C3's note on #445: cap an SNMP operation's `max_reply_bytes` at 65,507, the largest UDP payload over IPv4, instead of 0.3's 1 MiB. A larger value would advertise a `msgMaxSize` no datagram can carry. This changes C3 0.4's text, so it needs your approval. I recommend it.
