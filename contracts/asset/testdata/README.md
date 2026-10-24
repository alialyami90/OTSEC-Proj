# C1 golden examples

Written by `generate.py` (run `python3 -I generate.py` here). Device values are taken from the SEL-751 instruction manual (S22, date code 20260910) and are `documented-example` values, not device captures. Serial numbers, addresses, operators, IDs and times are invented. No example was captured from a device. Transcript spans (FID at offset 124, CID at 221) point into the invented C2 example transcript of the same invocation, `contracts/adapter/testdata/results/valid/ok.json`, which arrives with C2; C2's tests check each span selects its value.

## Valid

| File | What it shows |
| --- | --- |
| `valid/sel-751-simulated.json` | SEL-751 in the simulated slice: Telnet labelled plaintext with an acknowledgement, FID corroborated by the operator record and a simulator session, binding `device-reported` and `spoofable`, with the FID compared before the password and the serial after. |
| `valid/sel-751-identity-mismatch.json` | The simulator reported a different FID: the attribute is `conflicting`, keeps the declared value, and the asset is suspended for `identity-mismatch`. |
| `valid/site-node.json` | The site platform node as a `server` asset carrying A5's posture labels: OS out of support with its standing condition and migration date, and storage durability unverified. |
| `valid/sel-rtac-syslog.json` | An RTAC heard only through Syslog over UDP: plaintext, acknowledged, bound by address only. |
| `valid/sel-751-address-only.json` | A valid SEL-751 record whose binding is `address-only`: nothing is compared before a password would be sent, so `CredentialAllowed` refuses it (A6 C1 re-check R-1). |
| `valid/later-minor.json` | A 0.3 record with a device class and a field 0.1 does not know: a 0.1 reader accepts it and reads the class as `unknown`. |
| `valid/later-minor-unknown-binding-method.json` | A 0.2 binding method `tpm-attested` claiming `cryptographic`: a 0.1 reader reads `spoofable`. |
| `valid/later-minor-binding-without-pre-credential.json` | A 0.2 binding method 0.1 does not know, with no `pre_credential`. It reads as `address-only` and gets no credential (R-1). |
| `valid/later-minor-unknown-source-method.json` | A 0.2 source method `simulator-replay` labelled `device-observed`: a 0.1 reader reads `inferred`, never a device observation. |
| `valid/later-minor-unknown-confidence.json` | A 0.2 confidence `verified`: a 0.1 reader recomputes it (`corroborated`). |
| `valid/later-minor-unknown-evidence-class.json` | A 0.2 evidence class `hardware-verified`: a 0.1 reader reads `inferred`. |
| `valid/profile-sel-751-ascii.json` | SEL-751 capability profile: identification and SER `simulated`, time quality `documented-untested`, Syslog `unsupported`, configuration `unknown`. `max_read_rows` 1,024, the session limits of D1-18 and the secret policy of D1-19, cited to S22. |
| `valid/profile-sel-rtac-syslog.json` | RTAC profile: Syslog push only, no adapter operations, so no firmware allowlist, no session limits and no `max_read_rows`. |

## Invalid

| File | What it shows |
| --- | --- |
| `invalid/observation-without-evidence-class.json` | An observation with no evidence class is rejected. |
| `invalid/unknown-field-in-own-minor.json` | A 0.1 record with a field 0.1 does not define: read strictly, because only a later minor may add fields (A6 C1 re-check S-1). |
| `invalid/attribute-without-observations.json` | An attribute with no observations, and so no evidence class, is rejected. |
| `invalid/corroborated-by-one-class.json` | Two device claims (session and Syslog) do not corroborate each other: one evidence class. |
| `invalid/conflicting-value-not-declared.json` | A conflicting attribute must keep the operator-declared value, never the device's claim. |
| `invalid/telnet-labelled-encrypted.json` | A Telnet endpoint labelled `encrypted-authenticated`. |
| `invalid/plaintext-without-acknowledgement.json` | A plaintext endpoint with no per-device acknowledgement. |
| `invalid/device-reported-claims-cryptographic.json` | A `device-reported` binding claiming to be cryptographic. |
| `invalid/pinned-key-on-plaintext.json` | A pinned-key binding on an asset with a plaintext endpoint. |
| `invalid/binding-attribute-not-declared.json` | A binding attribute with no operator-declared value to compare against. |
| `invalid/platform-node-on-relay.json` | Posture labels on an asset that is not of class `server`. |
| `invalid/os-out-of-support-without-condition.json` | `os-out-of-support` with no standing condition. |
| `invalid/unknown-device-class-at-0.1.json` | A device class 0.1 does not know, in a 0.1 record. |
| `invalid/unprefixed-unknown-attribute.json` | A vendor attribute without its vendor prefix (`cid` instead of `sel.cid`). |
| `invalid/simulator-value-labelled-device.json` | A simulator observation labelled `device-observed`. |
| `invalid/session-observation-without-span.json` | A session observation with no transcript span (A4 EP-2). |
| `invalid/missing-vendor.json` | The required `vendor` attribute is missing. |
| `invalid/other-major.json` | A 1.0 record is not readable as 0.x. |
| `invalid/serial-labelled-encrypted.json` | A serial endpoint labelled `encrypted-authenticated`: serial is always plaintext (C1-A3-1). |
| `invalid/ssh-authenticated-without-pinned-key.json` | SSH labelled `encrypted-authenticated` on a `device-reported` asset: without a pinned key the device is not authenticated (C1-A3-2). |
| `invalid/syslog-tls-authenticated-without-pinned-key.json` | The same for a Syslog-over-TLS endpoint on an address-only asset (C1-A3-2). |
| `invalid/acknowledgement-without-scope.json` | A plaintext acknowledgement with no scope (C1-A3-3). |
| `invalid/asset-id-from-device-content.json` | An asset ID derived from the FID instead of an assigned UUID. |
| `invalid/binding-without-pre-credential.json` | A `device-reported` binding on `serial_number` alone, with nothing compared before the password (A6 change 1). |
| `invalid/device-reported-on-ip-address.json` | A `device-reported` binding on `ip_address`, which the device does not report. |
| `invalid/pre-credential-not-in-attributes.json` | A pre-credential attribute that is not a binding attribute. |
| `invalid/address-only-with-pre-credential.json` | An address-only binding with a pre-credential attribute. |
| `invalid/profile-pre-credential-operator-only.json` | A profile claiming the family reports `ip_address` before authentication. |
| `invalid/case-variant-key.json` | An `IDENTITY_BINDING` key after the real binding, which plain `encoding/json` would let replace it (A6 change 3). |
| `invalid/duplicate-key.json` | `identity_binding` given twice. |
| `invalid/profile-adapter-without-allowlist.json` | A profile that sends adapter operations with no firmware allowlist (AP-27). |
| `invalid/profile-claim-without-citation.json` | A capability claim with no citation. |
| `invalid/profile-without-session-limits.json` | A profile that sends adapter operations with no `session_limits` (D1-18). |
| `invalid/profile-floor-within-idle-timeout.json` | A failed-auth floor of 15 min against an idle timeout of 30 min: a new session could land at the prompt the failed one left (C7-A2 change 1). |
| `invalid/profile-two-password-attempts.json` | Two password attempts per session; C7 allows one. |
| `invalid/profile-without-max-read-rows.json` | SER retrieval by adapter operation with no `max_read_rows` (D1-12). |
| `invalid/profile-read-rows-over-ceiling.json` | `max_read_rows` 4,096, above C4's ceiling of 2,048. |
| `invalid/profile-syslog-with-session-limits.json` | A listen-only profile with session limits. |
| `invalid/profile-syslog-with-max-read-rows.json` | A listen-only profile with `max_read_rows`. |
| `invalid/profile-syslog-with-secret-policy.json` | A listen-only profile with a secret policy. |
| `invalid/profile-without-secret-policy.json` | A family that takes a password, with no `secret_policy` (D1-19). |
| `invalid/profile-secret-policy-zero-mnemonic.json` | A secret policy with neither `mnemonic_len` nor `whole_word`: zero is not a mode (D1-19). |
| `invalid/profile-secret-policy-both-modes.json` | A secret policy with both `mnemonic_len` and `whole_word`. |
