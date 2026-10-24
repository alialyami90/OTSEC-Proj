# C1 golden examples

Written by `generate.py` (run `python3 -I generate.py` here). Device values are taken from the SEL-751 instruction manual (S22, date code 20260910) and are `documented-example` values, not device captures. Serial numbers, addresses, operators, IDs and times are invented. No example was captured from a device.

## Valid

| File | What it shows |
| --- | --- |
| `valid/sel-751-simulated.json` | SEL-751 in the simulated slice: Telnet labelled plaintext with an acknowledgement, FID corroborated by the operator record and a simulator session, binding `device-reported` and `spoofable`. |
| `valid/sel-751-identity-mismatch.json` | The simulator reported a different FID: the attribute is `conflicting`, keeps the declared value, and the asset is suspended for `identity-mismatch`. |
| `valid/site-node.json` | The site platform node as a `server` asset carrying A5's posture labels: OS out of support with its standing condition and migration date, and storage durability unverified. |
| `valid/sel-rtac-syslog.json` | An RTAC heard only through Syslog over UDP: plaintext, acknowledged, bound by address only. |
| `valid/later-minor.json` | A 0.3 record with a device class and a field 0.1 does not know: a 0.1 reader accepts it and reads the class as `unknown`. |
| `valid/profile-sel-751-ascii.json` | SEL-751 capability profile: identification and SER `simulated`, time quality `documented-untested`, Syslog `unsupported`, configuration `unknown`. |
| `valid/profile-sel-rtac-syslog.json` | RTAC profile: Syslog push only, no adapter operations, so no firmware allowlist. |

## Invalid

| File | What it shows |
| --- | --- |
| `invalid/observation-without-evidence-class.json` | An observation with no evidence class is rejected. |
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
| `invalid/asset-id-from-device-content.json` | An asset ID derived from the FID instead of an assigned UUID. |
| `invalid/profile-adapter-without-allowlist.json` | A profile that sends adapter operations with no firmware allowlist (AP-27). |
| `invalid/profile-claim-without-citation.json` | A capability claim with no citation. |
