# C8 golden examples

None of these is device-derived. Device values are invented and labelled as such.

| File | What it shows |
| --- | --- |
| `chain/slice-session.jsonl` | Six chained records from one node: the chain start, an accepted collector request, a session open, a serial-number mismatch refusal (C1-A3-5), the credential suspended as exposed, and the session close. `TestGoldenRecords` verifies the chain. The close record's `transcript_sha256` is a placeholder (`cdcd…`), not the hash of any stored transcript: this chain has no C2 result behind it. A6's chain test checks a real digest end to end (D1-25). |
| `valid/device-refused-identity-mismatch.json` | The refusal record from that chain on its own. |
| `invalid/password-field.json` | A `password` field anywhere in a record is rejected. |
| `invalid/plaintext-labelled-encrypted.json` | A Telnet target labelled `encrypted-authenticated`. The plaintext label must stay visible. |
| `invalid/denied-without-reason.json` | A denied outcome with no reason code. |
| `invalid/device-action-without-target.json` | A device action that does not name the asset, transport and label. |
| `invalid/seq-one-without-genesis.json` | Seq 1 that is not the genesis `audit.chain.start` record. |

## 0.4: admin-signed requests

The admin group in these uses the C7 test admin key's ID (`ed25519-183d5080d1a2ef2b`, from the seed "otsec test admin key 1"), a fixed test nonce, and the SHA-256 of the text "otsec test admin payload". No real key or signed request is behind them.

| File | What it shows |
| --- | --- |
| `valid/collector-request-admin-claimed.json` | The node's info record before it sends: `claimed`, unchecked. |
| `valid/collector-request-admin-verified.json` | The accepted reply's record: `verified`, the collector's `CollectorReply.Admin`. |
| `valid/collector-request-admin-repeat.json` | A repeat answer: its own `collector_seq` 15 and `repeat_of` 9. |
| `invalid/claimed-stamped-0.3.json`, `invalid/repeat-stamped-0.3.json` | The fields on a record stamped 0.3. |
| `invalid/claimed-on-allowed.json` | `claimed` belongs on the info record only. |
| `invalid/verified-on-denied.json` | `verified` belongs on an accepted reply only. |
| `invalid/verified-on-another-action.json` | The fields belong on `collector.request` only. |
| `invalid/repeat-without-verified.json` | A repeat names what was verified. |
| `invalid/repeat-of-a-later-decision.json` | `repeat_of` must be below the record's own `collector_seq`. The schema cannot compare two fields, so this one passes the schema and fails `Validate`. |
| `invalid/claimed-with-payload.json` | The group is closed: no payload, signature or secret rides along. |
