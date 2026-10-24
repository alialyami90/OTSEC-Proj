# C8 golden examples

None of these is device-derived. Device values are invented and labelled as such.

| File | What it shows |
| --- | --- |
| `chain/slice-session.jsonl` | Six chained records from one node: the chain start, an accepted collector request, a session open, a serial-number mismatch refusal (C1-A3-5), the credential suspended as exposed, and the session close. `TestGoldenRecords` verifies the chain. |
| `valid/device-refused-identity-mismatch.json` | The refusal record from that chain on its own. |
| `invalid/password-field.json` | A `password` field anywhere in a record is rejected. |
| `invalid/plaintext-labelled-encrypted.json` | A Telnet target labelled `encrypted-authenticated`. The plaintext label must stay visible. |
| `invalid/denied-without-reason.json` | A denied outcome with no reason code. |
| `invalid/device-action-without-target.json` | A device action that does not name the asset, transport and label. |
| `invalid/seq-one-without-genesis.json` | Seq 1 that is not the genesis `audit.chain.start` record. |
