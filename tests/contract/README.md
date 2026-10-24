# Independent contract tests (A6)

Owner: A6. Brief: P1-A6 in [docs/agent-handoffs.md](../../docs/agent-handoffs.md).

These tests import the contract packages under `contracts/` but none of their owners' test helpers or golden files. Expected values come from A6's own transcription, not from a contract's `testdata/`.

| File | What it does | Ground truth |
| --- | --- | --- |
| `groundtruth_test.go` | Hand-written expected values for the SEL-751 `ID` (Figure 7.38) and `SER 8` (Figure 10.16) examples. Its tests check them against A6's transcription in [tests/safety/recording_simulator/documented/sel-751/](../safety/recording_simulator/documented/sel-751/SOURCE.md), including the ID line checksums and the 6 bad checksums in Figure 3.20. | GT-HAND from GT-EX |
| `chain_test.go` | The Phase 1 chain: C3 lookup, C7 IPC request, C2 invocation, C2 result with transcript, C1 identity check, C4 events, C5 commit and acknowledgement, C6 rendering, C8 audit. Since C2 merged, every link runs; a skip would be "not built", never a pass. | GT-HAND |
| `chain_links_test.go` | The links of the chain for merged contracts: C3 lookup (operations, session lines, the firmware gate on both documented FIDs and one allowed FID), C7 request (strict decode, register check, access level, unknown field and raw secret refused), C1 identity (a record built from Figure 7.38 with spans into A6's transcription, the credential gate, and an address-only asset refused a credential). | GT-HAND; same-source (manual) for the SEL-751 register and profile |
| `chain_session_test.go` | The C2 to C8 links. One simulated `ID` plus `SER` session, built by A6 from Figures 7.38 and 10.16, with the FID replaced by an allowed one (both figures print FIDs the register denies). The links run it through the C2 invocation and result (`Validate`, `CheckLines`), 8 C4 events, an A6 Committer behind a C5 `Log`, C6 `Render`, and a sealed C8 chain. Each link is checked against `gtID` and `gtSER`, not against the link before it. | GT-HAND; same-source (manual); the FID substitution is A6's, stated in the file |
| `c2_test.go` | C2: the probes from the C2 review. Each negative case validated at an earlier PR head and must stay refused: lines before a prompt, the credential slot (C-17), sends after the password (C-19), no probe or identity check before `ACC`, `QUI` after an unanswered `ACC` or a rejected probe, `access_level` and `quit_sent` against the bytes, `CheckLines` against the SEL-751 register, and a level-0 operation with a credential. Safe-path controls must still validate. | GT-HAND from contract prose and the manual pages it cites |
| `c8_d125_test.go`, `c2_d125_test.go` | D1-25. C8: `transcript_sha256` is required on `device.session.close` and refused on every other action; a wrong form, a mis-cased or duplicate key, and any other `transcript*` key are refused at 0.1 and at 0.2; a replaced digest breaks the chain. C2: `RecordFields` equals the Figure 10.16 heading, and each single rename, swap, missing field or extra field is refused for the field names. | GT-HAND from D1-25; same-source (manual) for the heading |
| `c4c6_evidence_class_test.go` | D1-23: `source.evidence_class` refused when it is missing, mis-cased, duplicated, set to another C1 class or put on a platform event; a later minor's value reads as simulated; `evc` is rendered once, cannot be injected through device text, and survives the size step and an insecure target. | GT-HAND from D1-23; A4's examples used as inputs only |
| `c5_test.go`, `c6_test.go` | C5: A1 D1-11 with A6's own Committer: with the audit store full, or after a commit of unknown durability, the act (`ACC`) never runs, and received Syslog still commits while the audit class is at quota. C6: A1 D1-15: audit over UDP, on a best-effort target, without a durable-ack check or without mutual TLS is refused. | GT-HAND from contract prose and A1 decisions; independent of A5's and A4's testdata |
| `c7_test.go`, `c8_test.go` | C7: request decode negatives, access-level refusals, every SEL-751 command word refused as a secret prefix, the failed-auth floor across a crash (D1-20, contract half). C8: tamper table on an A6-sealed chain, node binding, 0.1 strictness. | GT-HAND from contract prose; independent of the owners' testdata |
| `<contract>_test.go` (one per contract, as each lands) | Positive and negative cases written by A6, at least one negative case per contract that its owner did not write. | marked per test |

## Independence

Every test states its ground truth. A test is marked **independent** only when its expected value does not come from the same source the contract was written from. In Phase 1, almost every SEL expectation comes from the same SEL-751 manual that A2 used. Those tests are marked **same-source (manual)**: they catch transcription and logic errors, not errors in the manual itself (risk 3). Expectations that come from outside the manual are marked **independent**, for example a checksum rule from AG95-04, an RFC grammar, or a property such as "a skipped link is not a pass".

None of these fixtures is device output. Results support `simulated` claims only.

## Run

```
go test ./tests/contract/ -v
```

CI runs it on Linux and Windows with the rest of `go test ./...`.
