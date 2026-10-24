# Independent contract tests (A6)

Owner: A6. Brief: P1-A6 in [docs/agent-handoffs.md](../../docs/agent-handoffs.md).

These tests import the contract packages under `contracts/` but none of their owners' test helpers or golden files. Expected values come from A6's own transcription, not from a contract's `testdata/`.

| File | What it does | Ground truth |
| --- | --- | --- |
| `groundtruth_test.go` | Hand-written expected values for the SEL-751 `ID` (Figure 7.38) and `SER 8` (Figure 10.16) examples. Its tests check them against A6's transcription in [tests/safety/recording_simulator/documented/sel-751/](../safety/recording_simulator/documented/sel-751/SOURCE.md), including the ID line checksums and the 6 bad checksums in Figure 3.20. | GT-HAND from GT-EX |
| `chain_test.go` | The Phase 1 chain: C3 lookup, C7 IPC request, C2 invocation, C2 result with transcript, C1 identity check, C4 events, C5 commit and acknowledgement, C6 rendering, C8 audit. Each link skips until its contract merges. | GT-HAND |
| `<contract>_test.go` (one per contract, as each lands) | Positive and negative cases written by A6, at least one negative case per contract that its owner did not write. | marked per test |

## Independence

Every test states its ground truth. A test is marked **independent** only when its expected value does not come from the same source the contract was written from. In Phase 1, almost every SEL expectation comes from the same SEL-751 manual that A2 used. Those tests are marked **same-source (manual)**: they catch transcription and logic errors, not errors in the manual itself (risk 3). Expectations that come from outside the manual are marked **independent**, for example a checksum rule from AG95-04, an RFC grammar, or a property such as "a skipped link is not a pass".

None of these fixtures is device output. Results support `simulated` claims only.

## Run

```
go test ./tests/contract/ -v
```

CI runs it on Linux and Windows with the rest of `go test ./...`.
