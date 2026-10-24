# A4: SER normalizer (P2-A4, part 1)

- **Package:** `modules/telemetry/normalize`. The rules are in its package doc (`doc.go`); this note covers the seams with A2 and A5 and what was tested.
- **Evidence class of everything here:** `simulated` or `desk`. No device was contacted. The C4 goldens and Figure 10.16 are `documented-example`. Every other row in the tests is constructed test data, labelled as such in the test helpers.

## What it does

`Normalize(result, invocation, asset, input)` takes one C2 result of `sel.ser.read_all` and returns:

- pending C4 events (seq 0) for the rows that are new since the previous read, oldest first;
- platform health events about the read (`ser.gap`, `ser.alignment-ambiguous`, `parse.failed`);
- the capture (the C2 transcript as stored) that every event points into;
- the alignment state to keep for the next read.

`Output.Records` turns that into C5 records:

- the SER events go on the asset's stream, class `adapter-evidence`, each with the capture, and the last with the state as its `SourceCursor`;
- the health events go on the health stream, class `platform`.

## Seams

| With | What | State |
| --- | --- | --- |
| A2 (C2 producer) | `Normalize` runs C2 `Validate` and `CheckAgainst` itself and refuses a result that fails either. `evidence_class` is copied from `Result.target` only after that. | Built on C2 as merged. |
| A2 (C2 examples) | **Row order.** Figure 10.16 prints the oldest row first, with the highest number, and row 1 (the newest) last. A6's ground truth says the same (`tests/contract/groundtruth_test.go`). The C2 examples `ok.json`, `ok-with-echo.json` and `partial.parse_errors.json` print row 1 first. The normalizer requires row numbers to run n, ..., 2, 1 in transcript order. A read in the examples' order is kept as bytes and not aligned, because reading it the other way would store the newest row first. `TestNewestFirstReadIsNotAligned` pins the rule; `TestC2SERExamples` holds before and after the examples are reordered. The tests use the same read with the rows in the figure's order (`figureOrder`). | **Fix ready, A2** (9b64b98, opens as its own PR after #75). My C2 review (change 2) only asked for the times to be swapped, so this one is partly mine. |
| A2 (adapter parser) | The field values must appear in the row's bytes in order, separated by spaces only, with nothing but spaces after STATE. A row that fails this becomes an event with its native bytes and `parse_status: failed`, plus a `parse.failed` count. | Built. |
| A5 (scheduler) | Inputs from the node: node ID, the SER and health streams, the node clock's resolution and sync state at `ended_at`, and the previous state (`DecodeState` of the last `SourceCursor`). DATE_F and the UTC offset are optional; without them MDY is assumed and flagged, and no UTC is stated. | Built. |
| A5 (C5) | **State with no events.** An empty read after rows changes the state but adds no SER event: this is the one gap at a clear (D1-7). `Output.StateChanged` is true, but there is no SER record to carry the `SourceCursor`. If the state is not kept, the next read raises a second gap. `TestClearRaisesOneGap` shows the need. | **Resolved with A5 (2026-10-24), no C5 change.** The scheduler commits the health records first, then saves the state with a store-only `SaveSourceCursor` (A5, #77). A crash between the two leaves the old state, so the gap is raised a second time: a duplicate alarm, never a lost one. |
| A5 (C5) | A read that is not aligned (D1-12) has no SER events, so its capture goes on the first health record. | Built. A5 confirmed the store keeps a capture while any retained record in the same database refers to it, whatever its class. |

## Tests (container, Linux, go1.26.0)

| Test | Shows |
| --- | --- |
| `TestFig1016MatchesC4Goldens` | The 8 rows of Figure 10.16 produce the 8 C4 goldens byte for byte (after seq is assigned), oldest first, 1:1. |
| `TestKnownOffsetMatchesC4Golden`, `TestConstructedGoldenDeviceTimes` | DATE_F and offset known; invalid date; leap second. |
| `TestNormalizeC2Read` | A C2 read end to end: fields as printed, `received.utc` from `ReceivedAt`, evidence = transcript, `evc` simulated, C5 records valid, state on the last record. |
| `TestOverlapEmitsNoDuplicate` | 0, 50 and 100 percent overlap: no duplicate; 0 percent reports one gap. |
| `TestSlidingPolls`, `TestClearRaisesOneGap`, `TestAmbiguousOverlapKeepsRows`, `TestRemovedRowIsAGap` | Many polls, D1-7, D1-14, removed rows. |
| `TestReadRowsExceeded`, `TestFailedAndRefusedProduceNothing`, `TestFailedWithRecordsIsNotAligned` | D1-12; every failed and refused C2 example. |
| `TestRefusesResult`, `TestRefusesInput` | Fail closed: a simulator reported as a device, a changed byte, another invocation or endpoint, bad inputs. |
| `FuzzSERRow`, `FuzzDecodeState` | 60 s each, no panic and no invalid event. |
