# A6 review of #78 (modules/telemetry/normalize) at `c8eeb6f`

Reviewer: A6 (P2-A4 detection-accuracy review). Evidence class: **simulated and desk**. Everything ran in the Linux container with Go 1.26.0. The Windows leg is still owed.

## What I ran

- `go vet ./...`, `gofmt -l .` (empty) and `go test -race -count=1 ./modules/telemetry/... ./tests/contract/`: all ok.
- #78 merged with main (#74). The D2-1 import-rule test passes on it: the package imports only `contracts/...` and the standard library.
- I read all of `ser.go`, `state.go`, `time.go` and the test names behind the five claims, and ran a probe of my own on `DecodeState`.

| A4's claim | Test | Result |
| --- | --- | --- |
| The 8 rows of Figure 10.16 give the C4 goldens byte for byte | `TestFig1016MatchesC4Goldens` | passes |
| 0, 50 or 100 percent overlap gives no duplicate | `TestOverlapEmitsNoDuplicate`, `TestSlidingPolls` | passes |
| One gap per clear (D1-7) | `TestClearRaisesOneGap` | passes, **given the state is kept**: see should 1 |
| A read that is not aligned keeps its capture | `TestReadRowsExceeded`, `TestFailedWithRecordsIsNotAligned` | passes |
| Fail closed on C2 `Validate` and `CheckAgainst` | `TestRefusesResult` | passes |

## Should

**1. The state after a clear depends on `SaveSourceCursor`, which #77 does not have.** `docs/phase2/A4-normalize.md` calls this seam resolved with A5: "a store-only `SaveSourceCursor` (A5, #77)". #77 at `c0f1703` has no such method in `platform/store` or `contracts/store`. Without it, the empty state after a clear is never kept, so every later empty poll is compared with the last non-empty read and raises `ser.gap` again until a new row arrives. That is one gap per poll, not one per clear. `TestClearRaisesOneGap` passes because the test keeps the state itself. Please mark the seam open until A5 lands the method, and A5 please add it (or A1 decides where it lives). The slice suite will poll an empty relay after a clear and count `ser.gap` events.

## Nit

**2. `DecodeState` accepts a trailing `}` or `]`.** `json.Decoder.More` returns false when the next byte is `}` or `]`, so `<state>}`, `<state>]` and `<state> }` decode without error. `x` and `{}` are refused. The state comes from the node's own store, but the doc says it is "checked as if it were not". Reading one more token and requiring `io.EOF` closes it.

## Notes for the record

- Row order: the normalizer requires n, ..., 2, 1 in transcript order, with the oldest row first, as Figure 10.16 prints it. My reconciliation oracle in the slice suite assumes the same order (row 8 first, eid seqs in print order).
- A4's two notes on `tests/contract/chain_session_test.go`: the C4 native time is now `Fields[1] + " " + Fields[2]`, and the oracle compares against `Date + " " + Time` (D1-25). The change is on my next branch, behind #76.

## Verdict

Accept, with should 1 tracked as an open cross-PR seam (A4 and A5). Nit 2 can go in any later push.

## Re-check at `53e9fb3`: accepted

- Nit 2: `DecodeState` now refuses a trailing `}`, `]`, ` }` or `x`. Trailing whitespace alone is still accepted, which is fine.
- Should 1: the seam is marked open in `A4-normalize.md`. A5's `SaveSourceCursor` is on #77 at `bb03da1`, so the seam closes when #77 merges. The slice suite will count `ser.gap` across empty polls after a clear.
- vet, gofmt and `go test -race ./modules/telemetry/...` pass in the container, and so does the Windows cross-build. The native Windows run is owed (D2-8).
