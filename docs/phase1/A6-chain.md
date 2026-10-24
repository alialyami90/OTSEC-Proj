# Phase 1 chain test: A6 result

- **Test:** `TestChain` in `tests/contract/` (`chain_test.go`, `chain_links_test.go`, `chain_session_test.go`).
- **Run by:** A6, 2026-10-24, on `main` after C2 merged (`99a34aa`). CI runs it on Linux and Windows with `go test ./...`. The CI run is recorded in the Phase 1 exit report.
- **Evidence class:** `simulated`. The session is A6's synthetic transcript, made from A6's transcription of the SEL-751 manual (Figures 7.38 and 10.16). No device and no real collector were involved.

## What runs

All nine links run, and none is skipped:

C3 lookup → C7 IPC request → C2 invocation → C2 result → C1 identity → C4 events → C5 commit → C6 rendering → C8 audit.

Each link is checked against the hand-written ground truth (`gtID`, `gtSER`), never against the output of the link before it.

| Link | Checked |
| --- | --- |
| C2 invocation | Strict decode, the register lookup and `CheckAgainst`: the asset, endpoint and profile, the declared identity, the credential gate and limits within the profile. It is the run the C7 request authorizes. |
| C2 result | It passes `DecodeResult` (`Validate`) and `CheckLines` against the register. The transcript bytes survive JSON. Every `gtID` line other than the FID line is in the received bytes, and the 8 record spans are exactly the 8 `gtSER` rows, in device order. |
| C4 events | 8 pending events in device order, using `Align` (first read). For each: row, element, state and native time match `gtSER`, with millisecond resolution, offset unknown, and `evidence_class` simulated. |
| C5 | An A6 Committer behind `store.NewLog`. The 8 events get receipts with seqs 1 to 8 and no gap. Every stored event decodes and validates with its full ID. |
| C6 | Each stored event renders to a message that passes `CheckMessage`. Each message carries `eid`, `pos`, `inv`, `op`, `evc`, `dt`, `subj` and `val` as in the event and the ground truth, and its device text holds the row. |
| C8 | The session's records (chain start, request, session open, credential use, operation, close) are sealed by `SealAudit` in the Committer. They pass `VerifyChain` against the head and `VerifyCollectorSeq`. The four invocation records name the principal, operation and asset, and carry no marker, FID, row text or password. C8 time is C4's `Received` type. |

A4's C4 example for row 8 and A6's event have the same `record_sha256` and `alignment_key`. The two were built independently from the same manual row.

## Substitution

Both figures print a FID that the register denies: Figure 7.38 has R301 and Figure 10.16 has R100. The collector would never send `ACC` to either. The session therefore uses `allowedFID` (R501) in the `ID` reply, with its line checksum recomputed, and in the SER header. Every other byte is the transcription's.

## Findings for owners (not blocking the exit gate)

1. **C2 and C8 disagree on the transcript hash.** Closed by D1-25 (#64, #68). C8 `device.session.close` now carries `transcript_sha256`, and C2 `doc.go` cites it. The C8 link checks the field against A6's own SHA-256 of the stored transcript, and checks that a replaced digest breaks `VerifyChain`.
2. **Field names differ between C2 and C4.** Closed by D1-25 (#68). C2 `RecordFields` uses the printed headings `#`, `DATE`, `TIME`, `ELEMENT` and `STATE`. The C4 link checks every event's `native.fields` names against `gtSERColumns`, and `TestGroundTruthSER` ties that to A6's transcription.
3. **C4 native time is not byte-exact in A4's examples.** Closed by D1-25. C4 `DeviceTime.Native` is the printed DATE and TIME joined by one space, and the row's own spacing stays in the native record bytes. The chain's C4 link now checks exactly that.
4. **D1-24.** Done, now that #65 is merged. The chain endpoint has `Target: asset.Simulated`. The C2 result link runs `Result.CheckAgainst`, and the same result claiming `device-observed` is refused.
