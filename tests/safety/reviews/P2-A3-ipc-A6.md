# A6 review of #79 (C7 IPC: collectorwire, collector server, collectorclient) at `12396c6`

Reviewer: A6 (P2-A3 independent security review). Evidence class: **simulated and desk**. Everything ran in the Linux container with Go 1.26.0. The Windows transport has been cross-built only (`GOOS=windows go vet` and `go test -c`). Its native run is owed under D2-8 and is the boundary that matters in production.

## What I ran

- `go vet ./...`, `gofmt -l .` (empty) and `go test -race -count=1 ./modules/security/... ./contracts/... ./tests/contract/`: all ok.
- On this branch, which includes #74, the D2-1 import test passes. `collectorclient` imports `collectorwire` and contracts, never `collector`.
- I read `frame.go`, `outcome.go`, `endpoint.go`, `transport_linux.go`, `server.go` and `client.go`, and skimmed `transport_windows.go`. I also ran a probe of my own on `DecodeStrict` and `DecodeReply`.

What holds: the request is decoded with C7's own strict decoder before `Handle`, and every refusal goes through `Refuse`. A run starts only after the reply write returned. Handler contract breaches drop the connection. The client checks the reply's contract, request ID, status and refusal consistency, and checks the outcome with C2's `DecodeResult`, C8's `ValidatePending`, rising `collector_seq`, `correlation_id`, one paired session, and `transcript_sha256` equal to the result's digest. That last check is the link the slice suite's transcript test relies on.

## Should

**1. `DecodeStrict` lets a duplicate key through when one spelling folds to the other under Unicode case folding, and accepts keys that are not the exact field name.** `checkDuplicateKeys` compares `strings.ToLower` of each key. `encoding/json` matches field names with Unicode simple folding (`bytes.EqualFold`), under which `ſ` (U+017F) equals `s`. Probe results:

| Input to `DecodeReply` | Result |
| --- | --- |
| `..."status":"refused","ſtatus":"accepted"}` | **`status="accepted"`, no error** |
| `..."STATUS":"refused"...` | accepted, read as `status` |
| `..."status":"refused","status":"accepted"}` | refused: duplicate key |
| `..."invocation_id":"a",...,"Invocation_ID":"b"}` | refused: duplicate key |

So a reply that C7's strict decoder (`contracts/internal/strictjson`, which refuses `"ID"` as not a field name) would refuse is read here as accepted, which is exactly the writer and reader disagreement the comment says it prevents. The peer is the identity-checked collector, and the C2 result and C8 records inside the outcome go through the contracts' own decoders, so this is not an escalation. But the doc claims D1-10 strictness, and the envelope and reply don't meet it. The fix is to refuse any key that is not exactly a field name of the target, which also closes the folding twin. Better still, take the C7 0.2 `DecodeReply` you already list, built on the contracts' decoder, and use the same decoder for `RunOutcome`.

## Nits

**2. "The run starts only after the reply is delivered."** The run starts after `WriteFrame` returns, which means the kernel (or the pipe) has the bytes, not that the node has read them. If the node dies in between, the device session runs with no node-side record, and the only trace is the `collector_seq` gap, as your residual paragraph says. Please say "written" rather than "delivered" so nobody reads it as an acknowledgement.

**3. `linger` after an oversize refusal.** The server refuses an oversize frame without reading its body, then `linger` reads one byte and returns. In the oversize case, that byte is the client's own unread body, not its end of stream. So the server closes while the client may still be writing, which on Windows is the case the linger exists for: a pipe server that closes first may discard the reply. A conforming client never sends an oversize frame (`WriteFrame` and `Do` refuse it), so this only affects a broken client. It would show up as a numbered refusal the node never received, which looks like an audit omission. Either draining to EOF with a bound or skipping the linger there would fix it. Please add an oversize case to the PC run.

**4. Socket mode between bind and chmod.** `ListenUnix` creates the socket with the process umask, and the 0660 `chmod` follows. In between, the mode is whatever the umask allows. The `SO_PEERCRED` check is the real gate and the directory mode blocks replacement, so this is cosmetic. Creating it under `syscall.Umask(0o117)` would remove the window.

## For the PC run (owed)

Include `collectorwire/transport_test.go`, `transport_windows_test.go` and an oversize request (nit 3). Also check the open item you name: whether one service's token grants another service `TOKEN_QUERY`.

## Verdict

Accept, with should 1 asked for in this PR if it's cheap (an exact-name check), or recorded as a C7 0.2 item with A1 if not. The nits can ride along.
