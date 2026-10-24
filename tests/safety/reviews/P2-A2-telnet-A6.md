# P2-1 (`modules/ied/telnet`, `sel751` seam): A6 review

- **Reviewed:** PR #75 at `5ef2df0`, A2.
- **Reviewer:** A6, 2026-10-24.
- **Method:**
  - A6 wrote external probes (`package telnet_test`) against the exported API, with a scripted `net.Conn`.
  - With #74 applied, the D2-1 import test sees both new packages and finds no violation.
  - Where it ran: Linux container, Go 1.24.7. The Windows leg waits for Go on the owner's PC.
- **Evidence class:** `desk`.

## Outcome: changes requested (must 1)

| Probe | Result |
| --- | --- |
| `Send("ID\r\nSER C\r\n")` with an egress check that reads only the first line | **written to the socket**: two lines in one `Send` |
| `Send("ID")` without a terminator | written |
| `IAC SB 24 'x' IAC WILL 1 'A'` | data is `"\x01A"`: the option byte leaks into the NVT data, and `WILL 1` is not refused |
| An egress check that rewrites the line in place | the rewritten bytes are sent |
| `MaxReceived` 5: 5 bytes then EOF / 6 bytes | `EOF` / `ErrTooLarge` after the 5 bytes are returned |
| 100 distinct `WILL`s with `MaxCommands` 64 | 64 refusals (192 bytes), then `ErrNegotiation` |
| CR NUL, bare CR, trailing IAC at EOF | kept verbatim / kept / dropped with `EOF` |

## Must

**1. `Send` must send exactly one line.** Today the transport allows CR and LF anywhere in the argument, so the line framing depends entirely on the caller's `Egress`. `register.Matcher.Permit` takes a line without its terminator, and refuses CR and LF inside it. But nothing makes the adapter strip exactly one terminator before calling `Permit`. A wrapper that checks only up to the first CR LF lets a second, unchecked line out in the same write. The brief asks for a test showing that no line outside the register can reach the socket, and the transport is where that can be made structural.

Change: `Send` refuses CR and LF everywhere except a single final terminator, and requires that terminator: CR LF, or the one the adapter is configured with. `Egress` then gets the line without its terminator, as `Permit` expects. A test should cover two lines in one `Send`, a missing terminator, and a bare CR inside the line.

## Should

**2. End a subnegotiation cleanly on `IAC <verb>`.** In `stSBIAC`, any byte other than SE or IAC sets `stData` and drops the command byte. The option byte that follows then becomes NVT data, which corrupts the evidence stream, and the option goes unrefused. Change: treat it as if the IAC had arrived in `stData`, so `x` goes through the `stIAC` handling.

**3. Copy the line before `Egress` (nit).** The doc says "the bytes the egress check saw are the bytes on the socket". A check that writes to its argument breaks that. Copying first costs one allocation per line.

## On the C2 gap A2 raised

A6 recommends no C2 change for Phase 2. The refusal bytes are transport negotiation, not dialogue, and on the far side the simulator records every IAC sequence the collector sends (`--telnet`). A6's V-S7 check in the slice suite will assert that every sequence the collector sent is `IAC WONT x` or `IAC DONT x`, answering a `DO x` or `WILL x` the simulator sent first. If A1 wants the negotiation in the stored evidence later, a C2 minor could carry `Stats` (commands and refusals) in the result.

## Seam (`sel751/seam.go`)

No findings. `BeforeACC` returns only once the state is durable. `Confirmed` is called only on `=>`, and never on `=>>`. Both follow D1-20 as amended. One question for A2 and A3: the password line goes out through `Send`, so `Egress` sees it. The register does not list it, so `Permit` alone would refuse it. Say in the seam how the credential slot line passes the egress check, for example that `Egress` accepts exactly one slot line when the dialogue state is "after `Password: ?`". The slice test will then check that a second slot line is refused.
