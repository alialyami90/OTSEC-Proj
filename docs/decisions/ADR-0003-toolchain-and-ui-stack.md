# ADR-0003: Toolchain and UI stack

- Status: proposed (A1, 2026-10-23; to be accepted at the Phase 0 exit gate)
- Date: 2026-10-23
- Deciders: A1, with A5 (proposer); UI stack delegated to this decision by the owner in `PRODUCT.md`
- Related: P8, P9, R5.5, R5.6, R8.5, R8.7; `docs/phase0/A5-platform-feasibility.md` §3; A6 B-06; ADR-0002

## Context

No language or toolchain exists. Every Phase 2 implementation task is blocked on this choice. Criteria: deployable on site hardware without a runtime to manage; Telnet, SSH, and serial clients with prompt handling; parser fuzzing for hostile device input (A6 C-08); memory safety; maintained TLS and X.509; small supply chain; supportable by a rotating team.

## Options considered

Go, Rust, Python, Java, TypeScript/Node (A5 §3 table). UI: plain server-rendered HTML, React with Vite, SvelteKit.

## Evidence

- E-A5-5 (`simulated`): the experiment binary including the pure-Go SQLite driver cross-builds with `CGO_ENABLED=0` for linux/amd64, linux/arm64, linux/arm, windows/amd64, about 7 MiB each, 26 modules. A1 rebuilt it on 2026-10-23 without error.
- A2 §12: the primary family (SEL ASCII) needs a Telnet/serial line client and nothing vendor-specific; a pure-Go MMS client exists for the contrast family but needs a read-only facade (A2 D14).
- A3: Go is acceptable from a security standpoint (`x/crypto/ssh`, memory safety).
- Library claims (scrapligo, go.bug.st/serial, modernc.org/sqlite) are `[doc]`, not exercised against devices.

## Decision

- **Runtime language: Go**, toolchain pinned in `go.mod` (`go` and `toolchain` directives; currently 1.26, required by `modernc.org/sqlite`). Release builds use a pre-installed pinned toolchain, not an automatic download.
- **Build:** `CGO_ENABLED=0 go build -trimpath`; linux/amd64 and linux/arm64 targets; windows only if the owner confirms Windows site hosts.
- **Test:** `go test ./...` with `-race` in CI; golden-file parser tests from fixtures with `SOURCE.md`; `go test -fuzz` targets for every parser of device output.
- **Lint and supply chain:** `gofmt` enforced, `go vet`, `staticcheck`, `govulncheck`; every new third-party module is justified in a PR description and listed in the next ADR touching dependencies.
- **Verification tooling** (A6, `tests/`): Python 3 with pinned dependencies is permitted and is never shipped (B-06 ruling). Oracle independence rests on the no-import rule.
- **UI:** server-rendered HTML from the binary (`html/template`, embedded assets, no CDN, vanilla JS only where unavoidable, strict CSP with no inline script). No Node toolchain. The first surface still goes through the impeccable new-work flow, which writes `DESIGN.md`; `PRODUCT.md` "Stack" is updated through `/impeccable init` by A5 after acceptance.
- The commands to record in `CLAUDE.md` "Repository state" are set by A5 when the first module skeleton lands.

## Consequences

- One static artifact per target; no interpreter or native wheel tree on site nodes.
- Telnet support has no mature standalone Go library; a small RFC 854 client or the scrapligo transport must be written or vetted and tested against A6's Telnet simulator.
- A device path that only a Python or C library can serve would run as a separate collector process behind the same adapter contract (ADR-0002), not change the runtime language.

## Open objections

None.
