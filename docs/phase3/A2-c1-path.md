# C1 0.2: endpoint path (A2, Task P3-A2)

**Status:** proposed in the C1 0.2 PR. A1 approves the contract; A3, A5 and A6 review their fixtures.

## What changed

`otsec.asset/0.2` adds one optional field, `Endpoint.path`, with two values:

- `direct`: the node's connection ends at the device itself.
- `port-server`: the connection ends at a port server (a terminal or serial server), which keeps its own session state and timeouts in front of the device.

An administrator sets the path. It is never taken from what the far end reports. It is not set on a Syslog endpoint, because the node never connects to one.

`Endpoint.CheckPath` is the rule, and it runs before connecting. Only `direct` gets a session. Everything else is refused with its own reason, and every reason wraps `asset.ErrPathRefused`:

| Endpoint | CheckPath |
| --- | --- |
| `path: direct` | allowed |
| no path (every 0.1 record) | "endpoint ... has no path; an administrator must set it" |
| `path: port-server` | "is behind a port server, refused until its timeouts have evidence (H-13)" |
| a path this reader does not know (raw struct) | "path ... is not one this reader knows" |
| a Syslog endpoint | "the node only listens on" it |
| a transport this reader does not know, even with `path: direct` | "transport ... is not one this reader knows" (A6 on #149) |

This is A1's ruling (a), strict: D2-16 says "refused like a port server once the field exists", with no carve-out for simulated targets.

## Reading older and newer records

- **A 0.1 record is still read.** It decodes and validates as before, and its endpoints have no path, so `CheckPath` refuses them explicitly instead of failing to parse. A 0.1 record that carries `path` is invalid, because 0.1 has no such field.
- **A later minor's path** that 0.2 does not know reads as `port-server` (`FallbackPath`) in `Asset.Effective`, so it never gets a session.
- **Within 0.2**, an unknown path value is invalid, and so is a path on a Syslog endpoint.
- Capability profiles are unchanged and may stay at `otsec.asset/0.1`.

## Who enforces it

This PR adds the field, the rule and the fixtures. Nothing calls `CheckPath` yet, so no run changes behaviour from this PR alone. The refusal is wired in two places, in later PRs:

- **C2 0.5 (A2):** a before-connect refusal code that suspends nothing, so the path refusal is a C2 result and not a transport failure.
- **The adapter's own check (A2) and the collector (A3):** both call `CheckPath` before dialing, defence in depth. A reported TIDLE shortens the failed-auth floor only on a direct path (P3-A2 acceptance), and that also reads `path`.

## Release note (for the Phase 3 release)

> After upgrading, a node's stored asset records written before C1 0.2 have no endpoint path. The collector refuses every adapter session to those endpoints ("endpoint has no path") until an administrator sets `path` on each one: `direct` if the node connects to the device itself, or `port-server` if a terminal or serial server sits between them. Port-server endpoints stay refused until port-server timeout behaviour has evidence (H-13). Collection from those assets stops until then. This is intended: the platform fails closed instead of guessing how a device is reached. Syslog reception is not affected.

## Fixtures updated (authorised by A1, each owner reviewing their file)

Each now carries `"path": "direct"` and `otsec.asset/0.2`:

- `modules/security/collector/testdata/sel-751-simulated.json` (A3): a copy of the C1 golden.
- `cmd/otsec-collector/testdata/sel-751-simulated.json` (A3): a copy of the C1 golden.
- `platform/node/nodeconfigtest/nodeconfigtest.go` (A5). `tests/integration/slice/slicehelper` builds its asset from it, so it needed no change of its own.
- `tests/safety/windows_installer/node.template.json` (A6).
- `tests/contract/chain_links_test.go` and `tests/contract/chain_session_test.go` (A6). `c8_d125_test.go` carries a C8 audit target with no C1 endpoint, so it is unchanged.

One file outside A1's list also changed. `tests/security/lockdown_test.go` (A6) copies the telnet endpoint to make a Syslog one, so it now drops `path` from the copy. Without that, 0.2 refuses the Syslog endpoint for carrying a path. If A6 prefers, the alternative is to accept and ignore a path on a Syslog endpoint.

Not changed, because nothing enforces the path yet: Go tests that build `asset.Endpoint` values directly (`modules/security/collector/credstore_test.go`, `pipeline_test.go`), and the 0.1 example in `platform/node/README.md`. They need `Path: asset.Direct` in the PR that wires the collector check.

## Evidence

Contract tests only: goldens written by `contracts/asset/testdata/generate.py`, with `TestCheckPath`, `TestLaterMinorReadsDown` and the invalid examples. No device or port server was involved, and the H-13 timeout question is still open.
