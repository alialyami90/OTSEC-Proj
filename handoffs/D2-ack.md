# D2 acknowledgement: OT/IED Integration Engineer (2026-11-06)

D2 read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) (C-team to D-team), then [D2-handoff.md](D2-handoff.md), then the files they link to for this role: D4-49 to D4-58 in [B1-decisions.md](../docs/phase4/B1-decisions.md), the item 3 exit report [phase-4-item3-exit.md](../docs/phase-4-item3-exit.md) ("Next coordinated tasks"), and [C2-ack.md](C2-ack.md) for the role's standing scope.

## What D2 checked (2026-11-06, about 13:00Z)

No device and no network endpoint was contacted. Everything below is `desk` or `simulated`. Nothing is hardware-verified, and no SEL family is supported (B-01).

- `origin/main` is `a774a97` (#486, C1 to D1). Since the D2 handoff was written at `961221b`, `main` gained #479 (`a69c416`), #480 (`158a5d0`) and the checkpoint PRs #481 to #486. None of them touches role 2's code.
- Open PRs on the repository: none. Role 2 has no branch work, stash or patch in flight. This file is the only change on `claude/project-thread-nxpe76`.
- The handoff's open point on the RFC permission is closed: D4-58 on `main` records the owner's "Allow www.rfc-editor.org" (11:41Z) and the twelve texts. `sha256sum -c SHA256SUMS` in `reference/rfc/` gives `OK` for all twelve. That shows the copies are intact, not where they came from (D4-58 records that).
- In D2's container at `a774a97`, Go 1.27.3: `go vet ./modules/ied/... ./modules/asset/...` exit 0; `$(go env GOROOT)/bin/gofmt -l modules/ied modules/asset` prints nothing; `go test ./modules/ied/... ./modules/asset/...` exit 0, 4 packages `ok` (`sel751`, `snmpv3`, `telnet`, `asset`). The full `go test ./...`, pytest and Windows were not run here; the last CI result for this code is run [42174011840](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42174011840) on `961221b` (CI-Linux, CI-Windows).

## Scope as D2 understands it

**D2 owns:** SEL-first IED interoperability until the owner declares SEL coverage complete (ADR-0006); `modules/ied/` (`sel751`, `telnet`, `snmpv3`); `modules/asset/`; `tests/fixtures/ied/`; `docs/device-capabilities.md`; its own findings files under `docs/phase4/` (`C2-*.md` keep their names; new ones are `D2-*.md`).

**D2 drafts and D1 approves:** contracts C1 (`contracts/asset/`), C2 (`contracts/adapter/`, goldens only from the generators), C3 register content (`contracts/register/testdata/`) and C9 (`contracts/config/`). Each change needs the consumers' review and D6's contract tests.

**D2 reviews:** D3's and D4's work for IED compatibility and protocol reading, and D6's V-M1 PR for the SNMP reading.

**D2 does not touch:** `platform/`, `cmd/`, `modules/security`, `modules/access`, `modules/telemetry`, `modules/detection`, `modules/applicability`, `tests/integration|security|safety|contract`, `docs/verification.md`, `docs/threat-model.md`, `contracts/README.md`, the workflows, `go.mod`, `PRODUCT.md`.

**D2 never:** contacts a device or an SNMP endpoint, runs an H item or Q3, adds a write, `set`, Level 2 entry or new code without a brief, puts a non-test credential in the public repository, runs anything on the owner's PC while D4-12 holds, or messages another agent except through the coordinator (D4-58).

## First three actions

1. **NEXT ACTION: check `modules/ied/snmpv3` against the RFC texts** (D2-handoff task 1, P4-3-C2 deliverable 4). Read the texts in `reference/rfc/` and compare, with a section cited for each: RFC 3411 §5 (`SnmpEngineID`, `session.go`); RFC 3412 §6 (`msgGlobalData`, `msgFlags`, `msg.go`); RFC 3414 §2.6, §3.1, §3.2 and §4 (key localization, USM parameters, Report counters, discovery; `session.go`, `usm.go`); RFC 3826 §3.1.2.1 (IV and CFB, `usm.go`); RFC 7860 (24- and 48-octet digests, `usm.go`); RFC 3416 and RFC 3417 §8 (PDU tags, GetBulk fields, BER rules; `ber.go`, `msg.go`); RFC 3418 and RFC 6933 (OIDs, `identity.go`). The note goes in `docs/phase4/D2-snmpv3-rfc-check.md`. D2 does this from the texts alone and does not read D6's GT-MIB agent patch first, so the two readings stay independent. Acceptance: every layout the client encodes or decodes has a citation, and every divergence has a failing test first and then the fix, in a PR reviewed by D3 and D6. If the check finds no divergence, the note alone goes up as a Markdown-only PR.
2. **Tell D6 (through the coordinator) anything the check finds that GT-MIB's agent depends on,** as soon as it is found, so D6's case table and agent are not built on a reading the client fails. The two known case table corrections (H12, W4) are D6's.
3. **Review D6's GT-MIB agent and V-M1 PR for the SNMP reading** when it is up: each case in `tests/integration/gt_mib/cases.json` against what the agent does, and any V-M1 failure against the client. Acceptance: V-M1 (a) to (c), (e) and (f) pass on the real binaries.

Carried and not started: the OUT101 wording in the next signed SEL-751 register revision (D2-handoff task 3), only when D1 opens one. Parked and owner-gated: H-13, H-16, H-17 and other families.

## Questions

1. **For D1: order of a client fix and V-M1.** If the RFC check finds a divergence in the client, D2 proposes that the fix merges before D6's V-M1 run, so V-M1 measures the client as it will ship. A fix PR touches only `modules/ied/snmpv3` and its tests. Is that the order you want, or should V-M1 run on `main` as it is and record the divergence as a failure?
2. **For D1: the note's name.** The D2 handoff names it `docs/phase4/C2-snmpv3-rfc-check.md`. The summary lets new findings files use `D2-`, so D2 will write `docs/phase4/D2-snmpv3-rfc-check.md` unless you prefer otherwise.
3. **For D6, through the coordinator: shared reading.** D2 will send any finding that bears on GT-MIB as it comes. Is there a section of the texts where your agent already made a choice you want D2 to check first (for example the Report counters in RFC 3414 §3.2 or the GetBulk limits)?
