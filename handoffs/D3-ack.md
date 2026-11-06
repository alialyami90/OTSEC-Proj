# D3 acknowledgement: Security and Engineering Access Engineer

From D3 to D1, 2026-11-06, read at `main` `a774a97` (#486). I read [CLAUDE.md](../CLAUDE.md), [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), [D3-handoff.md](D3-handoff.md), [C3-ack.md](C3-ack.md) for its form, D4-58 in [B1-decisions.md](../docs/phase4/B1-decisions.md#d4-58-the-rfc-texts-message-routing-through-the-coordinator-and-the-c-to-d-handoff-owner-and-c1-2026-11-06), the HR-16 to HR-18 rows in [threat-model.md](../docs/threat-model.md), the item 3 exit report, and the D1, D2, D5 and D6 handoffs where they name role 3. Everything below is `desk`: I ran no tests for this ack, and I cite CI only where the summary or my handoff does.

## My scope

- **I own** C7 (`contracts/authz/`), C8 (`contracts/audit/`) and C11 (`contracts/advisory/`), whose changes D1 approves; `modules/security/` (`collector`, `collectorclient`, `collectorwire`, `nodekey`, `seal`, `snmpegress`); `modules/access/`; `cmd/otsec-collector/`; `docs/threat-model.md`; my own `docs/phase4/C3-*.md` and new `D3-*.md` files; and `tests/tools/advisorysign/` (the P4-3-C3 brief's "May change" line).
- **I review** trust boundaries for everyone: D2's register and SNMP client, D5's node side, every toolchain or dependency bump with D6 (D3-10), and security in V-M1. Reviews are COMMENT only, at the full 40-character head SHA.
- **I don't touch** another role's paths, `ci.yml`, `govulncheck.yml`, `contracts/README.md`, or another agent's branch, unless D1 authorizes it in writing.
- **The standing rules hold unchanged** (summary, "Standing rules every D agent must keep"): no device contact, loopback simulators only, test credentials only, GitHub Actions as the only test path while D4-12 holds, staging by explicit path, no force-push, and every message to another agent goes through the coordinator (D4-58).
- **D4-34 holds.** Item 3 ends with the owner's check. I take no new feature work until D1 relays the owner's choice of the next item. Reviews, and fixes to my own code that V-M1 or the RFC texts show are wrong, continue.
- **My branch** is `claude/project-thread-hm1s7a`. C3's branch `claude/project-thread-8k5430` has nothing ahead of `main` (D3-handoff §2), so I leave it alone.

## State I checked

| Item | State | Source |
| --- | --- | --- |
| `main` | `a774a97`: the six checkpoint PRs #481 to #486, with #479 (`a69c416`) and #480 (`158a5d0`) merged among them. All are Markdown-only, so the last code CI is still `961221b`'s ([run 42174011840](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42174011840)). | `git log origin/main` |
| Open role 3 PRs | None. | D3-handoff §3, summary "Open PRs" |
| D3-handoff §3's two caveats | Both resolved: #479 merged, so `docs/phase-4-item3-exit.md` is on `main`, and its line 114 still states role 3's no-objection with the two standing limits. #480 merged. | `git log`, `docs/phase-4-item3-exit.md:114` |
| C3's two proposals to D1 | Both recorded in D4-58: the coordinator routing rule, and the wall-clock rule for socket waits under a test clock. | `docs/phase4/B1-decisions.md:966` |
| HR-16, HR-17 | Still "open, draft" although the design is built (#446, #449, #456, #461). Task 2 below. | `docs/threat-model.md:197-198` |
| `snmpegress` | Comments cite RFC 3412, 3414 and 3416 and X.690, but D3-handoff §2 says its layouts were written from memory. Not yet checked against the texts in `/mnt/project-files/rfc/`. | `modules/security/snmpegress/egress.go:91,98,203` |
| GT-MIB's agent | A WIP patch only (`/mnt/project-files/c6-wip/2026-11-06-gt-mib-agent-wip.patch`); no PR yet. | `c6-wip/README.md` |

## My first three actions

1. **Check `modules/security/snmpegress` against the RFC texts now, while D6 builds GT-MIB.** D2 does the same for `modules/ied/snmpv3`, and D1-handoff line 42 makes a layout error in `snmpegress` mine to fix. Each layout the check reads (the v3 message header and `msgFlags`, RFC 3412 §6; the USM security parameters and the discovery shape, RFC 3414 §2.4 and §4; the PDU tags, RFC 3416 §3; length forms, RFC 3417 §8; AES-CFB IV, RFC 3826 §3.1) gets a citation to the text, in a desk note `docs/phase4/D3-snmpegress-rfc-check.md`. A divergence gets a failing test first, then the fix, in a PR reviewed by D6 and D2. The refusal of a non-minimal long-form length on our own outbound messages stays as policy, not as an RFC claim (D6-handoff fix (a) for H12). The deny corpus in `tests/integration/gt_mib/egress/` is D6's; I send what I find there through the coordinator. **Done when** the note cites every layout and `go test ./modules/security/...` passes in CI on Linux and Windows for any code change.
2. **Review V-M1's security when D6 posts GT-MIB's agent and runner (the handoff's NEXT ACTION).** Accept when: every message the client sends passes `snmpegress.Check`, and no `SetRequest` or v1/v2c message leaves it; an engine-ID mismatch, an unknown user, a wrong digest, a decryption error or a lower security level ends the session without re-localizing keys (HR-16, D4-49 Q1); the agent binds loopback only and imports no product package; M3's key search finds nothing; and the egress corpus's layouts match the texts. Proving tests: V-M1 (a) to (c), (e) and (f), (d) for the refusal alone, and `deny_test.go`. D6's runner installs an `snmpv3` credential through `slicehelper install-credential` (D6-handoff task 2). I have not checked that path end to end on the binaries, so I will confirm it the moment D6 asks.
3. **After V-M1 passes:** tell D1, through the coordinator, whether any role 3 objection is open. Then rewrite the HR-16 and HR-17 rows from `main`, each claim with its PR, test or run and its evidence class, nothing claimed for hardware, as a Markdown-only PR.

## Questions

**For D1:**

1. **Action 1 under D4-34.** I read checking my own `snmpegress` against the RFC texts as verification of item 3, not new feature work, so I am starting it now. Tell me if you want it held until D6's PR is up.
2. **D4-20 rule 4 (the evidence release and export kind)** is STALLED: untouched by B3 and C3, and now handed to me. D4-20 lets it stay unbuilt. Should it be recorded as deferred to a named later item, so it stops being carried as a task, or do you want a brief for it after item 3?
3. **D5's STALLED `clear-suspension.json` item** needs role 3's collector-side refusal of the unsigned file first (D5-handoff task 5). Same question: brief it after item 3, or record it as deferred?

**For D6 (through the coordinator):** none now. I will review GT-MIB's PR when it is up.

**For the owner (through D1):** nothing new. HR-18, severity scores and the v1/v2c approval key stay as the summary lists them, and no real advisory is entered until HR-18 is decided.

No overlap or gap found between my handoff and the summary's agent map.
