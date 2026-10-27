# B4 handoff: Telemetry, Event Processing and IDS

From A4, 2026-10-27, at `main` `d4afc63`. Read this file first, then the documents it links. It does not repeat what they say.

## Role & scope

B4 takes over A4's role in `CLAUDE.md` §4: telemetry, event processing and IDS. The working rules are in `CLAUDE.md` §2 and §5, and the scope update at the top of `CLAUDE.md` (all OT device classes, SEL first).

B4 owns, and may change without asking:

- `modules/telemetry/`: `receive/` (the Syslog listener), `normalize/` (SER and Syslog into C4 events), `forward/` (C4 events out as C6 Syslog), and `experiments/` (Phase 0 and 1 experiments, kept as evidence).
- `modules/detection/`: empty except `.gitkeep`. The Phase 4 event baseline goes here.
- `tests/fixtures/network/`.
- The A4 design notes: `docs/phase2/A4-*.md`, `docs/phase3/A4-syslog-receive.md`, and `docs/phase4/A4-*.md` when Phase 4 starts.
- The C4 contract `contracts/event/` (`otsec.event/0.2`) and the C6 contract `contracts/syslog/` (`otsec.syslog/0.3`), as their author. A change to either is a shared-contract change: write a proposal, have every consumer review it, and get A1's (B1's) approval (`CLAUDE.md` §5.3, §5.4).
- In Phase 4, a new `contracts/baseline/` (C10), with A1's approval.

B4 does not touch:

- `platform/` (A5 owns it, including how the node wires the listener and counts unknown storage);
- `modules/ied/` (A2);
- `modules/access/` and `modules/security/` (A3);
- `tests/integration/`, `tests/security/` and `tests/safety/` (A6);
- other contracts (`contracts/README.md` lists each owner).

Reviews owed by role (`CLAUDE.md` §5.6): A4 reviews A2's protocol-adjacent work (the SER output format and C2), A5's listener wiring and store changes that affect telemetry, and A6's tests on the receive and normalize paths.

## Current state

**All A4 work is merged. Nothing is in progress, paused or uncommitted, and no A4 PR is open.** The only A4 branch is `claude/project-thread-ix2tu3`, which carries this file.

**Phase 3 passed its exit gate with conditions (A1, 2026-10-27). The owner has not accepted it yet, so Phase 4 is held.** Do not start Phase 4 work until the owner accepts Phase 3 and A1 (B1) releases the Phase 4 briefs. See `docs/phase-3-exit.md`, "Decisions needed from the owner".

What A4 delivered (the PR list for each phase is in its exit report):

- **Phase 2** (`docs/phase-2-exit.md`). The SER normalizer `normalize.Normalize` (`modules/telemetry/normalize/ser.go`). The C6 forwarder `forward.New` / `(*Forwarder)` (`modules/telemetry/forward/forward.go`): RELP over TLS and RFC 5425. C4 and C6. Notes: `docs/phase2/A4-normalize.md`, `docs/phase2/A4-forward.md`, `docs/phase2/A4-c6-0.2.md`.
- **Phase 3** (`docs/phase-3-exit.md`, the A4 row of "Implemented"):
  - The Syslog receiver `receive.New` / `(*Receiver).Serve` (`modules/telemetry/receive/`, #150). It supports RFC 5425 TLS by default, plus RFC 6587 TCP and RFC 5426 UDP per listener. Raw bytes are stored before parsing. It correlates senders, applies per-source limits and an unknown-sender budget.
  - The Syslog normalizer `normalize.Syslog` (`normalize/syslog.go`), with the SEL dialects `normalize.Dialect`.
  - C4 0.2 and C6 0.3, which add the sender's TLS leaf.
  - The RTAC size fix.
  - `Config.UnknownSpent` (#178), and its defect fix #196: an unknown sender is charged as it is read.
  - The SER normalizer reads `DATE_F` (#203, D3-11).
  - Design note: `docs/phase3/A4-syslog-receive.md`. Its "Known limits" and "Handoff (P3-A4)" sections are current.

Everything is `desk` or `simulated`. No result is hardware-verified, and no device has ever sent Syslog to the platform.

## Next steps

**First action:** wait until the owner has accepted Phase 3 and B1 has confirmed that Phase 4 is open. Then read the P4-A4 brief ("Task P4-A4: The event-behaviour baseline (R4.8)" in `docs/agent-handoffs.md`). In `docs/verification.md`, read V-M4 and the section "R4.8 observation period and measures". Then draft C10 `otsec.baseline/0.1` in a new `contracts/baseline/`, in one PR, for B1's approval. Until Phase 4 opens, only reviews and fixes to merged A4 code are in scope.

In order, once Phase 4 is open:

1. **Draft C10** beside A2's (B2's) C9, so that the two share one store design (the brief's "Timing"). B1 approves C9, C10, C7 0.6 and C8 0.5 together, after every consumer has reviewed them (`docs/agent-handoffs.md`, the Phase 4 order, step 1). C10 must state the following. The brief fixes the first three points; the rest are still open, and the draft must decide them:
   - **The event-type key, exactly** as in "R4.8 observation period and measures". For SER, the element name and its state as printed. For Syslog, facility, severity and MSGID, or the digit-replaced template when there is no MSGID. A key change after A6 writes the tests is a contract change. B2 reviews the SER key.
   - **Clock.** Rate and time-of-day rules run on `received.utc`. Device time may be used only for time-of-day, and only when the offset is known (V-S3). The alarm names the clock it used.
   - **`asset-unresolved` events** belong to no asset's baseline (A6's invariant). *Open:* C10 must say whether they are ignored or counted only in a site-level total. A4 leans toward a site-level total only, so that a stranger flood remains visible without polluting any asset.
   - **Repeats.** A repeat (the same `record_sha256` within a window) counts as an occurrence, not as a duplicate to drop. R4.8's repeats rule depends on this.
   - ***Open:* how a `possible-duplicate` event counts.** The flag (`event.AlignPossibleDuplicate`, `contracts/event/align.go`; set in `rowAlignment` in `normalize/ser.go`) means that an ambiguous SER re-read overlap may have stored that row before. If every such row counted, one real occurrence could count twice and raise a false repeats alarm. If none counted, a real repeat could be missed. A4's proposal for A6 and B1: count a `possible-duplicate` SER row only when no event already counted for the asset has the same alignment key (the row bytes from DATE to the end of the line, `contracts/event/align.go`). When a row is not counted, the alarm and the baseline record its event ID as "possible duplicate, not counted". Syslog events never carry the flag. A6 asked that C10 state this rule, so it is a gate item.
   - The baseline record and the departure alarm, as listed in the brief's "Expected interfaces".
2. **Agree the C5 0.4 scope with A5 (B5) before C5 0.4 is drafted.** C5 is `contracts/store` (`otsec.store/0.3` now), and A5 owns it. P4-A5's brief puts three changes into one minor, so that two C5 minors are never open at once:
   - a configuration stream class with its own quota;
   - HR-11's separate class and quota for unknown senders;
   - the faster unknown count.

   What B4 must get into it:
   - The unknown class must be absolute. It must not be refilled by a restart or by a clock step (HR-11).
   - When the class is full, the node raises a health alarm, and a known device still stores.
   - The faster count must keep #196's rule: charge at read, count by received time. Two designs work: the store keeps the stream's latest received time, or the store keeps a running total saved with commits and keyed by received time. **A total keyed by commit time would bring back #178's defect** (see the brief's "A4 with A5: HR-11" item).
   - Where the C10 baseline itself is stored (a C5 class or C9's store) is *open* and is decided with C9.
3. **Build the learner and the five departure rules** in `modules/detection/` after C5 0.4 merges (the Phase 4 order, step 3). Deterministic rules only, with no machine learning. A6 tests the result against V-M4 on the GT-INJ series. Write a `docs/phase4/A4-*.md` design note.
4. **Receive hygiene, beside the above** (the brief's carry-over list):
   - a configurable UDP receive buffer (`SetReadBuffer`) that logs the size the OS grants;
   - the receiver side of HR-11's bound, once C5 0.4 exists.

   A6's test fills the bound across an outage while a known device still stores. HR-11 gates the first `device-observed` listener.

## Key files

| Path | What it is |
| --- | --- |
| `docs/agent-handoffs.md` | Every brief. Phase 4: "Task P4-A4", "Task P4-A5" (C5 0.4), "Carry-over and hygiene", "Phase 4 order". |
| `docs/verification.md` | V-M4 and "R4.8 observation period and measures"; V-S3 (offset known); V-S8 (raw bytes); V-S12 (collection failure). |
| `docs/phase-3-exit.md` | The current state, defects found, limitations, and the decisions waiting on the owner. |
| `docs/phase3/A1-decisions.md` | D3-1 to D3-11. |
| `docs/threat-model.md` | HR-11 and the other open risks. |
| `docs/decisions/ADR-0008-monitoring-goals-and-collection-method-order.md` | The owner's monitoring goals and the Phase 4 order. |
| `docs/requirements.md` | R4.8 (the event baseline). |
| `docs/phase3/A4-syslog-receive.md` | The receiver design, its limits, its Known limits and its tests. |
| `docs/phase2/A4-normalize.md`, `A4-forward.md`, `A4-c6-0.2.md` | The SER normalizer, the forwarder and C6. |
| `contracts/README.md` | Every contract, its version and its owner. |
| `contracts/event/` | C4. `event.go` (the `Event` type, `KnownFlags`, `Alignment`), `align.go` (the SER re-read alignment), `validate.go`, `schema/`. |
| `contracts/syslog/` | C6. `target.go` (`Identifier`, targets), `render.go`, `relp.go`, `schema/`. |
| `modules/telemetry/receive/receive.go` | `Config` (including `UnknownSpent`), `Limits`, `New`, `Serve`, `record`, `records`, `payUnknown`, `spend`, `startBudget`, `serveAlarms`, `alarmBudget`, `seqSlack`. |
| `modules/telemetry/receive/datagram.go`, `stream.go`, `frame.go`, `limit.go`, `senders.go`, `tls.go` | UDP read loop; TCP and TLS readers; RFC 6587 framing; per-source limits; `SendersFor` and `DialectOf`. |
| `modules/telemetry/normalize/ser.go`, `syslog.go`, `time.go`, `state.go` | `Normalize` and `dateOrder` (D3-11); `Syslog` and the dialect parsers (`parse5424`, `parse3164`, `rtac`). |
| `modules/telemetry/forward/forward.go`, `tls.go` | The forwarder. |
| `platform/node/listening.go`, `listenlimits.go` | A5's code, read-only for B4: how the node starts listeners, counts `UnknownSpent` (`NewListening`, `unresolved`) and sizes `UnknownBytes` (`ListenerSizings`). |

## Decisions made

The decision records hold the reasons. This list says which decisions bind A4's code.

- **A3's unknown-sender condition (cited as D3-3 with HR-11; the record is `docs/phase3/A4-syslog-receive.md`, Known limits, and `docs/threat-model.md`, HR-11).** A listener's unknown senders may store `UnknownBytes` per `UnknownWindow`. A node start does not refill this budget: the node counts the stored length of `asset-unresolved` records by received time and passes it as `Config.UnknownSpent`. A future time stamp counts as inside the window.
- **#196: unknown senders are paid for as read** (`payUnknown`, right after the received stamp). Each record is charged `len(event) + seqSlack`. `seqSlack` is 18, because the store writes the seq over `id.seq` 0. A message over budget is dropped before it takes queue room, and the alarm is raised off the read path (`serveAlarms`). Keep this rule in any change to the count.
- **D3-11.** A C2 0.5 result with no `DATE_F` keeps the pre-0.5 date rule: the caller's order, or MDY with `date-format-assumed:MDY`. A present but unknown `DATE_F` beside a parsed row returns `ErrResult`. A caller's order that disagrees with a known `DATE_F`, or that sits beside an unknown one, returns `ErrInput`. Refusing the whole read would stop collection while the relay's SER buffer overwrites.
- **C6 0.3.** The sender TLS leaf structured data (`tlsleaf`) is never omitted: it is 75 octets, inside the size budget. `Validate` accepts any `0.x` minor of C4 and C6.
- **RTAC packet bound of 1024 octets** (the RTAC size fix in #174), from RTAC documentation.
- **UDP loss before the read** (OS buffer overflow) is uncounted. It is a stated limitation (`docs/phase3/A4-syslog-receive.md`, Known limits; A6's #191), not a defect.
- **A3's ε option for the budget was declined.** Charging at read with `seqSlack` made it unnecessary.
- **Phase 0 and Phase 1 decisions** (event schema, alignment key, RELP versus RFC 5425, Zeek and Suricata evaluated before any in-house detection) are in `docs/phase-0-exit.md`, `docs/phase-1-exit.md` and the ADRs.

## Open questions / risks

- **HR-11 is open.** A forward wall-clock step followed by a restart refills the unknown budget. The absolute bound (C5 0.4) gates the first `device-observed` listener.
- **C10 rules that are still open:** how a `possible-duplicate` row counts (proposal above); whether `asset-unresolved` events are ignored or counted site-wide; where the baseline is stored.
- **C5 0.4 scope** is not agreed with A5 yet (see Next steps, item 2).
- **D3-10.** The Windows UDP memory corruption was likely golang/go#78041, fixed in Go 1.26.2, but the cause is inferred, not proven. Go 1.26.10 showed 0 crashes in 41 runs. The move to Go 1.27.3 is A1's hygiene item. If a `receive` panic appears on Windows again, reopen D3-10.
- **Syslog layouts rest on documents only** (RTAC, SEL-2730M, SEL-2488 and its time offset). RTAC firmware differences in time stamps are untested. The first real device may break a dialect.
- **Senders are attributed by source address.** That is spoofable on UDP and TCP, and on TLS until C1 has pinned keys: the TLS leaf says which certificate authenticated the sender but does not bind the asset (`docs/phase3/A4-syslog-receive.md`, Known limits).
- **No RELP receive.** The receiver takes RFC 5425, RFC 6587 and RFC 5426 only.
- **Synthetic false-positive rates** for the event baseline say nothing about a real device. V-M4 reports them as `simulated`.
- **Duplicated sizing constants.** The node's record-size constants (`ReceivedRecordFactor`, `ReceivedRecordOverhead` in `platform/node/listenlimits.go`) are copied, not imported, in `modules/telemetry/normalize/syslog_size_test.go`. A change on one side must update the other.

## Dependencies

- **A5 (B5):** C5 0.4 (the unknown class and quota, the faster count, the configuration class); storage for the baseline; the node wiring of any new receive option, such as the UDP buffer. B4's learner waits for C5 0.4.
- **A2 (B2):** C9 (drafted together with C10); review of the SER event-type key; the C2 and SEL output format that `normalize` reads.
- **A3 (B3):** security review of any receive or forward change, and of HR-11's bound.
- **A6 (B6):** V-M4 and the GT-INJ series (committed before B4's tests first run); the HR-11 outage test; mutation verdicts on every PR.
- **A1 (B1):** approval of C10 and of every C4 or C6 change; the Phase 4 release.
- **The owner:** acceptance of Phase 3. Any contact with real equipment needs explicit authorization. None has been given.

## Gotchas

- **One branch, squash merges.** Work on the thread's designated branch only. After a squash merge, restart the branch from `origin/main` (`git fetch origin main && git checkout -B <branch> origin/main`, then `git push --force-with-lease`). One PR at a time.
- **CI is the main test path** (D2-13). It runs ten jobs, and a merge needs every one green on the PR's head. Never register the owner's PC as a self-hosted runner.
- **Windows runners are slow.** Test properties with waits (the rig's `g.wait(...)`), never fixed sleeps or timings. #187 and #196's tests show the pattern, including the blocking Appender fake `blockingLog` and `sync.OnceFunc` release in `t.Cleanup`.
- **UDP tests lose datagrams before the read**, especially under `-race`. Send until the counter you test reaches its target, with a time limit; do not count the datagrams sent.
- **Mutation checks are expected in every PR.** Break the code under test, show that the test fails, and quote the result in the PR body. A6 does the same independently.
- **Long local runs.** `go test ./...` is slow because of `platform/store` and `platform/node`; for quick checks, run `go test ./modules/telemetry/... ./contracts/event/... ./contracts/syslog/...`. The full `python -m pytest -q` takes over 20 minutes; use CI's split, `python -m pytest -q --ignore=tests/integration/slice` plus the quick slice set (see `.github/workflows/ci.yml`).
- **Before every push:** `gofmt -l .` prints nothing, and `go vet ./...` passes.
- **Name clashes in `receive`.** The package is crowded. For example, `admit` in `stream.go` is connection admission, so check for a name before adding one.
- **The GitHub tools sometimes disconnect.** `git fetch origin pull/N/head:prN` fetches a PR to review locally.
- **Thread messages are at most 2000 characters.**
- **Evidence.** Every result here is `desk` or `simulated`. Never claim a hardware result. Every fixture needs a `SOURCE.md`, and no fixture is written by hand and presented as device output. The repository is public: no secrets, real device data or internal host names.
