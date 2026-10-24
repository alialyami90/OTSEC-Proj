# A5 handoff: P1-A5 (C5 `otsec.store/0.1` and node posture labels)

Owner: A5. Date: 2026-10-24. PR #33, branch `claude/project-thread-xni3ff`. C4 and C8 have merged, and the PR is ready for A1 to merge. A1 holds `docs/agent-handoffs.md`, so this file is the handoff for A1 to copy in.

**Completed**

- **C5 `otsec.store/0.1`** in `contracts/store/`. It is Go interfaces plus two pieces of logic owned by the contract: the group-commit `Log` and the startup sequence `RunStartup`/`Resume`. It uses the standard library and other contracts only, and does no I/O.
  - **Data ownership.** One writer per database, and each stream has a fixed class (`Layout`, `StreamSpec`). There is exactly one audit stream per node.
  - **Commit before acknowledgement.** Commits are grouped. A sealed `Receipt` exists only after a commit at `FULL`. A refusal (`quota-reached`, `invalid`) does not stop the Log; any other commit failure does.
  - **Outbox, cursors and pruning.**
    - The prune boundary comes from persisted cursors on every call (R-A5-5).
    - For a best-effort consumer the boundary is time-based only, and never comes from its cursor (D1-5).
    - Only C6 `relp-tls` targets with a `durable_ack` check can be required consumers.
    - Audit can be pruned only by required consumers.
    - C5 0.1 has no forced prune.
  - **Audit.**
    - Records are sealed into the C8 chain inside the commit (`SealAudit`).
    - A chain anchor is kept across pruning (`Outbox.ChainAnchor`).
    - `AuditBeforeAct` covers privileged operations and collection that uses a credential (C5-A3-3, D1-11).
  - **Startup recovery order.**
    - The order is lock, inspect, release reserve, headroom, open, settings, integrity, prune, compact, re-create reserves.
    - A failed release of either reserve stops startup.
    - Nothing else opens the store.
    - The two-tier reserve covers F-013 and F-014.
    - The last-resort reserve is released in the same run if the recovery reserve does not free enough space.
  - **States.** `blocked` and `drain-only` each have a defined exit (`Resume`), and `Mode.AcceptsEvents` tells collectors whether to run (D1-4). `ModeChangeOf` produces the health event and the audit record.
  - **Storage-full actions** are fixed per class. Alarms map to C4 health types (`AlarmCode.HealthType`).
- **Docs:**
  - `docs/phase1/A5-store-semantics.md`, sections 1 to 8;
  - `docs/phase1/A5-node-posture.md`: storage durability label, OS support label with the lifecycle table, the `node-os-unsupported` standing condition, one collecting node per asset (D1-3), and the shape proposed for C1.
- **Reviews written:**
  - `reviews/C4-A5.md`: accepted.
  - `reviews/C7-A5.md`: accepted on re-check, with one non-blocking wording item about flushing credential state changes.

**Evidence**

- `go test ./contracts/store` passes, and so does `-race -count=30`. The tests run against an in-memory fake.
- CI is green on Linux and Windows on every push of PR #33.
- A6 reviewed C5 with its own fakes, not `fake_test.go`.
- A3 ran an interop probe: the real C8 `Seal` with `SealAudit`, verified with `audit.VerifyChain`.
- The lifecycle table was checked by A6 against Microsoft's page and `zoneinfo`: 10 of 10 match.

Evidence class: `desk` and `simulated` only. Nothing has run on the Windows site image or on hardware.

**Reviewer outcomes**

| Reviewer | Record | Outcome |
| --- | --- | --- |
| A4 | `reviews/C5-A4.md` (#42 at `d24e1ae`) | Accepted. Four changes applied at `2ef46a2`. The re-check at `8c1eb82` stands. Its note on citing `durable_ack` is applied at `c7f664e`. |
| A3 | `reviews/C5-A3.md` (#38 at `0836ff2`) | Accepted. C5-A3-1 to C5-A3-3 were applied at `24db070` and closed on re-check. The lock is accepted for 0.1 on three Phase 2 conditions. |
| A6 | `reviews/C5-A6.md` (#40) | Accepted. Six changes applied at `ad0b470` and accepted on re-check. Its follow-up note is applied at `8c1eb82`. |
| A1 | D1-3, D1-4, D1-5, D1-11, D1-13 | All applied. D1-13 is in `A5-node-posture.md` section 5 and `deploy/README.md`. |

**Interfaces**

- Introduces C5 `otsec.store/0.1`.
- Uses C4's `EventID`, `contracts/node`'s `ID` and `Stream`, and C4's health type constants.
- Uses C8 `contracts/audit` (`ValidatePending`, `Seal`, `Hash`, `Checkpoint`, `GenesisPrevHash`).
- Proposes for C1 (A2) the posture shape in `A5-node-posture.md` section 6.

**Limitations**

- There is no SQLite implementation and no site-to-central protocol (both excluded by the brief).
- In 0.1 the `Layout` is read at startup, so a stream added when an asset is enrolled takes effect at the next restart.
- These values are *(proposed)* and not measured:
  - `OpenHeadroomBytes` (the WAL bound plus 64 KiB);
  - the 60 s retry intervals for `Resume`;
  - the 5-minute startup deadline;
  - the group-commit default of 100 events or 100 ms.

**Risks**

- Whether the open headroom actually prevents F-013 on NTFS is untested (H-14 part 3).
- The lock layers are untested: a protected DACL on the directory, `temp_store=MEMORY`, separate service SIDs, and a share-mode-0 lock file.
- `Usage` must count live pages, or startup prunes every confirmed event. This is a Phase 2 conformance test (V-S9).
- One bad pending audit record refuses its whole group, which is fail-closed (C5-A3-10). Phase 2 should validate audit records in `Append`.
- A local administrator or SYSTEM can bypass the store ACL. The C8 chain detects tampering; it does not prevent it.

**Dependencies**

- **A1:** add the C5 row to the `contracts/README.md` table; copy this handoff into `docs/agent-handoffs.md`.
- **A2:** carry the posture shape into C1.
- **A6:** run V-S9 (blocked, drain-only, failed release, nothing prunable at quota, D1-11) and H-14 part 3 on the site image.
- **Phase 2 (A5):** the SQLite store with A3's three lock conditions, an alarm channel outside the store (C5-A3-5), and the `Usage` and `CompactStep` conformance tests.

**Files changed**

- `contracts/store/`: `doc.go`, `key.go`, `errors.go`, `class.go`, `layout.go`, `commit.go`, `outbox.go`, `startup.go`, `audit.go`, `fake_test.go`, `store_test.go`, `audit_test.go`.
- `docs/phase1/`: `A5-store-semantics.md`, `A5-node-posture.md`, `A5-handoff-phase1.md`.
- `docs/phase1/reviews/`: `C4-A5.md`, `C7-A5.md`.
- `deploy/README.md`: upgrade order (D1-13), storage sizing, Windows host rules.
