# Phase 3 decisions (A1)

Decisions A1 made during Phase 3, numbered D3-n. Phase 2's are in `docs/phase2/A1-decisions.md`; the gate rulings that opened Phase 3 are D2-21 and ADR-0008.

## D3-1: C5 0.3 `Discarder.Discard` for the audited quarantine clear (P3-A5)

Date: 2026-10-26. Design: `docs/phase3/A5-quarantine-export.md` (A5; A3 agreed to the authorization with conditions A3-1 to A3-5).

**Approved**, as a C5 minor (0.3), with these conditions on the contract:

1. **Static scope.** `Discard` refuses any stream whose name is not under the quarantine prefix, as well as any stream that has a consumer. "No consumer" is a runtime state (a consumer can be unregistered at the moment of the call); the prefix is the property the contract can promise. Confirmed events are never within its reach.
2. **Captures.** A capture is removed only when no retained record of any stream refers to it, the rule `PruneStep` already states.
3. **One transaction, with evidence that it fits.** The clear is all-or-nothing in one transaction committed at `SyncFull`, as the design says, because A3-2 refuses a retry once any listed seq is gone. E-A5-3 (a large delete can need more WAL space than a full disk has) applies, so the PR must show, with a test in the store-full pattern, that a `Discard` of the largest quarantine stream the store-full limit allows succeeds under the reserved headroom. If it cannot, A5 proposes a bounded form before merge; it is not approved by default.
4. **Result.** `Discard` returns the count removed and the bytes freed, so the `quarantine.cleared` record and `otsec health` can show the effect, and the quarantine-room alarm clears through the existing headroom path, not by a new one.

**Brief amendment.** The P3-A5 brief said the read-only CLI "records `quarantine.exported` in the audit chain". The CLI cannot write the chain, and must not: it opens the store read-only. A5's resolution stands: the CLI leaves its manifest (hashes only) in `config/admin`, and the node verifies the manifest against its own stream under the protected-file rule and writes the record. The two C8 actions are A3's to add. `clear-quarantine.json` is unsigned in this PR and moves to the signed form together with `clear-suspension.json` and the reset acknowledgement under C7 0.4, which is A5's node-side task in Phase 3.
