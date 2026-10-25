# C8 0.2: collector reset and node-side suspensions

Owner: A3 (C8 is A3's, per `contracts/README.md`). Ruling: A1 D2-15. Reviewed in draft by A5 and A6 (`/mnt/project-files/phase2/reviews/A3-c8-seq-reset-A6.md`). Implemented in `contracts/audit` as `otsec.audit/0.2`. The node side is A5's and follows this contract.

## Problem

A reinstall after both collector stores are lost creates a fresh collector state. Two things follow.

- **Numbering restarts at 1.** The node writes each reply's `collector_seq` as it receives it. Without a rule, `audit.VerifyCollectorSeq` reports a real reinstall as a broken chain, and the node raises no alarm.
- **Safety state is lost.** The fresh state loses the asset suspensions the old collector recorded (`Code.Suspends`, PR 4) and the register family floors. From PR 4 a fresh state keeps a 31-minute failed-auth floor on every asset, but nothing brings back a suspension.

A restore of `credentials.json` and `state.json` together looks the same from the node, except that the install key does not change.

## The records

All five actions are new in 0.2 and written by the node. Each has outcome `info` and actor type `node`. A record stamped 0.1 cannot carry any of them, or any of their fields.

| Action | Fields | Written when |
| --- | --- | --- |
| `collector.install_key` | `install_key_id` | The node first trusts the collector's install key, at its first start, before its first request. The key is then in the chain from the start (A6 must 2). |
| `collector.seq_reset` | `previous_high` (the highest `collector_seq` recorded before; 0 when none), `install_key_id` (the new key), and `first_seen` when a reply showed the reset | The node finds the collector reset (below). |
| `collector.seq_reset_ack` | `install_key_id` | An admin acknowledged the reset on the key they confirmed. That key becomes the trusted key. |
| `asset.suspend` | `target.asset_id`, `suspension.reason` (C1), `suspension.code` (the C2 code that set it; absent for reason `operator`), with the ref as `correlation_id` (the C2 invocation ID, or the operator's principal ID) | The node records an outcome whose code suspends the asset, or an operator's suspension. |
| `asset.suspension_clear` | `target.asset_id`, `suspension.reason`, with the ref as `correlation_id` | An admin cleared that suspension. |

Each field is allowed only on its own actions. `asset.suspend` exists because collector-reported records do not reliably carry the C2 code (A5), and without it the node has nothing to rebuild its suspensions from.

## When the node writes a reset (A5, D2-15)

1. **Before each request**, the node reads `collector\public\install-key.json`. If the key ID differs from the trusted key, it writes `collector.seq_reset` without `first_seen`, holds collection, and sends nothing (A6 must 1). This catches a reinstall whose fresh floor has already passed, where one level 0 run could otherwise reach an asset the old collector had suspended.
2. **As a backstop**, a reply whose number is at or below the high mark is a reset. The high mark is the `collector_seq` of the newest audit record that carries one. The reset record goes first in the reply's audit batch, with `first_seen` set to the reply's number. If the key is unchanged, it is a restore or an impostor (W-1), never a reinstall: collection is held, and the admin must not acknowledge it.
3. **Fail closed.** If `install-key.json` cannot be read or parsed, the node sends nothing and holds. No reset record is written without the key. If the audit record cannot be written, the node holds (D2-15).
4. **The hold** follows from an open reset with no acknowledgement in the audit stream, so it survives a node restart.

## How the chain is verified

`VerifyCollectorSeq(recs, after, through)` has the same signature as in 0.1. A 0.1 chain verifies exactly as before. Records are read in chain order.

- **A reset closes an epoch.** The numbers before it must be exactly `after+1 .. previous_high`, each on one record, with nothing above. `previous_high ≥ after` is required. The epoch may be empty, for example when the verification window starts just before the reset.
- **The next epoch starts at 1.** It must hold `1 .. ` the next reset's `previous_high`, or `through` for the last epoch.
- **`first_seen` is checked.** When the reset carries it, the first collector record after the reset has that number. Numbers below it in the new epoch are still owed, so an unrecorded decision of the new collector breaks the chain.
- **The key must change.** The trusted key comes from `collector.install_key` and then from each acknowledgement. A reset whose key equals the trusted key, or any earlier reset's key, breaks the chain. A `collector.install_key` that changes a trusted key without an acknowledged reset breaks it too.
- **An acknowledgement** must name the key of the open reset. A second acknowledgement, or one with no open reset, breaks the chain.
- **A restart with no reset record** still breaks the chain, as in 0.1.

`VerifySuspensions(recs)` checks that each `asset.suspend` opens a suspension, keyed by asset, reason and ref, that is not already open. Each `asset.suspension_clear` must name one that is open. It returns the suspensions still open, which is what the node rebuilds from. The node's suspension file is a checkpoint carrying the audit seq it reflects (A5). Pruning stays within the checkpoint (D2-15).

## What the rules stop, and what they do not

- **A node that leaves records out cannot hide them behind a fake reset.** Without a reinstall, the collector's real numbers keep rising past `previous_high`, and the new epoch cannot hold `1..n`. The key rule adds a second check: the node can copy the current key into a fake reset, but the verifier refuses a reset that keeps the trusted key.
- **A node that forges records is not stopped.** `collector_seq` is node-written and unsigned. That was already true in 0.1. The C7 0.2 candidate `collector_epoch` (the state's `created_utc` on every reply) would let the node check the epoch before it sends. Signed collector reports would be needed to stop forgery.
- **A real reset can hide the old epoch's tail.** If the node left out 51 to 60 and then a real reinstall followed, it writes `previous_high: 50`, and the old collector, the only other holder of 60, is gone. A verifier that holds a higher old-epoch number from outside the node, such as the highest `collector_seq` forwarded upstream, should compare it.
- **A joint restore is caught only here.** The collector refuses a credential store restored by itself (the generation, A6 on #90). It does not refuse one restored together with its state. The numbers go back under an unchanged key, the node holds, and the admin does not acknowledge.

## The acknowledgement (Phase 2 interim)

The T-12 fingerprint confirmation is the acknowledgement, so the admin does one thing, not two.

1. The node status shows the trusted key ID and the new one side by side.
2. **The admin acknowledges only if the fingerprint differs from the one confirmed before.** An unchanged key means a restore, a fault or an impostor, and must be investigated.
3. **Before acknowledging, the admin reviews:**
   - the suspensions the node holds (A5's node-side suspensions carry them across the reset);
   - the active register revisions, because the fresh collector's family floors are empty and an older signed package could be activated again (A6 note).
4. Elevated, the admin writes `OTSEC\config\seq-reset-ack.json` naming the confirmed `install_key_id`. The node can read `config` but not write it. On `Tick`, the node writes `collector.seq_reset_ack` and resumes, only if the key matches the open reset. A file naming another key, including one left from an earlier reset, changes nothing.

`asset.suspension_clear` arrives the same way, as an admin-written file.

**The file names no person.** Before any `device-observed` endpoint, the acknowledgement and the clear must become admin-signed C7 0.2 requests (D2-11, D2-15).

## Numbered decisions all pass through the node

A6 asked whether a numbered decision can bypass the node. It cannot. The collector numbers a request only when it is decided, and requests arrive only over the collector pipe, whose peer check admits the node service alone (W-1). Credential installs after a reinstall are relayed by the node too, and the node records each reply as `collector.request` allowed or denied, with its number. A number the collector gave that the node did not record (a node crash between the reply and the commit) is a gap, and that was also true in 0.1.

## Tests (`contracts/audit/nodestate_test.go`)

- **Field and action rules:** every valid shape is sealed and parsed, and 27 invalid ones are refused. These include each field on another action, 0.1 stamping, a human actor on a file-borne record, a C1 reason where a C2 code belongs, and a code on a clear.
- **Epochs:**
  - one reset, a reset then an acknowledgement, two resets, a reset before any record, a window from a verified point, a window that starts at the reset, a window inside epoch 2, a reset found by the key, and the trusted key carried by the acknowledgement, all verify;
  - 18 broken cases each break the chain: a restart without a reset, a gap before the reset, `previous_high` above, below, or under `after`, numbers below `first_seen`, a first record that is not `first_seen`, a missing `first_seen`, a repeated key, a reset that keeps the trusted or the acknowledged key, a key change without a reset or before the acknowledgement, an acknowledgement without a reset, on another key, or twice, and missing tails.
- **Suspensions:** the open set after a clear, and a clear with nothing set, on another ref, on another reason, a double clear, and a duplicate suspend each break the chain.
- **Schema** `schema/record.json`: the five actions and four fields, with their conditional requirements.
