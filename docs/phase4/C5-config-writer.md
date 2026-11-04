# C5: the configuration-read writer (D4-40 item 2)

C5, 2026-11-04. A design note for the node's writer of scheduled configuration reads. Nothing is built yet, and every result will be `simulated`. Contracts used, all on `main`: C9 0.3 (`FromResult`, `CheckAgainst`, `Compare`, `Digest`), C8 0.5 to 0.8 (the configuration actions, `ApprovalCovers`, `VerifyConfig`) and C5 0.7 (#382). One question needs a ruling before code (section 2); the rest follows the contracts.

## 1. What one read does

After an accepted `sel.config.read_all` run whose outcome passed the client's checks, the node does the following, in this order:

1. **Snapshot.**
   - `config.FromResult` builds the snapshot, `CheckAgainst` checks it against the transcript, and `Encode` writes it.
   - A failure here keeps the outcome as quarantine, as a refused SER result is, raising the `collection-result-refused` alarm.
2. **Store the snapshot** in `config/<asset>`, with the transcript as its capture and with no hold.
3. **Compare** it with the asset's acknowledged configuration baseline. That baseline is the stored C9 snapshot whose digest the last succeeded `config.baseline_acknowledged` of kind `configuration` names: the same fold as `holds.go`. The C8 result follows this table:

   | Baseline | `Compare` | An open change against this baseline | C8 record | Holds and alarm |
   | --- | --- | --- | --- | --- |
   | none | not run | not applicable | none: the snapshot awaits an acknowledgement | none |
   | yes | no changes | none | `config.read_compared`, `no_difference` | none; rule 3 removes it later |
   | yes | no changes | yes | `config.baseline_restored` | the open change moves to `restored-difference`, and its alarm ends |
   | yes | changes; `ChangesDigest` is the newest recorded change's | yes | `config.read_compared`, `same_change`, naming that change's seq and digest | none |
   | yes | other changes, and an approval covers them | either | store the difference, then `config.change_detected`, info, `approved_change` | snapshot and difference held `approved-difference` |
   | yes | other changes, and no approval covers them | either | store the difference, then `config.change_detected`, warning, `unapproved_change` | snapshot and difference held `unapproved-difference`, and the `unapproved_change` alarm is raised |

4. **The fields** come from what the chain already holds:
   - `read_seq` is this run's `collector_seq`.
   - `unchanged_read_seq` and `unchanged_at` are the asset's previous run of the operation in the epoch. If there is none, they are the epoch's `collector.seq_reset` time.
   - `approval_seq` is the newest succeeded `config.change_approved` that `audit.ApprovalCovers` accepts.
   - `snapshot_seq` is the snapshot's stream seq.

   The node keeps these per asset in memory and rebuilds them from the chain at start.
5. **Holds, after the C8 record.** A hold's `Ref` is the C8 record, so the hold is taken only once that record has its Receipt (`Holder.Hold`, each in one transaction).
   - A crash between the record and the hold is repaired by the start-up reconcile, which rebuilds the holds from C8 already.
   - A crash between storing the snapshot and the record leaves a stored snapshot that has no result. The next read compares again. `VerifyConfig` requires only that a result names a real read.
6. **Store failures.** A failure to store the snapshot or the difference raises `evidence-not-stored`, and the read has no result. A failure to write the C8 record raises `audit-unavailable`. The stored records stay unheld, and the next read compares again. Neither failure stops the asset's other collections.

The difference has no capture. Its two snapshots are the baseline, already held `baseline`, and this read's snapshot.

## 2. The question: the node has no register

`FromResult` needs a `register.Matcher` to render the run's lines (`build.go:39`). The node loads no register package: `collectorclient.Client.Register` is nil on the node, so `CheckLines` runs only in the collector. Three ways out:

- **(a) The node loads the signed register envelope.** It reads the envelope it was commissioned with (`register_version` is already in the node configuration) and verifies it with `authz.VerifyRegisterPackage` against anchors in its own configuration. It keeps no floor: the node runs only `cfg.RegisterVersion`, and refuses at start a package of any other version. The same package can later set `collectorclient.Register`, so that the node checks lines as well (D1-25). That change is separate, because it changes how SER outcomes are treated. Cost: two configuration fields, and a review of the trust boundary by C3.
- **(b) C9 takes the run's lines from the snapshot rule.** `FromResult` gains a form that takes the lines from `Rules[ruleID].Classes`. The rule already names each class's command, so the register is not needed to know them. This is a C9 change (C2's). It drops the check that the run read exactly what the register's run renders, which the register's version gives today.
- **(c) The collector builds the snapshot.** This would move C9 into the privileged binary and add a field to the outcome (C7). I don't recommend it.

**I recommend (a).** It keeps C9 unchanged and keeps the check on the register's run. It is also the copy of the register that `collectorclient` was written to take. The rule ID per asset is a node table keyed by profile, with one entry: SEL-751 → `sel-751-sho/2`. A configuration read on an asset whose profile has no rule is refused at start.

## 3. Tests (simulated)

- **Each row of the table**, on a real node with the fake collector:
  - the C8 record, and `VerifyConfig` over the chain;
  - the stored records;
  - the holds after a restart;
  - the alarm.
- **Cross-version cases.** A baseline acknowledged before the read, an approval accepted before and after the read (`ApprovalCovers`), a restore after a change, and a re-acknowledgement.
- **Crashes**, at each step of section 1. After restart, the holds match the chain, and no result names a read that is not stored.
- **Refused snapshots.** A `FromResult` or `CheckAgainst` refusal is quarantined, and nothing is stored in `config/<asset>`.
- **Register refusals.** For (a), a register envelope that does not verify, or one of another version, is refused at start.

## 4. Not in this PR

- Rule 3's remover, which comes after the writer.
- The node side of `node.change_approval` and `node.baseline_ack`, which follows, on C3's #381.
- Wiring `collectorclient.Register`.
- Any rung other than `SHO` (D4-40 item 3).
