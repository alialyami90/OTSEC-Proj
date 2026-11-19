# C4: how the network path reads a later C4 minor's event (options)

**Status: proposed, not approved.** Owner D4. Brief P4-4-C4-FWD-OPT. This is the open item that D3's F4 on #763 (7009793907) raised and D1's approval on #763 (7010466389) assigned to D4: options before the next C4 minor that changes a field read on the network path, and before P4-4-DE, under D4-99 (a new mechanism is settled as options first). No code is changed here, and C13's approved option (b) (`docs/phase4/D4-c13-forward-read-options.md`) is not changed.

**Evidence class: `desk`.** Read at `main` `5938aec8`. Nothing in this note was run. The functions cited are in `contracts/event` (`Decode`, `Event.Validate`, `checkNetobs`, `checkObservedAddress`, `checkSensorCounters`), `contracts/internal/strictjson` (`Forward`, `checker.check`), `contracts/netobs` (`ObservationFromEvent`, `DecodeStored`, `AlertFromEvent`), `platform/node/netdetector.go` (`observationOf`, `alertsAfter`, `rebuildFrameIndex`, `observeTo`) and `platform/sensorlink/link.go` (`Link.record`).

## 1. What the network path judges, and what a forward read can drop

### 1.1 Which C4 kinds the network path judges

The product code calls `event.Decode` in twelve places (`git grep -n "event.Decode(" -- platform modules cmd ':!*_test.go'`). Five are in the network and intake files (`netdetector.go`, `netintake.go`), and only one reader leads to a judgement:

| Reader | C4 kind and type | What it does with the event | Judged? |
| --- | --- | --- | --- |
| `observationOf` (`netdetector.go`), called by `observeTo`, `rebuildFrameIndex` and the stored-capture lookup | `network-observation` | `event.Decode`, then `netobs.ObservationFromEvent`, then the detector's rules | **Yes** |
| `alertsAfter` (`netdetector.go`) | `telemetry-health`, type `netobs.alert` | `event.Decode`, then `AlertFromEvent`, to hold back alerts a replay raises again | No: an alert records a judgement already made (as in the C13 note, §1) |
| none in the node | `telemetry-health`, type `sensor.counters` | Written by `sensorlink` (`health.go`) and forwarded; no product code reads one back | No |
| `runSessionOf` and the two run lookups (`netintake.go`) | `telemetry-health`, `collection.run` and related | Rebuild a run's session for the hold | No rule of the detector reads the envelope from it; outside this note |

So **the one C4 kind the network path judges is `network-observation`**, through `ObservationFromEvent`. The rest of this note is about that kind.

### 1.2 What `ObservationFromEvent` reads from the envelope

`ObservationFromEvent` reads three envelope fields, and the rules read none:

- `kind`: anything but `network-observation` is refused as `type`.
- `source.asset.id` and `flags`: checked against the body's `node.dst_asset` (C13 §5). An unresolved destination needs no asset and the flag `asset-unresolved`; a resolved one needs the asset to equal `dst_asset`. Either mismatch is refused as `conflict`.
- `netobs`: handed to `DecodeStored`.

`observationOf` returns only the `*netobs.Observation`. The detector's rules, the frame index and the learner see the body, never the envelope. `Link.record` builds the envelope from the body (`source.asset` from `node.dst_asset`, the flag from `AssetUnresolved`), so today the envelope repeats the body and adds nothing a rule depends on.

### 1.3 What a forward read of a later C4 minor drops

`event.Decode` reads an event of a later 0.x minor with `strictjson.Forward`, which ignores a key that is not a field name and still refuses duplicates and case variants (`Decode`'s comment; D1-10). Read from the code:

- **Inside `netobs`, nothing is dropped.** `Event.Netobs` is a `json.RawMessage`. In `checker.check` it is neither a struct nor a map, so its object's keys are walked as `any` and none is refused or dropped, and `encoding/json` copies the raw bytes. The body therefore reaches `DecodeStored` whole, where C13's (b) decides it.
- **In the envelope, any key the reader's `Event` type lacks is dropped:** a new top-level key, or a new key in `source`, `source.asset`, `source.asset.binding` or `received`.
- **A new value in an open set is kept but not understood.** `flags` is open (`KnownFlags`; `checkFlag` checks only the token form), and `kind` is open. A later minor's flag value passes any reader's `Validate`, and `ObservationFromEvent` ignores every flag but `asset-unresolved`.
- **What fails closed already.** A new `binding.method` or `binding.confidence` value is refused by `checkAsset` and `checkObservedAddress` (closed sets). A later minor that moved the body out of `netobs` would fail `checkNetobs` (`missing`). A new kind for observations would fail `ObservationFromEvent` (`type`). Each of these is refused at judging, and the replay counts it under `observations_refused`.

### 1.4 Whether a dropped key can change a judgement

- **Today, no.** C4 0.4 and 0.5 changed only `sensor.counters` (C4-0.4-1 to -3, C4-0.5-1 to -3, `contracts/event/doc.go`); no rule of `network-observation` changed after 0.3. Nothing in §1.2 depends on a key that 0.4 or 0.5 added. So every build on `main` reads a stored 0.5 network-observation event the way it would read the same event at its own minor (`TestCCD2ForwardE47` and `TestCCD0E47StoredEvents` show the decode, not the judgement).
- **Later, yes.** The fail-open is latent: it opens the first time a C4 minor puts something a rule should respect into the envelope of a `network-observation` event, rather than into the C13 body. Two forms of that change read less restrictively to an older build:
  1. **A dropped key**, for example an envelope key saying the body is partial, redacted or superseded, or a second asset reference that the asset check must also match.
  2. **An ignored flag value** with the same meaning, for example a flag that marks the observation as not to be judged as complete.

  In both, the older build judges the observation as if the qualifier were not there. C13's (b) does not stop it, because the body's own `schema` is still within the reader's C13 minor.
- **Which records.** The same window as C13's §1: stored observations after the detector's restored `Through`, replayed by `observeTo` after a rollback, and the stored-capture lookup. **Held records are not in it:** `Link.record` builds the envelope when it commits, with `event.Identifier`, so a held record released by an older build carries the older build's C4 minor, and only its body can be of a later minor (C13 (b) then decides).
- **Why C4 moves separately.** `Identifier` is one constant (`doc.go`, 0.4 and 0.5 entries), so every C4 minor restamps every event the node writes, `network-observation` included, even when it changes only `sensor.counters`. C4 moved three minors (0.3, 0.4, 0.5) while C13 moved two.

## 2. The options

Each option answers the same points: whether it closes the fail-open; its cost to readers; the sensor; its tests with controls and mutants; its effect on the `docs/release.md` §7.1 floors and AP-10; and when it must land. "The hand install" (a build installed by hand below the mechanism) is the residual of every option, as in the C13 note, and AP-10 does not stop it either.

### (a) A per-key statement in each later C4 minor

Each C4 minor states, for the `network-observation` envelope, each key and flag value it adds and what a forward-reading build does with it. One that reads less restrictively is not added as an ignorable key: it goes into the C13 body (where C13's (b) refuses it), or into a closed set an older reader already checks, or the minor takes a §7.1 floor at its first reader.

- **Closes it?** Only by review, minor by minor. Nothing checks the statement. The C13 note rejected this for C13 because §15.8 (b)'s "would refuse" was wrong for seven builds and was found by a probe, not by review (D6's finding 1 on #762).
- **Readers.** No code change; a harmless C4 minor costs nothing after a rollback. That matters more for C4 than for C13, since C4 restamps every event (§1.4).
- **The sensor.** None. The sensor writes the C13 body; the node writes the C4 envelope.
- **Tests.** Per minor, D6's old-reader leg with the previous release as reader: `ObservationFromEvent` over each new envelope key's event, asserting refusal or a stated harmless drop. *Control:* a key stated as refused, read by a reader patched to drop it, fails the leg. It proves each minor's statement, not that the next minor has one.
- **Floors and AP-10.** None of its own; a minor that cannot be made harmless takes a floor held by `docs/release.md` until AP-10 exists.
- **When.** A text rule in C4 and a line in `docs/release.md` §7.2's "Rules that will add rows", before the next C4 minor is approved.

### (b) `ObservationFromEvent` refuses a later C4 minor

`ObservationFromEvent` refuses a `network-observation` event whose `schema` is a later C4 minor than the reader's own, after its `kind` check and before `DecodeStored`. `event.Decode` is unchanged, so SER, Syslog, health and alert events keep their forward read (`docs/release.md` §7.2, the C4 0.4 row).

- **The refusal.** A `*netobs.Error` with `Code: CodeSchema` and `Field: "schema"` (the event's, against `"netobs.schema"` for the body), for which `errors.Is(err, netobs.ErrLaterMinor)` holds: the same sentinel as C13's (b), so D5's `later-minor` reason counts both, and the detail says which stamp was later. The comparison is with C4's own minor taken from `event.Identifier`, not with C13's `self`. A later C4 event with an unknown envelope key is refused as `schema` too, because `event.Decode` has already read it forward.
- **Closes it?** Yes, in code, for every build that carries it and every later C4 minor, with no per-key review: a later envelope is never judged with a key dropped or a flag misunderstood.
- **Readers.** After a rollback across any C4 minor, every network observation of the newer C4 minor still to be judged is refused, even when that minor changed only `sensor.counters`, as 0.4 and 0.5 did. That is the cost of `Identifier` being one constant. It falls on the same replay window as the fail-open and as C13's (b) (§1.4); held records are outside it. A refused first sight drops out of `rebuildFrameIndex`, and an alert citing its frames counts them under `frames_missing`, as under C13's (b). Refused is still unjudged, so (b) needs the same condition as C13's (b): D5's durable, alarmed refusal (`network-observation-refused`, D1's 7001264083 item 4) lands with it or before it.
- **The sensor.** None.
- **Tests.**
  - Contract (`contracts/netobs`, D4): a `network-observation` event stamped one C4 minor above `event.Identifier`'s, computed from it and not written as `0.6` (self-check item 11), with a body at C13's `self` and no unknown key, is refused as `schema` with `ErrLaterMinor`. *Mutant:* the refusal removed, which accepts it. The same event with an unknown key at the top level and in `source.asset` is refused as `schema`, not `decode`. *Control:* the same event at `event.Identifier` is accepted. *Mutant:* the comparison made `>=`, which refuses the control. *Mutant:* the comparison made against C13's `self` instead of C4's, which refuses the control while C4's minor is above C13's (0.5 against 0.3 today).
  - Placement controls (D4): a SER, a Syslog and a `netobs.alert` event one C4 minor later still pass `event.Decode`, and the alert still passes `AlertFromEvent`. *Mutant:* the refusal moved into `event.Decode` or `Event.Validate`, which refuses them; `TestCCD2ForwardE47` and `TestCCD0E47StoredEvents` (`tests/contract`, D6's) would fail too.
  - Node (D5): a replayed observation of a later C4 minor is refused, counted under `later-minor` and alarmed once, and the count survives a restart. *Control:* the same event at the node's own minor is judged. Link (D5): a held record released by the build is stamped `event.Identifier` and judged, which shows held records are outside the cost.
  - Old-reader leg (D6): the commit that lands (b) as reader R3 reads a head `network-observation` event restamped to R3's C4 minor + 1 and refuses it as `schema`; *control:* at R3's own minor it is accepted; the leg's own control is R3 with the refusal removed, which must fail.
  - **Tests that change: none known.** No test on `main` passes a `network-observation` event of a later C4 minor through `ObservationFromEvent` or `observationOf`. The `git grep` of `otsec.event/0.[6-9]` in `_test.go` files finds SER, health, `sensor.counters` and store tests, which go through `event.Decode` or the store only; `TestCCD2ForwardR3Observation` calls `ObservationFromEvent` on 0.4 events, below C4's 0.5. The implementer re-checks this when writing the code.
- **Floors and AP-10.** (b)'s merge commit becomes a `docs/release.md` §7.1 floor for a node that has stored a `network-observation` event of a C4 minor above the one current at that commit: every build below it reads such an event forward. If it lands in the same commit as C13's (b), it is the same floor, with this condition added to that row. AP-10's floor must be at least that commit, as for C13's (b). (b) is checked by the older build after a downgrade; AP-10 by the newer build before one. They complement each other, and (b) does not replace AP-10.
- **When.** Before the next C4 minor is approved, before P4-4-DE, and in every case before the first release. Best in the same change as C13's (b) code, which edits the same function's path and needs the same D5 condition.

### (c) (b) with a per-kind stamp

As (b), but the node stamps a `network-observation` event with the C4 minor that last changed that kind's envelope (a constant in `contracts/event`, 0.3 today), not with `Identifier`. A C4 minor that leaves the kind alone does not move its stamp, so a rollback across it refuses nothing.

- **Closes it?** Yes, as (b), for the stamp's moves. If a minor adds an envelope key and forgets the stamp, an older build at or above the stamp reads the event strictly and refuses the unknown key as `decode`, so a forgotten key fails closed. A forgotten new flag value or a changed meaning fails open, as under (a).
- **Readers.** Refuses only after a rollback across a minor that changed the kind. That precision saves records only inside the same replay window (b) refuses.
- **Costs elsewhere.** C4's rule that every event this code stamps says the current minor (`doc.go`) changes to one stamp per kind; C6 forwards a `network-observation` event with an older `ev` than the node's other events, which receivers and D6's C6 tests must accept; `Link.record` and the store's commit check change (D5's); the per-kind constant is a per-minor judgement made in code, like (d) in the C13 note.
- **Tests.** (b)'s, plus: a `network-observation` event is stamped with the kind's minor; *mutant:* stamped with `Identifier`. A contract test that a `network-observation` event the node builds decodes strictly at the kind's minor: it needs the earlier minor's type, so it is D6's old-reader leg, not a unit test.
- **Floors and AP-10.** As (b), but the floor applies only from the first minor that moves the kind's stamp.
- **When.** As (b).

### (d) A floor only

Each C4 minor that changes the `network-observation` envelope takes a `docs/release.md` §7.1 floor at its first reader, and nothing changes in code.

- **Closes it?** Only while the floor holds, and the floor holds only by the release record until AP-10 is built (`docs/release.md` §7.3). Which minors need one is (a)'s judgement.
- **Readers.** No cost.
- **Tests.** (a)'s per minor, plus the release record's ancestry check (§7.3).
- **When.** At each such minor. It adds nothing that (a) with its floor clause does not already have.

### Not an option: all of C4 strict

Making `event.Decode` refuse every later minor would refuse SER and Syslog after a rollback across any C4 minor; `docs/release.md` §7.2's C4 0.4 row depends on their forward read, and so does C6's receiver rule. It is listed only so that (b)'s placement control has a named mutant.

## 3. Recommendation: (b), with C13's (b)

- **Why (b).** It closes the latent fail-open in code for every later C4 minor, without a per-key review, with one comparison in a function D4 drafts, and it reuses C13's (b) sentinel, D5's reason and alarm, and the old-reader leg. It refuses nothing that SER, Syslog or alerts read.
- **Its cost, stated plainly.** Because `Identifier` is one constant, a rollback across any C4 minor, including one that changes only `sensor.counters`, refuses the replay window's network observations, refused and alarmed. That is the same window and the same kind of loss C13's (b) accepts, and held records are outside it.
- **Not (c):** its precision saves records only inside that window, at the cost of a per-kind stamp in C4 and C6 and a per-minor judgement in code. If a later C4 minor's rollback cost proves too high, (c) can be added on top of (b) without undoing it.
- **Not (a) or (d) alone:** nothing checks them.
- **Its conditions.**
  1. D5's durable, alarmed refusal lands with it or before it (C13's (b) condition 1).
  2. C4's text states that a `network-observation` event of a later C4 minor is refused at judging, and C13's text states it beside the stored observation's strictness; the change goes through D1, reviewed by D5, D6 and D3. D2 reviews if C6's `ev` handling is touched (it is not under (b)).
  3. `docs/release.md` §7.1: the floor of §2 (b), merged into C13's (b) row if the two land together; §7.2's "Rules that will add rows" gains: a later C4 minor states its rollback cost for `network-observation` as "refused, alarmed".
  4. Timing as §2 (b): before the next C4 minor is approved, before P4-4-DE, before the first release.
- **Residual under (b):** the hand install of a build below it; AP-10, still owed before the first release.

## 4. What each owner owes

| Owner | What | By |
| --- | --- | --- |
| D4 | C4 and C13 text (condition 2), through D1 | DE, and before the next C4 minor |
| D4 | The refusal in `ObservationFromEvent` and §2 (b)'s contract and placement tests, in the same change as C13's (b) code | DE |
| D5 | The node and link tests of §2 (b); `later-minor` covers the C4 refusal | with (b)'s code |
| D6 | The old-reader leg's C4 case at R3 | with (b)'s code |
| D7 | §7.1 floor row and §7.2 rule (condition 3) | after the approved change merges; release |
| D1 | Records the ruling in the decision log | at the ruling |
