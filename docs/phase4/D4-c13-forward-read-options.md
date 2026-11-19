# C13: how a build reads a later minor's stored record (options)

**Status: proposed, not approved.** Owner D4. This is the open item of D1's ruling 7001264083 on #760, item 3 (to be recorded in D4-120): options before the next C13 minor and before P4-4-DE, under D4-99 (a new mechanism is settled as options first). No code is changed here.

**Evidence class: `desk`.** Read at `main` `2dde13b6`. The forward-read results cited are D4's probe (7001201557 on #760) and D6's (7001254947 on #760, 7001107395 on #762), both scratch tests on the owner's PC that were not committed. Nothing in this note was run.

## 1. The problem

- **What reads forward.** Two of C13's stored forms are read forward when their minor is later than the reader's own:
  - stored observations, by `DecodeStored` (`contracts/netobs/observation.go`; `storedSchema` sets `c.later`);
  - network baselines (`otsec.netbaseline/`), by `DecodeBaseline` (`contracts/netobs/baseline.go`), which the detector, the learner's restore and `modules/security/netack` call.

  Both use `strictjson.Forward`, which drops a key the reader does not know. That is by design: contracts/README.md ("Readers accept every minor of their own major and ignore fields they do not know"; D1-9, D1-10), and C13 0.2's CH-35 ("forward for a later one").
- **What does not.** Both network checkpoints decode strictly at every minor (`DecodeLearnerCheckpoint`, `DecodeDetectorCheckpoint`), and a detector checkpoint of a minor the node cannot read goes through CH-35's bridge items 1 and 2. A stored alert of a later minor is read through bridge items 3 and 4 (`AlertFromHealth`); an alert records a judgement already made and is not judged again, so it is outside this note.
- **The fail-open.** A later minor that adds a key whose absence reads less restrictively (a key a rule, the learner or a coverage check depends on) is dropped without a word by every build below it, and the record is judged as if the key were not there. §15 of the C13 0.3 proposal showed the case: at `26545062`, a 0.3 record's `objects_unread` and `inner_vlans` are dropped (D6's finding 1 on #762). The same probe shows a record stamped **0.4** read forward with both keys dropped at `2dde13b6` and at `26545062` (D4's 7001201557), and at #760's head `57048382` (D6's 7001254947). So #760 and every build after it does the same to the next minor's keys (D3's 7001225871 condition 2; D6's 7001254947 point 4).
- **Where it bites (read from code, not measured).**
  - **Observations:** the stored observations a build judges after a rollback: those after the detector's restored `Through`, replayed by `observeTo` (`platform/node/netdetector.go`), and the stored-capture lookup that also calls `observationOf`. Records the newer build judged before it stopped are not judged again. How many a real rollback leaves unjudged depends on how the newer build stopped, and is not measured.
  - **Baselines:** an approved baseline of a later `netbaseline` minor is read for the whole time the older build runs. A dropped key that widens what the baseline allows would loosen it for that whole time; a dropped key that adds allowed entries would only add alerts.
- **Which builds.** Every build on `main` today reads forward. None has been released (`docs/release.md` §7.3, §7.4), so no released build carries the fail-open yet. Any mechanism in a build protects only from that build on: a build cannot refuse on a check it does not carry (D3's 7001225871). So whichever option is chosen must be in **every released build**, which means it lands before the first release.
- **What no option here stops.** A hand install of an old commit, which AP-10's signed floor does not stop either (D3's 7001225871; D6's 7001254947 point 3). That residual is named in each option's row as "the hand install".
- **Not covered here.** C4's `event.Decode` reads a later C4 minor forward too (`contracts/event/decode.go`). The detector reads `source.asset` and `flags` from the event (`ObservationFromEvent`); a new flag value is kept, a new top-level C4 key would be dropped. No C4 key the detector depends on is proposed. If one is, the same question is owed for C4 (D4 owns C4).

## 2. The options

Each option is answered on the same five points: does it close the fail-open for records written by a newer build; what it costs readers; what it costs the sensor; which tests prove it; when it must land.

### (a) A per-key statement in each later minor

Each C13 minor states, key by key and value by value, what a forward-reading build does with it (drops the key; refuses a new value in a closed set, as it refused `sa: unknown`) and whether the record then reads less restrictively. A key that does is not added as an ignorable key: it is carried in a form every reader in the rollback set refuses (a new value of a closed set the older reader already checks, or a new major), or the minor takes a `docs/release.md` §7.1 floor at its first strict reader.

- **Closes it?** Only by review, minor by minor. Nothing in code checks the statement. §15.8 (b)'s "would refuse" was wrong for seven builds and was found by D6's probe, not by review (D6's finding 1 on #762), so this is exactly the mistake the option relies on people not making. A floor taken under it holds only by the release record until AP-10 is built (§7.3).
- **Readers.** No code change. A harmless key stays harmless after a rollback (CH-35's purpose).
- **The sensor.** None. Which keys the sensor emits is fixed by the minor.
- **Tests.** Per minor, an old-reader leg (the shape of D6's leg in 7001264083 item 7): the previous release's `DecodeStored` over each new key's record, asserting refusal or a stated harmless drop. It proves each minor's statement, not that the next minor will have one.
- **When.** A text rule in C13, before the next minor is approved. It costs every later minor a review that §7.2's "Rules that will add rows" already partly asks for.

### (b) `DecodeStored` and `DecodeBaseline` refuse any later minor

C13's stored observation and `netbaseline` declare themselves strict, as contracts/README.md allows ("A contract may declare itself strict"; C7's requests are). A record of a minor above the reader's own is refused as `schema`; earlier minors are read strictly, as now. The precedent is D4-61: the node refuses an `otsec.finding/` minor that `finding.Known` does not name, per asset, with an alarm.

- **Closes it?** Yes, for every build that carries it and every later minor, with no per-key review: a later record is refused, never judged with keys missing. Refused is still unjudged (D3's F1 on #762): without D5's open item (D1's 7001264083 item 4, a durable, alarmed refusal) a refusal shows only as the in-memory `observations_refused`, which breaks P5. **So (b) needs that item to land with it or before it.**
- **Readers.**
  - After a rollback across a C13 minor, every stored observation of the newer minor still to be judged is refused, harmless keys or not. It is the same set the fail-open reaches (§1), so the loss is bounded by the same window.
  - After a rollback across a `netbaseline` minor, the approved baseline is refused: `NewDetector` fails and `startDetector` returns the error. What the node shows then is not traced in this note; D5 states it. Detection on that node stops until a baseline the older build reads is approved. `netbaseline` is its own identifier (0.1 today), so this happens only when the baseline form changes, not at every C13 minor.
  - It reverses CH-35's "forward for a later one" for these two forms. Bridge item 4 (an unknown `coverage.degraded` value read as degraded) then no longer reaches a stored observation; it stays for alerts.
- **The sensor.** None. The channel is strict already: a sensor whose minor the node does not list fails the hello (`channelIdentifiers`), and its records wait in its buffer (CH-20). The upgrade order in §7.2 (node first, sensor second) is unchanged.
- **Tests.**
  - Contract (`contracts/netobs`): a stored observation stamped one minor above `self`, with no unknown key, is refused as `schema`; the same record at `self` is accepted. The minor is computed from `self`, not written as `0.4`, so the test does not break at the next minor (self-check item 11). *Mutant:* the forward branch restored, which accepts it. The same pair for `DecodeBaseline` over `baselineSelf`.
  - Node (D5's): a replayed later-minor observation is refused, counted and raises the alarm of D5's open item; *control:* the refusal not alarmed.
  - Tests that assert the forward read today change, each reviewed by its owner: `TestStoredRoundTrip`, `TestFlowEnd03Minors` and `TestBridgeUnknownDegraded`'s stored leg (`contracts/netobs`); `TestDetectorBridgeLaterRecords` (D5's, `platform/node/netbridge_test.go`); `TestC13v02R2StoredReader` (D6's, `tests/contract`). `TestBaselineCanonical`'s "another minor" case is unaffected: it reads `IsCanonical`, which decodes with `strictjson.Decode` and does not pin the minor, not `DecodeBaseline`. D4 changing another role's test needs D1's authorization under CLAUDE.md §5.3, as for #755 (D4-119 item 2.7).
  - From the first release on, D6's old-reader leg with the previous release as the reader proves each later minor is refused there.
- **When.** Before the next C13 minor is approved, so its §7.1 row states "refused, alarmed" as the rollback cost, and before P4-4-DE (D1's item 3). In any case before the first release.

### (c) A node-side floor stamped in the store

The node writes a key in the store's `meta` table (for example the lowest C13 minor a reader needs), in the same transaction as the first record that needs it. At start, the network detector compares the stamp with its own `self`, and if the stamp is higher it does not restore or judge, and raises an alarm; collection and SER forwarding go on, as under D4-61.

- **Closes it?** Yes, for builds that carry the check. An older build ignores an unknown `meta` key: at `2dde13b6` the store compares only `format`, `node_id` and `database` (`platform/store/db.go`). Bumping the store's `format` instead would refuse the whole store, SER included, which is too broad.
- **How it relates to AP-10.** AP-10 is checked by the newer build, against an update package, before the downgrade is installed; it needs a signed release and an updater, neither designed (§7.3). (c) is checked by the older build, from the data, after the downgrade, and also covers a hand install of any build that carries it. They complement each other. Neither binds a build that predates it.
- **Readers.** Coarser than (b): a stamp turns off all judging on the node, not only the later records. A stamp has to be cleared when no record needing it remains, which needs retention to be tracked, or it stays until an operator acts. It adds a writer duty and a transactional ordering in `platform/` (D5's code).
- **The sensor.** None.
- **Tests.** Store and node (D5's): a stamp above `self` leaves the detector off with the alarm while SER continues; *control:* an equal stamp starts it. A crash test between the stamp and the first record shows that neither commits without the other.
- **When.** Before the first release, and before the first writer that needs the stamp.

### (d) A per-record reader floor

The writer marks only the records that need it: a stored key, for example the lowest minor that may read the record forward, set by the node when the record carries a key whose absence reads less restrictively. A reader that carries the check refuses a record whose floor is above its own minor and reads every other later record forward.

- **Closes it?** Yes, for builds that carry the check, and only for keys the writer is told to mark. Which keys need marking is (a)'s per-key judgement, made once in code instead of once in text, with the same chance of being wrong.
- **Readers.** Refuses only what matters, so harmless keys survive a rollback. That precision saves records only inside the same small window (b) refuses (§1).
- **The sensor.** None, if the node sets the floor at intake.
- **Tests.** Contract: a later record with a floor above `self` is refused, the same record without the floor is read forward; *mutant:* the floor ignored. Plus (a)'s per-minor leg for each marked key.
- **When.** Before the first release, and the reader check before the first minor that sets the floor.

### (e) A new major for each such change

A change that adds a key the detector depends on is a new major (C13 1.0). Every build on `main` refuses another major already (`self.Accepts` in `storedSchema`), so this binds today's builds too, the seven forward-reading ones included (D4's probe: a 1.0 record is refused at `2dde13b6` and `26545062`).

- **Closes it?** Yes, by refusal, for every build. Refused is still unjudged (D3's F1), so it needs D5's open item as (b) does.
- **Readers.** A major across every netobs reader: alerts, checkpoints, the bridge, the 0.2 alert stamp and C4's `netobs` path, with a migration note and every consumer's review (contracts/README.md). D4's option (c) in 7001201557 costed it as the largest change.
- **The sensor.** A new major on the channel and a new hello.
- **Tests.** Every netobs test at the new major; the old-reader leg refuses it.
- **When.** At each such change. Its only advantage over (b) is binding builds that were never released.

## 3. Recommendation: (b), with D5's open item

- **Why (b).** It is the only option that closes the fail-open in code, for every later minor, without relying on a per-key judgement that has already been wrong once (§15.8 (b)). The change is small: `storedSchema` refuses a later minor, `DecodeStored`'s forward branch goes, and `DecodeBaseline` does the same. The project already chose refusal over forward reading for a form whose loss misjudges (D4-61). Its cost, refusing harmless keys after a rollback, falls on the same replay window as the fail-open (§1).
- **Its conditions.**
  1. **D5's open item (7001264083 item 4) lands with it or before it,** so a refused stored record is durable and alarmed, not only an in-memory count (P5).
  2. **C13's text declares the stored observation and `netbaseline` strict,** and states that CH-35's forward read for these two forms is superseded; the change goes through D1 as a contract change, reviewed by D5, D6 and D3.
  3. **D5 states what the node shows when the detector cannot start on a refused baseline** (§2 (b), "Readers"). If it is not an alarm, that is fixed in the same change.
  4. **Each later minor's §7.1 row still states its rollback cost** (§7.2, "Rules that will add rows"): under (b) that cost is "refused, alarmed", not a fail-open.
  5. **Timing:** before the next C13 minor is approved, before P4-4-DE (D1's item 3), and in every case before the first release.
- **Not (a)** alone: nothing checks it. **Not (c):** coarser, more machinery in `platform/`, and no record here lacks its own schema stamp, which is what a store stamp would add. **Not (d):** its precision saves records only inside the window (b) refuses, at the cost of (a)'s judgement in code. **Not (e):** a major at each such change, to bind builds that were never released.
- **Residual under (b):** the hand install of a build below it, as under every option; and AP-10 is still owed before the first release (D1's 7001264083 item 2).
