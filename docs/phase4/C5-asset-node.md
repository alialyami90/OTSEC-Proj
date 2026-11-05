# The node's side of item 3: the asset module and R9 (P4-3-A5)

C5, 2026-11-05. This is the design note for brief P4-3-A5 (`docs/agent-handoffs.md`, "Phase 4 item 3: Stage A briefs", D4-48). It is a desk design. Nothing in it is built or measured. It depends on three drafts that are not written yet: C2's C1 0.3 (identity attributes with a source) and C3 0.4 (the SNMP read operation), C3's C11 (the advisory set), and C4's C12 (the finding). Where this note assumes something about them, it says so, and the "Questions" section lists each assumption for its owner.

**No store contract change is made here.** What the design needs from C5 is listed under "What C5 0.8 would need". That list becomes its own proposal once C1, C11 and C12 settle, as the brief requires.

## What the node owns, and what it does not

- **`modules/asset/`** is C2's (R1.8, P4-3-A2). It defines the SNMP read operations and how the identity attributes are read. The SNMP adapter runs in the collector, as the SEL-751 adapter does.
- **The matcher** is C4's (C12, P4-3-A4). It is a pure function from the identity records and the set to findings. It has no clock, store or network.
- **The node** decides what runs and when. It schedules SNMP polls through the collector, as it schedules SER today. It stores identity records, the advisory set and findings, replaces the set atomically, runs the matcher, and reports health. This note covers that part.

Device contact stays where it is today. The node sends a signed invocation to the collector. The collector holds the credentials (C7) and opens the session. That includes SNMPv3 USM keys, which this design keeps in the collector and never in the node (Questions, item 2). R9 code in the node gets no `Collector` and no network handle. It reads only stored records, so it cannot probe a device (R9.4).

## 1. Enabling and disabling each one, independently

**The switches.** These are two top-level node config sections, and an absent section means the feature is disabled. This follows the pattern `event_baselines` set: no section, no work.

- `asset` turns on the asset module's side of the node. It has no required fields at first. Its only field would be the per-family SNMP defaults if C3 0.4 needs any.
- `applicability` turns on R9. Its fields are the advisory set's verification key (the public key C11 names, pinned here as the register's anchor is pinned), and the set's file name in `admin_dir`.

**What each one owns, and so what does not happen when it is off:**

| | `asset` off | `applicability` off |
| --- | --- | --- |
| Schedule entries | A schedule entry with an SNMP operation (C3 0.4's operation IDs) is refused at load, with the reason. Nothing is ignored silently. | Unchanged. |
| Identity records | None are written. SER runs are unchanged: the adapter's own identity check against the declared identity (AP-27, `refused.identity_mismatch`) is C2's and stays on. | Written as usual (asset on). |
| Advisory set | — | `admin_dir` is not scanned for the set file. A file that is there is neither read nor reported. |
| Matcher, findings | — | Nothing runs, and no finding is written. |
| Layout and quota | No identity series, and no addition to the configuration floor. | No `advisory` stream, and no addition to the floor. |
| Status and health | No `identity` lines. | No `applicability` section and no R9 alarm. |
| Goroutines and timers | None added. | None added. |

**`applicability` needs `asset`.** Findings are computed from identity records, and only the asset module writes them. A config with `applicability` and no `asset` is refused at load, with the reason. The four combinations are then:
- both off, which is today's node;
- `asset` alone;
- both on;
- `applicability` alone, which is refused.

This is the reading I propose for "independently". It is Questions, item 1, for C1.

**Turning one off later.** Stored identity records, sets and findings stay where they are. Nothing deletes or rewrites them, and they still count against the configuration quota. Turning the switch on again resumes from them: the newest set in use, then the matcher over the newest identity of each asset.

**How the paired runs see it.** V-M1 (a) needs "`asset` disabled: GT-MIB receives zero PDUs". The load-time refusal gives that on the node's side. It is tested both by config tests and on the binaries. The collector's register gate is a second line, because the collector refuses an operation the node did not schedule.

V-M8 compares two runs with the same schedule, one with `applicability` on and one with it off. R9 adds no schedule entry and no collector request, and it opens no socket. So the device flows must match by construction, and the paired capture tests that. Questions, item 3, covers the one flow difference I expect: the upstream target's RELP flow carries R9's health events.

## 2. Where everything is stored

**The configuration class (C5 0.4) in the configuration database.**

All three are typed documents, not C4 events, and they share the class's properties:
- each record is bounded (`ConfigRecordBytes`, 1.5 MiB);
- validation is strict before storing (`ConfigDocuments`);
- the full action is `stop-collecting`;
- nothing is forwarded, because no Syslog target consumes a configuration stream;
- a record that is still needed is held, and an old one is removed in bounded steps (`RemoveConfig`, D4-32).

A new class would need its own full action and its own quota rules for no gain. Every row below needs a series that C5 0.7's closed table does not have, which is what makes C5 0.8 necessary.

| What | Stream | Written when | Size bound | Proposed series |
| --- | --- | --- | --- | --- |
| Identity record (C1 0.3) | `config/<asset>` | at the asset's first identity, and when any attribute's value or source changes | small: the attributes, plus a capture of only the bytes the observations point to | `identity` (evidence) |
| Advisory set (C11) | `advisory`, a new node-level stream in the configuration database, present only with `applicability` | when a set is accepted | C11 must bound it below the record cap (Questions, item 4) | `advisory.set` (evidence) |
| Finding (C12) | `config/<asset>` | when a finding first appears and when its class changes, never on an unchanged evaluation | small | `finding` (evidence) |

**An identity record carries its own evidence.** For the SEL-751, the attributes come from the `ID` exchange at Level 0 in every collection run. Today the FID, CID and serial number are already in the adapter's `Result.Observations`, each with its span in the transcript, and they need no extra read.

The record's capture is the bytes those spans cover, so the record's evidence ID (its stream and seq) still points at device bytes after `ser/<asset>` is pruned. An SNMP poll's `Result` has the same shape, and its identity takes the same path.

An `operator` identity comes from the asset's declaration in the node config. A `passive` one (R6.7) comes later, through the same writer and with no change here. The writer stores only a change, so a run that reads the same identity stores nothing new.

**What holds what.**
- A finding names its set by digest and its identity records by evidence ID. The set and the identity records stay held while a finding that is the newest for its (asset, advisory) names them.
- The newest record of each series is never removed, as C5 0.7 already rules for every series.
- Older identity records and findings are evidence of a change (V-M7: "records the change"). They are removed only under the D4-32 rule, oldest first, and never while held.

**The quota floor** (D4-20) grows by:
- for each asset with `asset` on, room for the newest identity record and one change;
- for each asset with `applicability` on, room for its findings at the set's bounded advisory count;
- once per node with `applicability` on, two sets at C11's bound: the one in use and the one being installed.

The figures follow from C11's and C1 0.3's bounds once they exist. A configuration quota below the floor is refused at load, as it is today.

## 3. Replacing the set atomically

The administrator writes the signed set file to `admin_dir`. That is the locked, administrator-only directory admin requests already use (D2-12). The node reads it at most once per node tick, bounded by C11's size cap. A set takes one of three paths: refused, installed, or the same set.

**1. Refused.** The node refuses the set when any of these holds:
- the signature fails against the pinned key, or the set is unsigned;
- it does not decode strictly, or it is truncated;
- its version is not above the set in use (an equal version that is not the same set, or an older one);
- an entry has no source;
- an entry is `test-only` and the node is a release build.

On refusal nothing is stored, and the set in use stays in use. The node writes the refusal to the audit chain (C3's C8 addition) with the file's SHA-256 and the reason. It also raises `advisory-set-refused` with the same reason, keyed by the file's hash, so a file left in place is reported once and not at every tick.

If the audit stream cannot take the record, the set is still not installed, and the alarm says the refusal was not recorded. Privileged changes fail closed, as audit does today.

**2. Accepted.** The node appends the file's exact bytes as one configuration record on `advisory`. One commit is atomic: after a crash the record is either there whole or not at all. Then the node writes the audit record of the installation.

A set is in use only once its audit record is in the chain. At start, the node folds the chain. It writes any missing installation record for a stored set, and only then decides which set is in use. This is the order `config.baseline_recorded` already follows (D4-26). The cases split this way:
- a crash before the commit leaves the file in `admin_dir`, and it is tried again;
- a crash between the commit and the audit record is repaired at start;
- a crash after both leaves only the evaluation to run, at the next pass.

**3. The same set again** (same digest). Nothing is done, and nothing is raised.

**The set in use** is the newest `advisory` record whose installation record is in the chain. Its version, date and digest go into every finding written under it, and into status (R9.3).

## 4. Running the matcher

The matcher runs in the scheduler's goroutine between collection runs, with a time budget, as the event-baseline feeder does. A large evaluation therefore cannot delay a collection run.

**When an asset is evaluated:**
- after a new identity record for it is stored;
- after a new set comes into use, when every asset is evaluated;
- at start, for every asset;
- at the interval C4's note sets for evidence currency ("R9 classes and what `confirmed` needs", point 3).

Each evaluation compares the matcher's output with the newest stored finding for each (asset, advisory). It writes only the differences, so evaluations are idempotent across restarts. A reclassification is a new record that names the one it supersedes, never an overwrite (V-M7). With `applicability` off, none of this runs.

## 5. SNMP poll scheduling under the register's limits

An SNMP poll is an ordinary schedule entry: an asset, one of C3 0.4's SNMP operations, and `every_seconds`. The scheduler and the collector need nothing new. Their existing limits already bound it:

- **The node's plan** (`schedule.go`). Each entry is due one interval after its last run began. Each asset also has a quiet window of `MinIntervalSeconds` (60 s) after its last session ended, whichever entry ran it. An asset with both an SNMP poll and another read cannot be read faster than the floor.
- **Load-time checks.** `every_seconds` must be at least 60 s, as for every entry, and at least the asset's C1 `session_limits.min_interval_ms`. I propose the node refuse a slower register or profile limit at load, with the reason, instead of leaving it to a collector refusal at every run.
- **The collector** still refuses a run sooner than `min_interval_ms` (`refused.rate_limited`, `CheckInterval`). The node's plan keeps that from happening in normal operation.
- **The register's operation limits** (C3 0.4): the named OIDs, the number of requests, `max-repetitions` for `GETBULK`, timeouts and the deadline. The adapter in the collector enforces them, so they bound each poll's load on the device. The node only passes the operation ID.
- **Runs are serial.** The node runs its schedule from one goroutine, so it never polls two devices at once. The cost is head-of-line delay: an SNMP poll that times out holds the next run for up to its deadline. Status already shows each asset's last run time, so a lagging schedule is visible. If measured polls show this matters, a later change can bound it. This note does not propose one.

No SNMPv1 or v2c entry is accepted without C3's approval record (V-M1 (d)). The node checks for it at load, from the audit chain, and the collector checks it again at run time. Without it, the entry is refused with the reason.

## 6. Health and status

**Status (`status.json`)** gains sections only when their switch is on:

- **`assets[<id>]`**, as today: the last run's time and code, for an SNMP poll as for SER. With `asset` on it also gains `identity`, which holds:
  - each attribute's value and source;
  - the evidence ID;
  - the time the record was stored.
- **`applicability`**, with `applicability` on. It holds:
  - the set in use: version, date and digest, and when it came into use;
  - the last refusal, if any: the file's hash, the reason, and when;
  - the last evaluation's time;
  - each asset's count of findings by class.

**Alarms and health events,** on `platform/health` and so forwarded:

- **`identity-changed`** (asset): a stored identity differs from the asset's last one, with both evidence IDs. A changed FID or model is a security signal on its own, apart from R9.
- **SNMP run failures** (V-M1 (c)): a refusal of a weaker USM level, a wrong user, wrong keys or a wrong engine ID shows as the run's code in `assets[<id>]`. It also raises the existing collection-failure alarm with that code. The codes are C2's to name, in C3 0.4.
- **`advisory-set-refused`** (R9), as in section 3.
- **`applicability-no-set`** (R9): R9 is on and no set is in use yet. It is raised once, not at every tick.
- **`finding-changed`** (R9): a finding appeared or changed class, with the asset, the advisory and both classes. Its wording follows C12, and no field states exploitability (R9.2).

## What C5 0.8 would need

These are the inputs for a separate proposal, not changes made here:

- **Three evidence series** in `DocumentInfo`'s closed table: `identity`, `finding` and `advisory.set`. `ConfigDocuments` would accept the three documents by their contracts' own validators, in the bytes their encoders write.
- **Holds:** a finding holds its set and its identity records while it is the newest for its (asset, advisory).
- **The `advisory` stream:** a node-level stream in the configuration database. Its name is the node's layout, not a contract matter. The class rules for it are the contract matter.
- **The quota floor terms** in section 2.

## Questions

1. **C1: does "independently" allow `applicability` without `asset`?** I propose refusing that config, since R9 has no identity without the asset module. The other three combinations are each a supported configuration.
2. **C3: where do the SNMPv3 USM keys live?** The brief's threat-model row says "the node key register". This design keeps them in the collector as C7 credentials, like the SEL-751 password, so the node never holds a device secret. If "node key register" means something else, this note changes.
3. **C6 and C1: does V-M8's "same flows" count the RELP flow?** The R9-on run sends `finding-changed` and the set events to the upstream target, on a RELP flow the R9-off run also has, but with more packets on it. I read V-M8's "no flow the other lacks" and "same flows to every device address" as allowing that, because the upstream target is not a device. If it does not, R9's events would go to status only, and R9.1's report would need another path upstream.
4. **C3: will C11 bound a set's size below `ConfigRecordBytes`?** A set has to be one record for the atomic replacement above. If a set can exceed 1.5 MiB, the replacement needs another design, and I would bring that back before any proposal.
5. **C2: are the SEL-751's identity attributes in C1 0.3 exactly the `Observations` the adapter already returns?** Today those are the FID, the CID and the serial number, on an `ok` or `partial` run (`modules/ied/sel751/run.go`). The model and the firmware version would come from the FID string. If C1 0.3 adds an attribute the run does not read today, R9 on the SEL-751 needs a register change, not only node work.
