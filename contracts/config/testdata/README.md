# C9 golden examples

These files are written by `generate.py`; run `python3 -I generate.py` here.

**Nothing here was captured from a device.**

- Every transcript is constructed, and every snapshot has `target` `simulated`.
- The setting lines are copied from S22's printed examples and settings tables. `generate.py`'s docstring lists the source of each class.
- The invocation IDs and times are invented.
- The session framing, the prompts and the header follow C2's `generate.py`, and carry its assumptions (H-13).

`generate.py` reads the replies with its own Python version of the rule in `doc.go`. The Go tests then check that each snapshot is exactly what Go's `CheckAgainst` reads from its transcript, and that each golden difference is exactly what Go's `Compare` computes. That way two implementations of the rule are checked against each other.

Coverage: a snapshot holds what `SHO` prints. The touchscreen display settings (S22 Table 7.80) are not read, by the owner's decision of 2026-10-28, so nothing here claims full coverage of a touchscreen model.

## Transcripts

| File | What it shows |
| --- | --- |
| `transcripts/read-1.json` | A config.read session: the probe, `ID`, `ACC` with the credential redacted, all 24 SHO forms of S22 Table 7.67, then `QUI`. Ports 2 to 4, Modbus, IEC 60870-5-103, EtherNet/IP and DNP maps 2 and 3 answer `Invalid Command`. |
| `transcripts/read-2.json` | ASSUMED layouts, not documented for `SHO`: the same configuration printed differently: a header with another time before the settings of `SHO 1` and of `SHO 2`, `SHO 3` one setting per line with `TR` wrapped, `CTRN` before `CTR` in `SHO 4`, and `ER` wrapped at other columns in `SHO R`. |
| `transcripts/read-3.json` | Read 1 with four changes: 50P1P changed from 10.00 to 9.50, LL removed from group 1, Port 2 present, and DNP map 1 answering `Invalid Command`. |

## Valid

| File | What it shows |
| --- | --- |
| `valid/snapshot-read-1.json` | The snapshot of read 1. Each section has its span and SHA-256 in the transcript; port sections are marked sensitive, and absent sections carry no settings. |
| `valid/snapshot-read-2.json` | The snapshot of read 2: the same settings as read 1, with different section hashes. |
| `valid/snapshot-read-3.json` | The snapshot of read 3. |
| `valid/difference-1-2.json` | Read 1 to read 2: no changes. The header's time, columns, order and wrapping are not semantic (P4-A2's acceptance case). |
| `valid/difference-1-3.json` | Read 1 to read 3: one changed, one removed, Port 2 appeared with its settings added, and DNP map 1 disappeared with its settings removed. |
| `valid/later-minor-snapshot.json` | A 0.3 snapshot with a field 0.2 does not know: a 0.2 reader accepts it and ignores the field. |

## Invalid

| File | What it shows |
| --- | --- |
| `invalid/snapshot-missing-class.json` | A snapshot holds every class of its rule; one with 23 of 24 is refused. |
| `invalid/snapshot-classes-out-of-order.json` | Sections follow the rule's order. |
| `invalid/snapshot-required-class-absent.json` | Group 1 is standard and cannot be absent. |
| `invalid/snapshot-absent-with-settings.json` | An absent section carries no settings. |
| `invalid/snapshot-present-without-settings.json` | A present section with no settings is a read that failed, not a snapshot. |
| `invalid/snapshot-port-not-sensitive.json` | Port sections are sensitive under the rule; one marked otherwise is refused. |
| `invalid/snapshot-unknown-rule.json` | A rule this minor does not know is refused, because no difference can be computed under it. |
| `invalid/snapshot-setting-twice.json` | A setting name printed twice in one section is refused. |
| `invalid/snapshot-value-two-spaces.json` | Two spaces end a value, so no value holds them. |
| `invalid/snapshot-value-holds-assign.json` | No value holds `:=`. |
| `invalid/snapshot-ref-not-transcript.json` | The transcript ref is `sha256:` plus the transcript's SHA-256, and nothing else. |
| `invalid/snapshot-other-major.json` | Another major version is refused. |
| `invalid/snapshot-unknown-field-in-own-minor.json` | An unknown field in a 0.2 document is a writer bug and is refused. |
| `invalid/snapshot-wrong-kind.json` | A snapshot's kind is `config.snapshot`. |
| `invalid/snapshot-without-register-version.json` | The register package that permitted the lines is required. |
| `invalid/snapshot-target-documented.json` | The target is `device-observed` or `simulated`, as in C2. |
| `invalid/snapshot-sections-overlap.json` | Sections are in the order the run read them, so a span never starts before the end of the one before it. |
| `invalid/difference-changed-equal-values.json` | A changed setting has two different values. |
| `invalid/difference-added-with-from.json` | An added setting has no `from` value. |
| `invalid/difference-out-of-order.json` | Changes follow the rule's class order, then names in byte order. |
| `invalid/difference-required-section-appeared.json` | A class that cannot be absent cannot appear or disappear. |
| `invalid/difference-without-changes.json` | `changes` is required; an empty list is how no change is said. |
| `invalid/difference-digest-without-prefix.json` | A snapshot digest is `sha256:<hex>`. |
| `invalid/difference-sensitive-unmarked.json` | A change in a port section carries the port's sensitive mark. |
