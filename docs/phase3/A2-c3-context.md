# C3 0.2 context reads and SEL-751 register revision 4 (A2, P3-A2)

**Status:** contract change, approved in principle by A1 as D3-2 (`docs/phase3/A1-decisions.md`, #148). Desk evidence only: Go tests on a CI runner. No relay was contacted.

## Why

P3-A2 has the SEL-751 adapter read `DATE_F` with `SHO G` before `SER`, so that A4's normalizer reads the SER's dates in the relay's own order instead of assuming MDY. `SHO G` has been in the register since revision 1 (A1, 2026-10-23), but nothing in C3 tied it to `SER`. `CheckLines` permits an operate line only if it is the invocation's operation or the read of a precondition, posture warning or firmware condition, so a `SHO G` in a `SER` run was refused (`TestCheckLinesRefuses`, "read not needed"). A precondition would be the wrong tool: `DATE_F` refuses nothing, and every one of its three values is fine.

## The format change

`Package.context` is a list of context reads, new in `otsec.register/0.2`:

| Field | Meaning |
| --- | --- |
| `id` | an entry ID, unique across the package |
| `setting` | the device setting, e.g. `DATE_F` |
| `read_by` | the operation that reads it, e.g. `sel.settings.show_global` |
| `for` | the operations whose output needs it, e.g. `sel.ser.read_all` |
| `values` | the values the consumer understands, e.g. `MDY`, `YMD`, `DMY` |
| `reason` | why, with citations |

A context read refuses nothing and adds no line to the allowlist. It does one thing: `CheckLines` permits its `read_by` line in a run of an operation in `for`, and in no other run. A `SHO G` in a run of `SHO P 1` is still refused.

`Package.Validate` enforces A1's D3-2 conditions:

- `read_by` is an operation of the same package (so read-only, since only read-only lines are operations) and runs in `operate`;
- its access level is the same as or lower than that of every operation in `for`; levels are compared as numbers, and a level that is not a number (C) is compared only for equality;
- `for` names other operations, each once, and never `read_by` itself;
- `setting` is a setting name, `values` are `[A-Z0-9]+` and distinct, `reason` is not empty;
- a 0.1 package that carries `context` is invalid.

The other two conditions are behaviour, written into the doc comment and checked in the adapter PR: the context line counts against the run's line and rate limits, and it is kept in the raw capture like any other line.

## Versions and upgrade

- This reader decodes 0.1 and 0.2 packages. A later minor is invalid, since C3 readers are strict. A node that has not been upgraded therefore refuses a 0.2 package, raises the SC-18 alarm, and keeps the floor and package it has (fail closed).
- `SigningDomain` stays `"otsec.register/0.1 package\n"` in every minor. It is a domain-separation tag, not a version, and the payload names its own contract inside the signed bytes. A signature made over a 0.1 package is unchanged.
- The envelope's `contract` is the reader's own identifier, now `otsec.register/0.2`, and `authz.VerifyRegisterPackage` is unchanged: it compares the envelope's contract with `register.ContractID`. **Release note:** after an upgrade, a collector configured with a register envelope stamped `otsec.register/0.1` rejects it with the SC-18 alarm until the envelope is re-stamped `0.2`. The payload and signature stay as they are; no new signature is needed. Accepting both envelope stamps would be a one-line change in C7, and is A3's call; I left C7 alone.

## SEL-751 content, revision 4

Built by `contracts/register/testdata/build_sel751.py` (`rev4`), which also writes revision 3 to `sel-751-rev3.json` on the way, byte-identical to the revision 3 that was on `main`.

- Contract `otsec.register/0.2`, revision 4, issued 2026-10-26.
- `ctx.date_f`: `DATE_F`, read by `sel.settings.show_global`, for `sel.ser.read_all`, values `MDY`, `YMD`, `DMY`. Both operations are Level 1.
- Citation fix: `SHO G` cited "Table 4.90 p.4.230 (UTC_OFF, DST_BEGM..DST_ENDH, DATE_F)". `DATE_F` is in S22 Table 4.84 (General Global Settings) p. 4.225, with its explanation on p. 4.226; Table 4.90 is Time and Date Management Settings and holds `UTC_OFF` and the DST settings only. The Table 4.90 reference now lists those, and a Table 4.84 reference is added.
- Evidence for what `DATE_F` governs: S22 p. 4.226 ("change the relay date presentation format") and p. 7.31, which says it for the date of a command response. That the SER rows follow the same setting is **inferred**, not stated, and the reason says so.
- Nothing else changes: lines, session lines, deny rules, preconditions, warnings and the firmware allowlist are revision 3's (`TestContentRev4`), so the deny-corpus result is the same, and `TestContentAllowlistUnchanged` re-runs A6's corpora on revision 4.

## Files outside C3 that move with revision 4

The node names `register_version` in every run request and the collector refuses another revision, so the fixtures that pin revision 3 move to 4. Each owner is asked to confirm their file:

| File | Owner | Change |
| --- | --- | --- |
| `contracts/adapter/lines.go` | A2 (C2); A3 reviews | `CheckLines` honours context reads |
| `contracts/adapter/lines_test.go` | A2 | "read not needed" uses `ID`; `TestCheckLinesContext` adds A6's case |
| `contracts/adapter/testdata/generate.py` and the regenerated results | A2 | `REGISTER_REVISION = 4`; only `register_version` changes in each golden |
| `contracts/authz/sel751_register_test.go` | A3 | revision 3 is read from `sel-751-rev3.json`; new `TestSEL751Rev4SupersedesRev3` |
| `platform/node/nodeconfigtest/nodeconfigtest.go` | A5 | `RegisterVersion: 4` |
| `tests/safety/windows_installer/node.template.json` | A6 | `"register_version": 4` (its test says it follows the register on `main`) |

The collector's own register copies (`modules/security/collector/testdata/`, `modules/security/collectorclient/testdata/`, `cmd/otsec-collector/testdata/`) stay revision 3, 0.1, and still decode.

## Tests

`TestContext` (18 refusal cases and `ContextFor`), `TestContentRev4`, `TestCheckLinesContext` (a `SHO G` in a `SER` run is permitted; with the context moved to `SHO P 1`, the same line is refused), `TestSEL751Rev4SupersedesRev3`, and the JSON schema accepts revisions 2, 3 and 4 and the Phase 0 package. `go vet`, `gofmt` and `go test ./...` pass locally.
