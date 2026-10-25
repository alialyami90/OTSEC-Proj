# A6 review of #92 (scheduler, read-only CLI, SCM services, installer) at `8362c45`

Reviewer: A6 (P2-A5 reliability and device-safety review). Evidence class: **simulated and desk**, plus a **native Windows run** of the non-admin tests on ALI's PC (Windows 11 Pro 10.0.26200, portable Go 1.26.0, non-elevated shell). The installer has not run anywhere yet. Running it needs administrator rights on ALI's PC, and that waits on ALI's answer. No device is involved: every endpoint is the loopback simulator (D2-4, D2-10).

Verdict: **changes requested**, one must.

## What I ran

- Linux container: #92 is up to date with main. `go vet ./...` and `gofmt -l .` are clean (empty output), and `go test -race -count=1 ./platform/... ./cmd/... ./tests/contract/` passes. The Windows cross-build passes: `GOOS=windows go vet` for `./platform/... ./cmd/...`, and `go test -c` for `platform/store`, `platform/node`, `platform/winsvc` and `cmd/otsec`.
- Windows, native, `go test -count=1 -v ./platform/... ./cmd/...`:
  - platform/node: 21 passed
  - platform/winsvc: 2 passed
  - platform/store: 24 passed, **1 failed**, 2 skipped by design
  - cmd/otsec: 1 passed, **1 failed**
  - `TestDirDACLChecked` passed, including the junction and SDDL cases.
- I read `schedule.go` in full, plus `config.go` (the schedule checks) and `platform/store/reader.go`, and ran a probe of the config loader. The probe is not in the repo.

## Must

**1. The read-only store open fails on Windows, so the CLI's `events`, `assets` and `health` do not work on the production OS.** Both failures come from one cause:

- `TestOpenReadOnly` fails with `reader_test.go:25: SQL logic error: invalid uri authority: C: (1)`.
- `TestReadOnlyCommands` fails with `main_test.go:102: events list: 1  SQL logic error: invalid uri authority: C: (1)`.

`reader.go:35` builds `url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro"}`. On Windows the path is `C:/...`, so the URI comes out as `file://C:/...`, and SQLite reads `C:` as the authority. A Windows path needs a leading slash: `file:///C:/...`. Please prefix `/` when the path has a volume name, and add a test case whose path contains a space. The owner's OTSEC folder has one ("AI Apps"), and `%20` decoding should be shown to work. This is exactly the kind of fault D2-8 said the Linux-only runs would miss.

## Should

**2. Two schedule entries for one asset defeat the minimum interval.** `MinIntervalSeconds` exists because "a relay's session limits are small", and `Run` says a node "never polls a device faster than the minimum interval". But `ParseConfig` checks the interval per entry, not per asset. My probe added a second entry with the same asset, endpoint, operation and `every_seconds: 60` under a new ID, and `ParseConfig` accepted it. The relay is then polled twice a minute. Separately, a run that takes longer than its interval is followed at once by the next one (`next[i] = now`), with no gap between sessions to one device.

Please either refuse a second schedule entry for the same asset and endpoint, or keep the last session end per asset in the scheduler, and never start a run sooner than `MinIntervalSeconds` after it. A test should show each case: the two-entry config, and a run longer than its interval. This must be in place before D2-4 is lifted for a real device. It does not block the simulator slice.

**3. The unauthorized-line halt has no live trigger yet.** `RunOnce` halts the asset when `resp.Quarantine.UnauthorizedLine` is set. The client only sets it when node-side `CheckLines` fails, and `Client.Register` is not set (A5-node.md, "Open"), so in the built node that path cannot fire today. `TestUnauthorizedLineQuarantinedAndHaltedDurably` shows the handling is right once the flag arrives. It is not evidence that a real unauthorized line stops collection. Please record this in the Phase 2 exit report as a gate item: either the node holds a verified register package and sets `Client.Register`, or the collector's own `CheckLines` result (A3 PR 3) reaches the node as a quarantine with the flag set. My slice test for "no unauthorized write" will check whichever path is live, end to end.

## Nits

**4.** "Each run ends with exactly one of them on platform/health" does not hold when the normalizer refuses a result. `commitResult` quarantines it and raises `collection-result-refused`, but writes no `collection.*` health event. Writing `collection.outcome-unknown` with `quarantined=true`, as the collector-quarantine path does, would fix it.

**5.** `OpenReadOnly`'s doc says it "writes nothing". A5-node.md says a stopped node's `-wal` file is created empty by the reader. Please make the doc comment say the same as the A5 note.

## Notes for the record

- The scheduler order holds: the audit record is committed before the request is sent (`AuditBeforeAct`), the decision and the collector-reported records go in one audit batch, and a quarantine is two records in one batch. A quarantine the store refuses stops every run on the node. The halt scan at startup treats an unreadable quarantine stream as a halt, which fails closed.
- `cannotKeep` is checked before every run, so no request is sent without room for its quarantine.
- **Intermittent Windows failure, not from this PR:** `modules/security/collectorwire` `TestTransportRefusesOtherServer` failed once under `go test -count=3 ./...` (at #89 `378fec0`) and once under `-count=5 ./...` on main `8c97081`, with "server received -1 bytes". The value -1 means `Accept` itself returned an error. I've sent it to A3.
- Installer (W-1 to W-4, `-collector-config`, `collector\public`, the WER value): not run. It needs administrator rights on ALI's PC, and I've asked ALI. Until then, none of `install_windows.go` has run anywhere.

## Re-check at `817ee41`

- **Must 1 is fixed.** `fileURI` prefixes `/` when the path has a volume name. The writer now opens by URI too, because a plain name was cut at its first `?`, which A5 found. Natively on Windows, `TestOpenReadOnly` and `TestReadOnlyCommands` now pass.
- **Should 2 is fixed.** Each asset now waits 60 s after its last session ends, whichever entry ran it. `TestPlanSpacesSessionsPerAsset` covers this and passes on Windows.
- **Should 3 is closed.** It is recorded as a Phase 2 gate item.
- **New failure on Windows:** `TestOpenReadOnlyPath` fails during setup. Its directory name `OT SEC #1 ?x` contains `?`, which Windows does not allow, so `os.Mkdir` fails. I asked A5 to keep the space and `#` on every OS, and to add `?` only on non-Windows.
- Linux: vet, gofmt and `-race` all pass. Windows per package: platform/node 22 passed, platform/store 25 passed and 1 failed (2 skipped by design), winsvc 2 passed, cmd/otsec 2 passed.

## Re-check at `b2a604d`: non-admin part accepted

- `TestOpenReadOnlyPath` keeps the space and `#` on every OS and adds `?` only off Windows.
- Native Windows run on ALI's PC (non-elevated shell, portable Go 1.26.0): vet and gofmt are clean, and `go test -count=1 -v ./platform/... ./cmd/...` passes. `TestOpenReadOnlyPath`, `TestOpenReadOnly`, `TestReadOnlyCommands` and `TestDirDACLChecked` pass by name. Per package (top-level tests passed/failed/skipped): platform/node 22/0/0, platform/store 26/0/2 (`TestCrashChild` and `TestFileModes`, skipped by design), platform/winsvc 2/0/0, cmd/otsec 2/0/0.
- Linux: vet, gofmt and `go test` of platform/node, store, winsvc and cmd/otsec pass.
- Verdict: **accept** for everything that runs without administrator rights. Nits 4 and 5 are left to A5.
- Still not run: the installer (W-1 to W-4, `-collector-config`, `collector\public`, the WER value). It needs administrator rights on ALI's PC and waits on ALI's answer. Until it runs, `install_windows.go` has no evidence beyond compiling.

## Installer run as administrator at `c1f9e27`: accepted, with the limits below

ALI approved this run on 2026-10-25 (decision card: "Yes, on this PC, then clean up") and started the elevated step. It ran on ALI's PC (Windows 11 Pro 10.0.26200), with `otsec.exe` built from `c1f9e27` (`CGO_ENABLED=0`, portable Go 1.26.0) and the scripts in `tests/safety/windows_installer/` at `ca08b6d`. Logs are in `otsec-ci-a6\ci-logs\installer\run2\` on that PC. Evidence class: **native Windows host, simulated device**. No device was contacted, and no collector ran: `otsec-collector.exe` was a renamed copy of `otsec.exe`, installed but never started.

The first attempt (`run1`) stopped right after its preflight, before it changed anything. The cause was a bug in my script: `sc` is an alias of `Set-Content` in Windows PowerShell. It was fixed in `ca08b6d`.

| Check | Result |
| --- | --- |
| W-4: `OTSEC\store` pre-created by the normal user, then install | Refused: "C:\ProgramData\OTSEC exists with another owner; the installer stops (W-4)". Exit 1, no service created |
| Install | Exit 0 |
| The 7 directory descriptors | Each one is `O:BA`, protected, with exactly the ACEs of `TestDirs`, using the real service SIDs |
| `config\node.json` | Inherited SY, BA, and node read. No collector or user entry |
| `collector\collector.json` (`-collector-config`) | Owner BA, inherited SY, BA, and collector read (`0x1200a9`). No node entry |
| `collector\state\provision` | Written |
| Both services | `NT SERVICE\<name>`, SID type `UNRESTRICTED`, required privileges `SeChangeNotifyPrivilege` only, restart after 60 s with a reset of 86400 s (from `sc qc`, `qsidtype`, `qprivs` and `qfailure`) |
| WER `ExcludedApplications\otsec-collector.exe` | `1` (DWORD) |
| W-3 rule | Outbound, Block, TCP, remote port 23, service `otsec-node`, enabled |
| Event log sources | Both present |
| Second install | Refused ("node.json exists"). `node.json` unchanged |
| Non-admin user | Refused for all of these: read `collector.json` and `node.json`, list `credentials` and `store`, write in `store`, `config`, `collector\public` and `Program Files\OTSEC`, create a folder in `OTSEC`, and `sc config otsec-node` (FAILED 5) |
| `otsec-node` service started for 90 s | Running as `NT SERVICE\otsec-node`, store created (`audit.db`, `evidence.db`, reserves, `status.json`). With no collector, the scheduled run ended `collection-no-decision` ("no reply"), as the node's fail-closed path requires. `otsec health` read it |
| Uninstall, then cleanup | Exit 0. Services, event sources, firewall rule and WER value removed. `OTSEC` folders deleted by the script. Then checked again from a non-admin shell: nothing left |

**Script defect, not an installer defect.** `S-otsec-node` and `S-otsec-collector` printed FAIL. With a single match, `$privs` was a plain string, so `$privs[0]` was the letter `S`. The `sc qprivs` output in the same log shows `PRIVILEGES : SeChangeNotifyPrivilege` for both services, and the per-check details say the same. The script is fixed in #96 (`@(...)`). I count both service checks as passing, on the raw `sc` output.

**Not covered here, owed until A3's collector binary exists:**
- W-1: the pipe impostor.
- W-2 on a live token. Only the configured privilege list was checked here.
- W-3 by connection: only the collector reaching port 23.
- The collector's first start from the provision marker.

Verdict: the installer is **accepted**, which closes the last item of my #92 review. The four items above stay open for the slice tests.
