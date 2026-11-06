# C1: refuse an all-zero or all-`ff` `snmp_engine_id`

D2, 2026-11-06. This is a proposal and its code in one PR, paired with D3's C7 0.9 (#497). D1 approved it on 2026-11-06 as a fix within 0.3, relayed by the coordinator. Like #497, it merges after V-M1's counted run. It needs D6's contract-test review and D3's review as a consumer.

## Why

RFC 3411 §5 (`SnmpEngineID`, `/mnt/project-files/rfc/rfc3411.txt`) says an engine ID "may not be all zeros or all 'ff'H". The collector's client refuses such a pinned ID before it sends anything (#495, `TestPinnedEngineIDForm`). C7 0.9 (#497) refuses such a credential at install. C1 0.3 still accepts the same value as an asset's declared `snmp_engine_id`. Because the collector requires the credential's engine ID to equal the asset's (`endpointMatches`), an asset like that can never get a credential and can never run. So the defect should be refused where the asset record is written, as it is for the credential. D3 asked whether C1 carries the same rule (D1 passed the question to D2), and D2 answered yes.

## The change

- `contracts/asset/asset.go`: the `snmp_engine_id` value check refuses a value that is all `00` or all `ff` octets, at any length from 5 to 32. The pattern rule is unchanged and runs first, so the value is even-length lowercase hex when the new check runs.
- The rule applies to every record that can carry the attribute, which is 0.3 and later. Nothing on the wire changes.
- `contracts/asset/testdata/generate.py`: two invalid examples, `engine-id-all-zeros` (5 octets) and `engine-id-all-ff` (32 octets), regenerated with `python3 -I generate.py`. No other example changes. `testdata/README.md` gains a line for each.
- `schema/asset.schema.json` is unchanged. It is structural, and it has never carried the engine ID's form, which `Asset.Validate` enforces.

## Version: a fix within 0.3 (D1, recorded with D4-60)

C1 0.3 defined the attribute as an RFC 3411 SnmpEngineID ("lowercase hex, 5 to 32 octets (RFC 3411 SnmpEngineID)", `asset.go`). An all-zero or all-`ff` value was therefore never an SnmpEngineID, and the 0.3 reader's check was incomplete. `Contract` stays `otsec.asset/0.3`. D1 chose this over a bump to `otsec.asset/0.4` on 2026-11-06, recorded with D4-60. A bump would have restamped about 70 files with no difference in behaviour: every generated example, the later-minor examples moving from 0.4 to 0.5, `doc.go`, the schema's `$id`, and the stamps in `modules/asset` and D5's `nodeconfigtest`.

## Compatibility

- **A stored asset record is re-validated** wherever C1's `Validate` runs on read. A record that already holds such an engine ID then fails, which fails closed (P5). Such a record could exist only in a test store, because no real asset is registered and no device has been contacted. It could never have run under #495 and C7 0.9. No example or fixture in the repository has such an engine ID (checked with `grep -rnE '"(00){5,32}"|"(ff){5,32}"'` across `*.go` and `*.json`).
- **C2 is unchanged.** `session.snmp.engine_id` in an adapter result is what the agent sent at discovery, and a result keeps native evidence whatever it holds. If an agent ever sends an all-zero ID, the run already fails, because a valid pinned ID cannot equal it. An identity item carrying that value is refused only when it would become a C1 observation, through this rule.

## Tests

`desk` and `simulated` only. No device was contacted.

- `TestInvalidExamples`: the two new examples failed ("accepted") on `main` at `c20bb64` before the change, and pass with it. `26e40f5` has the same `contracts/asset`.
- `TestEngineIDNearMiss` (new): `00000000ff`, `ffffffff00` and `0000000001` stay valid.
- **Mutants:** four mutants of the new condition were run, and the tests above kill all four:
  - a condition that never holds;
  - the `"f"` half dropped;
  - the `"0"` half dropped;
  - a single `Trim(val, "0f")`, which refuses mixed IDs.
- In D2's container (Linux, Go 1.27.3): `go vet ./...` exit 0; `gofmt -l .` prints nothing; `go test ./...` 52 packages ok.
