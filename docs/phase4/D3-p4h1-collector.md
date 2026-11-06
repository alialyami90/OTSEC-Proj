# P4-H1, the collector: an off-lab asset's suspension is lifted only by a signed clear

D3, 2026-11-06, at `main` `c10da6f`. This is the collector part of P4-H1 (`docs/agent-handoffs.md`, "After item 3: hardening briefs", D4-62). D5's node part follows it. Evidence class: `desk` for the reading. The tests are Go-level and `simulated`, and the CI result is on the PR. No device is contacted, and every key is a test key (D2-5).

## What was there

- **The signed path already existed.** C7 0.4 puts `asset.clear_suspension` in `adminKinds` and `DefaultAdminKinds`. `Pipeline.Handle` sends any request carrying `AdminSigned` through `verifyAdmin`, which checks the signature, the key, the binding, the window, and the nonce, and spends the nonce before any decision. `decideAdmin` then clears through `State.ClearAssetSuspension`, which refuses another invocation with `suspension_mismatch` and changes nothing. It reads no file.
- **The unsigned path** (`clearAsset`, C7 0.2, D2-15) took the node's clear in the clear and lifted the suspension when the request, the administrator's `clear-suspension.json` and the collector's own record named the same asset and invocation. It did this for every asset, on the lab or off it.

## The change

`clearAsset` refuses the clear in the clear for an asset that has **any** endpoint not labelled `simulated` in the collector's configuration. The checks run in this order:

1. The principal is checked first, as before. Only the node relays a clear.
2. The asset must be enrolled, as before.
3. **New:** if the asset is off-lab, the reply is `admin_unverified` with check `envelope` and the fixed detail (`authz.AdminRefusal`). An alarm names the request, the asset and the endpoint. The file is **not read**, so a file planted for that asset is never even opened.
4. Otherwise, for a lab-only asset, the file path runs unchanged.

**Why this code, and no new one.** C7 already defines `admin_unverified` as "an admin request is unsigned, or its signature ... fails". An unsigned credential request gets the same refusal, through `VerifyAdminRequest`'s `envelope` check. A request stamped before 0.4 gets `principal_not_permitted` (`Refusal.ForRequest`), as every older node already handles it. So no C7 or C8 field and no new code is needed, and the contract does not change.

**Per asset, not per node.** The collector decides from the asset's own endpoints. The node's `LabOnly` is per node, so it is the stricter of the two. The collector's rule stands on its own: a node that believes it is lab-only, or a compromised node, still cannot lift an off-lab asset's suspension with the file.

**Not changed:**
- the signed path;
- `credential.clear_suspension`;
- a lab-only asset's file path;
- `clear-quarantine.json` and `seq-reset-ack.json` (#347).

## Tests

`TestAssetClearOffLab` (`modules/security/collector/assetclear_test.go`) was written first, and it failed on `main`: the unsigned clear was accepted. The asset has a simulated endpoint and, after loading, a second endpoint with `device-observed` (D2-4 keeps that target out of the loader). The test then checks each of the following:

- The node's clear in the clear, with a matching file, is refused `admin_unverified` (`envelope`) when stamped 0.9, and `principal_not_permitted` when stamped 0.3. Both replies pass `CollectorReply.Validate`. The file is read zero times. The asset stays suspended in memory and on disk. One alarm is raised per refusal.
- A signed clear naming another invocation is refused `suspension_mismatch`. Sending it again is refused `replay`, so a refused signed request spends its nonce.
- A signed clear whose signature is made by a key no collector pins, under the pinned key's ID, is refused `signature`.
- An expired signed clear is refused `window`.
- The administrator's signed clear lifts the suspension durably, with `Admin.Principal` the signing administrator, and still with no file read.
- After a later suspension, a replay of that accepted clear is refused `replay` and lifts nothing.

Lab-only behaviour is pinned by the existing `TestAssetClear` and `TestAssetClearDenials`, which pass unchanged.

**Mutants**, each run against the whole collector package and each killed by `TestAssetClearOffLab`:
- the off-lab check disabled (`&& false`);
- only the first endpoint looked at, so a simulated endpoint first hides an off-lab one.

**Desk runs (Linux):**
- `go vet ./...`, `GOOS=windows go vet ./modules/security/...` and GOROOT `gofmt -l .` are clean.
- `go test ./modules/security/... ./cmd/otsec-collector/... ./contracts/... ./platform/node/...` passes.

CI on the PR gives the Windows result.

## For D5 and D6 (through the coordinator)

- **D5:** until the node part lands, a node that is not lab-only and acts on `clear-suspension.json` lifts its own suspension, while the collector keeps the asset suspended. Every later run is then refused `asset_suspended`, and the node adopts the held suspension again. So the asset stays suspended, which fails closed. The node's relay of the signed request needs nothing new at the collector.
- **D6:** each of D6's planned cases has a hook here. The divergence case (a lab-only node, with the asset off-lab in the collector's configuration) is the collector deciding per asset. A refused request spending its nonce is the "another invocation" step. The off-lab mutant is caught on its own. The relayed bytes are verified as sent, because `verifyAdmin` checks `AdminSigned` exactly as it arrives. The credential-clear tests are untouched.
