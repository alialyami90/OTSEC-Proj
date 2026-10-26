# C7 golden examples

Files under `requests/invalid/` are named `<expected refusal code>__<what>.json`, and `TestGoldenRequests` checks that `DecodeRequest` refuses each one with that code. Files under `requests/against-register/` decode, but fail a check against the verified SEL-751 register with the code their name gives (`TestCheckAccessLevel`). None is device-derived. Asset IDs are C1 lowercase UUIDs, the same one C1 and C4 use in their examples.

| File | What it shows |
| --- | --- |
| `requests/valid/run-ser-read-all.json` | A schedule asks for `sel.ser.read_all` on one enrolled asset: no line, no limits, no secret. |
| `requests/valid/run-id-without-credential.json` | A run of `sel.id`, a level 0 operation sent before `ACC`: it carries no `credential_ref` (C7-A2-5). `TestRunAgainstRegister` refuses a level 0 run that carries one, and a level 1 run that does not. |
| `requests/valid/credential-install.json` | An admin installs version 2 of a lab-only Telnet credential, as ciphertext sealed to the collector. |
| `requests/valid/credential-revoke.json` | An admin revokes a credential after rotation. |
| `requests/valid/credential-clear-suspension.json` | An admin clears a suspension on the exact version they reviewed. |
| `requests/valid/asset-clear-suspension.json` | 0.2: the node asks the collector to clear its suspension of one asset, naming the invocation that suspended it. The collector still reads the administrator's file itself before it clears. |
| `requests/valid/admin-signed-credential-install.json` | 0.4: the same install, stamped 0.4, signed by a test admin key (seed: SHA-256 of `otsec test admin key 1`, test only, D2-5). The body travels only inside the signed payload. `TestAdminSignedGolden` rebuilds it byte for byte and verifies it. |
| `requests/valid/admin-signed-node-quarantine-clear.json` | 0.5: an administrator's signed clear of one quarantine the node holds, with the same test key and nonce. The body names the asset and the manifest's SHA-256 (of `otsec test quarantine manifest`, not a real manifest). `TestNodeQuarantineClearGolden` rebuilds and verifies it. |
| `requests/invalid/bad_params__line-break-in-param.json` | A parameter value carrying CR LF and a second command. |
| `requests/invalid/contract_mismatch__other-major.json` | A request stamped with another major version. |
| `requests/invalid/invalid__asset-clear-suspension-ref-not-an-invocation.json` | An asset clear whose ref is a path, not a C2 invocation ID. |
| `requests/invalid/invalid__asset-clear-suspension-stamped-0.1.json` | An asset clear stamped 0.1, which does not have that kind. |
| `requests/invalid/invalid__body-does-not-match-kind.json` | Kind `run` with a revoke body. |
| `requests/invalid/invalid__engineering-purpose.json` | A credential whose purpose is not `collect-readonly`. |
| `requests/invalid/invalid__params-missing.json` | A run with no `params` object; it must be present, even if empty. |
| `requests/invalid/invalid__sealed-with-other-algorithm.json` | A sealed secret claiming algorithm `none`. |
| `requests/invalid/invalid__telnet-credential-labelled-encrypted.json` | A Telnet credential labelled `encrypted-authenticated`; plaintext must stay visible. |
| `requests/invalid/invalid__telnet-credential-without-lab-only-scope.json` | A Telnet credential with no `lab-only` scope (ADR-0005: simulated and lab slice only). |
| `requests/invalid/invalid__two-bodies.json` | A run that also carries a revoke body. |
| `requests/invalid/invalid__unknown-kind-exec.json` | Kind `exec`, which does not exist. |
| `requests/invalid/malformed__duplicate-operation-id.json` | Two `operation_id` keys (`sel.ser.read_all`, then `sel.ser.clear`). JSON Schema cannot see this; the decoder must. |
| `requests/invalid/malformed__trailing-data.json` | A valid request followed by a second object. |
| `requests/invalid/oversize__padded-request.json` | A request over 8 KiB. |
| `requests/invalid/principal_not_permitted__person-asks-for-device-io.json` | A person asks for device I/O directly (AP-15). |
| `requests/invalid/principal_not_permitted__person-clears-asset-suspension.json` | A person asks the collector to clear an asset suspension directly; only the node relays the administrator's file (D2-15). |
| `requests/invalid/principal_not_permitted__schedule-installs-credential.json` | A schedule tries to install a credential. |
| `requests/invalid/unknown_field__case-folded-key.json` | A second `Kind` key next to `kind`. Go's own decoder would let `Kind` overwrite `kind`; the shared strict decoder accepts only exact field names (D1-10). |
| `requests/invalid/unknown_field__command-at-top-level.json` | A `command` field next to the request. |
| `requests/invalid/unknown_field__limits-from-main-process.json` | The main process tries to set limits; they come from the register and profile. |
| `requests/invalid/unknown_field__raw-line-in-run.json` | A raw `line` inside the run body. |
| `requests/invalid/unknown_field__secret-in-credential-ref.json` | A `secret` field inside a credential reference. |
| `requests/against-register/credential_mismatch__level-2ac.json` | A credential installed for access level `2AC`. It decodes, but no auth-phase session line in the SEL-751 register reaches it and no read-only operation needs it (C7-A6-1). |
