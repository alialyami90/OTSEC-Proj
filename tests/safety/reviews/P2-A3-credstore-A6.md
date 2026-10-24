# A6 review of #90 (collector state, credential store, sealing) at `732baa0`

Reviewer: A6 (P2-A3 independent security review). Evidence class: **simulated and desk**. All runs were in the Linux container with Go 1.26.0, where the store key protection is `none-development`. The Windows DPAPI path (`storekey_windows.go`) only runs natively on Windows. That run is owed on ALI's PC. No device or real credential is involved, and every secret in the tests is a constructed value.

Verdict: **accept**, with one should and notes. No must.

## What I ran

- #90 merged with main, no conflicts. `go vet ./...` and `gofmt -l .` are clean (empty output). `go test -race -count=1 ./modules/security/... ./contracts/... ./tests/contract/` passes. The D2-1 import test passes.
- Windows cross-build: `GOOS=windows go vet ./modules/security/...`, plus `go test -c` for `collector` and `seal`, pass.
- I read `seal.go`, `credstore.go`, `secret.go`, `state.go`, both `storekey_*.go` and both `fsync_*.go`, and checked `Install` against D2-11 (#91). I also ran one probe of my own (below). It is not in the repo.

## What holds

- **Sealing.** Seal uses an ephemeral X25519 key, then HKDF-SHA256 with both public keys in `info`, then AES-256-GCM with `SealAAD(ref)`. Seal refuses to run without a pinned fingerprint, and the comparison is constant time. Open returns one error, `ErrOpen`, for every failure and carries no plaintext. The key ID is derived from the key, so a mismatched ID is refused.
- **At rest.** Three HKDF subkeys of the store key (records, install key, reuse tags) mean no key serves two purposes. Each record is bound to its reference by the AAD (`TestStoredCiphertextBoundToReference`). `checkEntries` runs on open and before every write. A revoked entry that still holds secret material is refused, as are two live versions of one reference.
- **Writes.** Every write goes to `.tmp`, is flushed, then renamed (`MOVEFILE_WRITE_THROUGH` on Windows, directory fsync on Linux). A failed write breaks the store until restart, so it fails closed.
- **Slot.** `SecretHandle.Use` hands the adapter a copy and wipes it when `f` returns, and a second `Use` fails. `Close` wipes the stored bytes.
- **Refusals.** `TestRefusalNeverEchoesSecret` holds, and `Install` replaces a detail with the generic message if it would contain the secret.

## Should

**1. Restoring an older copy of the store file brings a revoked credential back.** The doc says revocation "is terminal" and that removing the ciphertext "is the destruction of the secret" (section 7). My probe:
1. Install a credential and copy `credentials.json`.
2. Revoke the credential with reason `compromised`.
3. Write the old copy back and reopen the store.

`OpenCredStore` accepts the old copy, and `Acquire` returns a working handle for the revoked credential. Nothing in the file says a newer version existed.

Who can do this: anyone who can write the store file and has an older copy, meaning the collector account, SYSTEM or Administrators under W-4. That person already holds a great deal of power. But older copies turn up without anyone planning it:
- Windows Volume Shadow Copies and System Restore keep earlier versions of files under ProgramData;
- backups;
- a `.tmp` left by a crash.

Each copy holds the ciphertext and the DPAPI-protected store key together, so the collector account can still decrypt a "destroyed" secret from it.

Please do two things:
- (a) **In the doc:** say that removal is logical. A revoked secret stays recoverable from any older copy of the file by the collector's account, so revocation of a compromised secret must be paired with changing it on the device. That is already the rule for a real compromise, and the doc should say it.
- (b) **In the code:** add a generation counter to the store document, raised on every write, and keep its highest value in the durable collector State (or in the audit chain once C8 carries it). `OpenCredStore` then refuses a store older than the recorded generation. Rolling back both files together is still possible, but it needs a second coordinated step, and the C8 chain would show the gap. My probe can be the test: revoke, restore the old file, and expect `ErrStateUnavailable` on open.

This can be a follow-up PR before any `device-observed` endpoint (the same gate as D2-11). It does not need to hold this one.

## Notes for the record

1. D2-11 (#91): the install oracle is real in this code. A guess installed with scope `""` on an asset that has an encrypted endpoint is compared against every live `lab-only` secret, and the reply is `secret_rejected` exactly on equality. My review of #91 covers why the interim budget is acceptable only while every stored secret is a lab test value. When the budget lands in PR 3, I will test that the 11th install in an hour is refused, that the refusal survives a restart, and that no count appears in a reply.
2. `secret_rejected` is also the code for "sealed secret does not open". That is fine: the reuse oracle is the difference between success and refusal, not between refusal reasons.
3. On Linux the store key sits in the file in the clear (`none-development`). A store written there is refused on Windows by the `key_protection` check, so a development store cannot be carried into production by accident.
4. Owed on Windows: `go test ./modules/security/...` at `732baa0` on ALI's PC. That is the only run that exercises `CryptProtectData` and `CryptUnprotectData`.
