# Handoff P3-A3 — A3 — 2026-10-26

The brief is "Task P3-A3" in `docs/agent-handoffs.md`. Every result below is `simulated` or from the GitHub-hosted Windows runner. Nothing here ran against a device or on the owner's PC.

## Completed

- **C7 0.4, admin-signed requests** (#146, contract; #153, collector). Install, revoke and clear-suspension requests are signed by an enrolled administrator key over the D2-11 fields: the operation, node ID, asset, reference, sealed secret hash, nonce and expiry, under a fixed domain-separation prefix. The collector verifies the signature and spends the nonce durably before it decides anything. It refuses every unsigned or mis-bound request with one refusal code, so a wrong guess and a right one look the same. The install budget stays as defence in depth.
- **The collector's admin clock** (#153). `state.json` keeps a high-water mark (`admin_clock_utc`), and requests are judged at the later of the clock and that mark. Setting the clock back therefore cannot reopen a spent nonce or an expired request. When the clock is more than two minutes behind the mark, an alarm is raised.
- **The admin key procedure**: `docs/phase3/A3-admin-keys.md` covers enrolment, planned rotation, revocation, retiring a collector, what the audit shows, and the tests A6 can run.
- **The §9 node key store** (#157, `modules/security/nodekey`). It has a strict `register.json`, resolution to a `tls.Certificate` whose key is a `crypto.Signer`, and rotation through `Request`, `Install`, `SetAnchors` and `Retire`. On Windows the key is a non-exportable CNG machine key; elsewhere `LabFiles` is used, behind the lab flag. The DACL is set once, after the CSR is signed: SYSTEM and Administrators full control, and the node service generic read (D3-7, with A1's ruling that Administrators keep GA).
- **C8 0.3** (#155): `quarantine.exported` and `quarantine.cleared`. The actor is the node, and the file's principal goes in `requested_by` (D3-3).
- **C3 0.2 envelope stamps** (#159): the register envelope accepts every minor the reader decodes (D3-4).
- **The collector's path check** (#160): a run on an endpoint whose C1 path is not `direct` is refused before the adapter is invoked (D2-16).
- **Threat model** (#162): HR-11, the storage bound on unknown Syslog senders (D3-3), and HR-12, plaintext Syslog receive (D3-5). #169 updated HR-11 to show it is mitigated in part.
- **Reviews**, each recorded on its PR:
  - #150 and #154: the Syslog listener as a new inbound surface;
  - #163: quarantine export and clear, the clear's checks and how far the files are trusted;
  - #164: `refused.endpoint_path`;
  - #167 and #170: `tls_leaf_sha256` and `tlsleaf`, what they mean and the binding;
  - #169: listener sizing, option (b).

## Evidence

- **C7 0.4.** In `contracts/authz/adminsig_test.go`: `TestAdminRequestVerifies`, `TestAdminRequestRefusals`, `TestValidateAdminSigned` and the golden. In `modules/security/collector/adminsig_test.go`:
  - `TestAdminRefusalsComeFirst`: unsigned, no key pinned, another key, a mis-bound field;
  - `TestAdminReplayRefused` and `TestAdminNoncesInState`: the nonce is spent durably;
  - `TestAdminRepliesDoNotLeak`: there is no equality oracle;
  - `TestAdminClockBack`: the clock set back, which was A6's finding on #153.

  A mutation pass on the clock fix killed 7 of 7 mutants. A6's acceptance results are A6's to record in `docs/verification.md`.
- **Node key store, on Linux.** `go test ./modules/security/nodekey` covers a real mutual-TLS handshake with a resolved certificate, rotation, the refusal paths, expiry, and `TestRequestRestricts`.
- **Node key store, on the hosted Windows runner** (run 40385117971, Server 2025 build 26100, elevated, high integrity):
  - `TestCNGKeyLifecycle` passed.
  - `TestCNGRightsProbe` recorded the KSP's rule. A DACL change needs generic write, through any handle. Delete needs the delete right. Opening by name needs read.
  - A6's `TestA6NodeKeyClaims` (`tests/security/nodekey_cng_windows_test.go`, carried byte for byte) passed. The node service signs and cannot export. Another service account and a plain user can neither open nor sign. SYSTEM and an elevated administrator cannot export under any of 8 blob types, before or after trying to turn the export policy on.
- **Collector path check.** `TestRunRefusals` has cases for a port-server path and for no path.

## Interfaces

- C7 0.4 (signed request envelope), C8 0.3 (quarantine records) and C3 0.2 (envelope stamp reading). Each has a reader for the previous minor and a rollback note in its PR.
- `nodekey`: `Register`, `Certificate`, `TrustAnchors`, `Expiring`, `Request`, `Install`, `SetAnchors` and `Retire`. The providers are `CNG{Users}` and `LabFiles{Dir}`. There is no contract change. A5 wires it behind the C6 reference resolver.

## Limitations

- Nothing imports `nodekey` yet. Until A5's wiring lands, the node still resolves TLS references from the D2-12 files in `tls_dir`, which is lab only.
- The TPM provider (Platform Crypto Provider) is untested (T-2). There is no certificate renewal, and the admin tool that writes `register.json` is not built.
- `clear-quarantine.json` and `clear-suspension.json` are still unsigned on the node side. They move to C7 0.4 signed requests in A5's task.
- The signing client and how an administrator's key is held are left to the site (`A3-admin-keys.md`, "Not covered").

## Risks

- **A local administrator can use the node's TLS client key** (D3-7), though nobody can export it. A compromised administrator account therefore holds the node's forwarding identity until the certificate is revoked. This is recorded in the credential design's §10.
- **HR-11 stays open.** #169 bounds unknown senders only over the planned outage, and each node restart adds one hour's budget. The absolute bound (a separate C5 class and quota) gates the first device-observed listener and goes into the Phase 4 briefs.
- **HR-12.** On a plaintext listener, a host that spoofs a known device's address is attributed to that device. Plaintext never raises binding confidence (D3-5), and health shows it.

## Dependencies

- **A5:**
  - resolve `client_credential_ref`, `trust_anchor_ref` and the listener references from `nodekey`, with `CNG{Users: [node service SID]}` on Windows and the files only behind the lab flag;
  - a `key_register` path in `node.json`;
  - C8 `policy.apply` for each newly loaded entry;
  - the signed `clear-*` requests.
- **A4:** start the unknown-sender bucket empty after a node start (#169 review), until the absolute bound replaces it.
- **A2:** the SEL-751 adapter PR, with the rev 4 runner tests and the adapter's own path check. A3 reviews it.
- **A3, owed:** a C8 test case for the target asset-ID pattern on the next C8 change. Removing that check survived the C8 suite.

## Files changed

- `contracts/authz/`, `contracts/audit/` (C8 0.3), `contracts/register/` (envelope stamps)
- `modules/security/collector/`, `modules/security/nodekey/`
- `.github/workflows/ci.yml`: the `nodekey CNG tests` and `nodekey claims (A6)` steps
- `docs/phase1/A3-credential-design.md` (§9, §10), `docs/threat-model.md` (SC-16, HR-11, HR-12), `docs/phase3/A3-admin-keys.md`, this file

## Reviewer(s) and outcome

- #146, #153, #155, #159, #160 and #162 are merged by A1 on the reviews recorded on each PR.
- #157 is merged with A5's API review, A1's integration review and A6's three claims passing on the hosted runner.
