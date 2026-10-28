// Package nodekey is the node's key register and key store for its TLS
// references (credential design section 9, P3-A3). It replaces the D2-12
// file resolver, which reads an unencrypted private key from tls_dir and
// stays behind an explicit lab flag (A5).
//
// # References
//
// A C6 target's trust_anchor_ref and client_credential_ref, and a C4
// listener's certificate reference (A4, #150), name an entry of the
// register: "nodekey_" and 8 to 40 lowercase letters or digits (RefPattern).
// A node key reference is not a C7 CredentialRef. It is held by the node,
// never the collector, and it names a certificate and a key, never a
// password.
//
// # The register
//
// register.json (Register) is written by an administrator's tool, never by
// the node, and read by the node with the protected-file rule. Each entry
// has a kind, a version and a state:
//
//   - tls-key: a key the node signs with, and the certificate an
//     administrator had a CA issue for it. It is pending from the key's
//     creation (Request) until its certificate is installed (Install), then
//     active; the version it replaces is retired. The entry holds the key's
//     public key and its provider; the private key is never in the register.
//   - trust-anchors: a CA set, or one peer certificate, that verifies a
//     peer. It is public, but whoever changes it chooses which peers are
//     trusted, so it is in the register, not a loose file.
//
// Every entry names the node it is for and the administrator who made the
// change. Fingerprints are recomputed when the register is read, and a
// mismatch refuses the whole register: nothing falls back to anything.
//
// # Keys
//
// A Keys provider creates and opens non-exportable ECDSA P-256 keys by
// name. The name is derived from the reference and version (KeyName), so
// the register cannot point an entry at another entry's key. Open returns a
// crypto.Signer, which is what tls.Certificate.PrivateKey and
// x509.CreateCertificateRequest take, so the key never has to leave the
// provider:
//
//   - On Windows, CNG: a machine-scope key in the Microsoft Software Key
//     Storage Provider, or the Platform Crypto Provider (TPM) where T-2
//     shows it works, with its export policy off. Once its request is signed,
//     its DACL gives SYSTEM and Administrators full control and lets the
//     listed users (the node service) use it; no other account has any
//     right (Request calls Restrict). Nobody, an administrator included,
//     can read the private key out.
//   - LabFiles: PKCS #8 files in a directory, for Linux tests and the lab.
//     The key is as exposed as any file the node can read. A5 constructs it
//     only behind the lab flag, as the D2-12 resolver is.
//
// # What it does not do
//
//   - It writes no audit record. The node writes C8 policy.apply for each
//     register change it loads, naming the reference, kind, version and
//     fingerprint (section 9, A5).
//   - It does not renew certificates. Expiry is reported (Expiring) for node
//     health 30 days ahead, and an expired certificate is refused at
//     resolution (Certificate, TrustAnchors), with an error that wraps
//     ErrCertificatePeriod only when the period is the sole fault. A caller
//     that holds back one link for an expired certificate loads with
//     LoadCertificate and LoadTrustAnchors, which leave the period to the
//     TLS check (HR-13, D4-11).
package nodekey
