// Package asset is contract C1, otsec.asset/0.1: how the platform identifies
// a device, what it knows about it and how well, how it reaches it, and which
// capability profile applies.
//
// # What it covers
//
//   - The asset ID, assigned once at registration and never derived from
//     device content (a device's own claims can change or be forged).
//   - Every descriptive fact as an Attribute: a resolved value, a confidence,
//     and one or more observations, each with its evidence source and
//     evidence class. Device class, vendor and product family (ADR-0006) are
//     attributes like any other, so their provenance is visible too.
//   - Endpoints, each with its transport and its downstream_security label
//     (A3 §4.5). A plaintext endpoint needs a recorded per-device
//     acknowledgement and is labelled insecure wherever it appears.
//   - The identity binding: which attributes the collector compares, and how
//     strong that comparison is. See "What the identity binding proves" below.
//   - A suspension that stops collection from the asset until an operator
//     clears it, with a reason from a closed list.
//   - The site platform node as an asset of class "server", carrying A5's
//     posture labels.
//   - Capability profiles (profile.go): per family, which capabilities exist,
//     by which mechanism, with which evidence class.
//
// # What the identity binding proves (B-05, C-07)
//
// For SEL ASCII over Telnet (ADR-0005) the transport has no cryptographic
// identity. The binding is method "device-reported": the operator declares
// the firmware ID (FID) and, where known, the serial number at commissioning
// from records, and the collector compares them with what the device reports.
//
// What it proves: that the device answering at this address reports the same
// FID (and, after authentication, the same serial number) as the records. It
// catches a relay replaced by a different model or firmware, a wrong address,
// and a firmware upgrade nobody recorded. The FID check runs at Level 0,
// before any credential is sent, so firmware outside the allowlist never
// receives a password (AP-27).
//
// What it does not prove: that the device is genuine. Anything on the
// station LAN can answer at the relay's address and print the expected FID
// and serial number, because both are plain text the relay prints to anyone
// at Level 0 or Level 1. The binding is therefore labelled "spoofable", and a
// match never authenticates the device. The Level 1 password is still sent in
// clear text to whatever answers (owner-accepted risk, ADR-0005).
//
// The serial number is not in the SEL-751 ID response (S22 Figure 7.38). It
// appears in the SER report header (Figure 10.16) and the STA report, both
// Level 1, so it can only be compared after the password has been sent. It
// can detect a substitution, but cannot protect the credential.
//
// What a mismatch does: the collector sends nothing more except the close
// sequence that is safe at that point, the invocation ends with an
// identity_mismatch error (C2), the asset is suspended with reason
// "identity-mismatch", and collection stays stopped until an operator
// re-commissions the asset. A mismatch is never resolved automatically, and
// the observed value never replaces the declared one.
//
// # What it leaves out
//
//   - Node ID and timestamp model: C4. Principal and credential reference:
//     C7. Operation ID and the firmware allowlist: C3. Each is marked
//     TODO(C<n>) until that package is merged.
//   - Asset discovery, storage, and the UI.
//   - Configuration baselines (Phase 4).
//
// # Serves
//
// R1.1 to R1.7, R2.3 (insecure downstream labelled), P3, P7; A3 §4.5,
// AP-23, AP-27; A6 C-07, V-S1, V-S14; blocker B-05.
package asset
