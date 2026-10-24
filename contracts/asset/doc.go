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
//     (A3 §4.5). Telnet, serial and Syslog without TLS are always
//     plaintext-unauthenticated. Only a pinned-key binding makes a link
//     encrypted-authenticated. Anything less needs a recorded per-device
//     acknowledgement with its scope, and is labelled insecure wherever it
//     appears.
//   - The identity binding: which attributes the collector compares, and how
//     strong that comparison is. See "What the identity binding proves" below.
//   - A suspension that stops collection from the asset until an operator
//     clears it, with a reason from a closed list.
//   - The site platform node as an asset of class "server", carrying A5's
//     posture labels.
//   - Capability profiles (profile.go): per family, which capabilities exist,
//     by which mechanism, with which evidence class, and for a family the
//     platform sends commands to, the most rows one read may hold (D1-12)
//     and its session limits (D1-18): concurrent sessions, the interval
//     between collections, password attempts, the idle timeout the device
//     may keep session state for, and the failed-auth floor, which must be
//     longer than that timeout.
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
// clear text to whatever answers (owner-accepted risk, ADR-0005). Anyone
// who can read station LAN traffic also reads the Level 1 password; the
// binding gives no protection against that. This is why plaintext links are
// accepted for the lab only (Acknowledgement.Scope).
//
// The serial number is not in the SEL-751 ID response (S22 Figure 7.38). It
// appears in the SER report header (Figure 10.16) and the STA report, both
// Level 1, so it can only be compared after the password has been sent. It
// can detect a substitution, but cannot protect the credential.
//
// The record says which is which: IdentityBinding.PreCredential lists the
// attributes compared before any credential is sent ("firmware_id" for the
// SEL-751), and a device-reported binding without one is invalid, so ACC is
// never sent ungated. The family's profile lists what it reports before
// authentication, and Asset.CheckProfile holds the binding to that list.
//
// Decoding is strict about spelling (strictjson.Forward, D1-10): a key that
// differs from a field name only in case, or a key given twice, rejects the
// record, so a reviewer and the node always read the same binding. Values
// added by a later minor are read down to the least trusted 0.1 value
// (Asset.Effective).
//
// What a mismatch does: the collector sends nothing more except the close
// sequence that is safe at that point, the invocation ends with an
// identity_mismatch error (C2), the asset is suspended with reason
// "identity-mismatch", and collection stays stopped until an operator
// re-commissions the asset. A mismatch is never resolved automatically, and
// the observed value never replaces the declared one. A mismatch found after
// authentication (the serial number in the SER header) means the password
// went to a device that is not the bound one: C7 then treats the credential
// as exposed, and only rotation or re-commissioning clears it (C1-A3-5). No
// event is created for the asset from that session.
//
// After a mismatch, the operator re-commissions. If the device is the same
// unit (same serial number; for example an unrecorded firmware upgrade), the
// asset keeps its ID and gets new declared values. If it is a different unit
// (a replaced relay), it gets a new asset ID and the old record is retired
// with its history, so events never mix two physical devices under one ID
// (C1-A4-3).
//
// # What it leaves out
//
//   - Timestamp model: C4. The node ID is contracts/node's (D1-1). Principal
//     and credential reference: C7. Operation ID and the firmware allowlist:
//     C3. Each is marked TODO(C<n>) until that package is merged.
//   - Asset discovery, storage, and the UI.
//   - Configuration baselines (Phase 4).
//
// # Serves
//
// R1.1 to R1.7, R2.3 (insecure downstream labelled), P3, P7; A3 §4.5,
// AP-23, AP-27; A6 C-07, V-S1, V-S14; blocker B-05.
package asset
