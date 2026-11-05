// Package asset is contract C1, otsec.asset/0.3: how the platform identifies
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
//     attributes like any other, so their provenance is visible too. From
//     0.3 each observation also says its kind, device-read, passive or
//     operator (D4-49 Q4), and a device read from a session says its read
//     path; see "Source kinds" below.
//   - Endpoints, each with its transport and its downstream_security label
//     (A3 §4.5). Telnet, serial and Syslog without TLS are always
//     plaintext-unauthenticated. An snmpv3 endpoint (0.3) is authPriv with
//     the engine ID pinned, so it is encrypted-authenticated and sits on a
//     pinned-key binding. Only a pinned-key binding makes a link
//     encrypted-authenticated. Anything less needs a recorded per-device
//     acknowledgement with its scope, and is labelled insecure wherever it
//     appears.
//   - Each endpoint's target: device-observed or simulated, whether a device
//     or a simulator is behind it (D1-24). An admin sets it; it is never
//     taken from the far end and never defaulted, in any minor. C2 copies it
//     into Result.target and C4 into an event's evidence class (D1-23). A
//     session or received value labelled device-observed needs an endpoint
//     whose target is device-observed, and a simulator value one whose target
//     is simulated.
//   - Each endpoint's path, added in 0.2: direct, or through a port server.
//     Only a direct path gets a session (Endpoint.CheckPath). A port server
//     is refused until its timeouts have evidence (H-13), and no path (every
//     0.1 record) or an unknown one is refused the same way, explicitly
//     rather than as a parse failure, until an administrator sets it (D2-16).
//   - The identity binding: which attributes the collector compares, and how
//     strong that comparison is. See "What the identity binding proves" below.
//   - A suspension that stops collection from the asset until an operator
//     clears it, with a reason from a closed list. It stops adapter
//     sessions, never the reception of what the device sends (EP-1).
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
// SEL-751), and a device-reported binding without one is invalid. The
// family's profile lists what it reports before authentication, and
// Asset.CheckProfile holds the binding to that list. Asset.CredentialAllowed
// is the rule the collector applies before any credential is used: only a
// pinned-key binding, or a device-reported binding whose pre_credential
// passes CheckProfile, gets one. An address-only binding, or a binding method
// from a later minor, never does, so ACC is never sent ungated (A6 R-1).
//
// Decoding is strict (D1-10, A6 S-1). A record of this minor or an earlier
// one is read with strictjson.Decode, so an unknown field is an error. A
// record of a later minor is read with strictjson.Forward, which ignores the
// fields it adds. Either way a key that differs from a field name only in
// case, or a key given twice, rejects the record, so a reviewer and the node
// always read the same binding. Values added by a later minor are read down
// to the least trusted 0.1 value (Asset.Effective); an unknown binding method
// reads as address-only.
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
// # Source kinds (0.3)
//
// Source.Kind is KindOf(Source.Method): adapter-session and
// simulator-session are device-read (the evidence class still says which is
// a simulator), syslog-received and passive-network are passive, and
// operator-entry and document are operator. A derived observation takes the
// kind its inputs warrant, and Validate refuses device-read unless every
// attribute its ref names (comma-separated) carries a device-read
// observation equal to that attribute's value, so a rule cannot raise its
// inputs. A value cut from device bytes, such as the model and firmware
// version inside a FID, is not derived: it is its own session observation
// whose span covers only its part of the bytes, with the same ref.
//
// Source.Read, required on a device read from a session and absent
// otherwise, gives the endpoint's transport, the C3 operation (the run's
// step, not the run) and, for snmpv3, exactly one of the varbind OID or the
// header field (msgAuthoritativeEngineID, for snmp_engine_id). V-M1 (e)
// checks the transport and V-M7 the kind. The evidence ID of a device read
// is Source.Ref, the C2 invocation ID, with the span.
//
// # SNMPv3 (0.3)
//
// An snmpv3 endpoint's binding is pinned-key, and its pre_credential is
// exactly snmp_engine_id: the engine ID the device's USM keys are localized
// to, declared at commissioning from the device itself (its settings or its
// MAC label), never from a network discovery. Discovery's engine ID is
// compared with it before anything authenticated is sent; after that, a
// response verifies only if the responder holds a key localized to it
// (RFC 3414 §2.6). The FID may be a binding attribute, compared after
// authentication. The key is per device only if the USM password is, which
// is a commissioning rule (C3, #437). There is no v1 or v2c transport
// (D4-49 Q3).
//
// # Versions
//
//   - 0.1 (#32): the record, endpoints with target (D1-24), the binding,
//     suspension, posture, and capability profiles.
//   - 0.2: Endpoint.path (D2-16, ADR-0008). A 0.1 record is still read; its
//     endpoints have no path, so CheckPath refuses a session to them. A 0.1
//     record that carries a path is invalid. Capability profiles are
//     unchanged and may stay at 0.1.
//   - 0.3 (D4-53, C1 0.3 in docs/phase4/C2-c1-0.3-c3-0.4.md): Source.kind
//     and Source.read, the snmpv3 transport, the snmp_engine_id attribute,
//     and pinned-key's SNMPv3 meaning. A 0.2 record is still read; its
//     observations have no kind, and Observation.EffectiveKind gives them
//     their method's (a derived one reads as operator). A 0.2 record that
//     carries kind, read or an snmpv3 endpoint is invalid. A 0.2 node
//     refuses a 0.3 record with an snmpv3 endpoint, and with it the asset,
//     so a node is upgraded before an SNMP endpoint is added. A 0.3
//     capability profile may list its family's models, as printed
//     (CapabilityProfile.Models, C1 on #445); absent means no family check.
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
