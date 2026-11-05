// Package finding is contract C12, otsec.finding/0.1, a DRAFT for review
// under Phase 4 item 3 Stage A (brief P4-3-A4, D4-48). It is not approved,
// and no product code may depend on it until C1 approves it together with
// C1 0.3 (identity attributes) and C11 (the advisory set).
//
// A finding is the result of matching one asset's identity against one
// advisory of the signed offline set (R9.1, R9.2). The classes and what
// each needs are fixed by docs/verification.md, "R9 classes and what
// `confirmed` needs", and V-M7. This package states them as a record and the
// rules that hold on one record. It holds no matcher: no I/O, no storage, no
// clock. The matcher's design is docs/phase4/C4-matcher.md.
//
// # What a finding holds
//
//   - The asset, the advisory's ID, and the set's version and date (R9.3).
//   - The class: applicable-by-version, confirmed, mitigated, not-applicable,
//     not-applicable-operator or not-applicable-passive (the "not-applicable
//     (operator)" of the verification text and D4-49's "not-applicable
//     (passive)", each written as one token).
//   - The identity it was decided on: the product and version as read, the
//     source (device-read, passive or operator) and its evidence IDs.
//   - Every further precondition the advisory names, by its name in the
//     set, each evidenced, not met, or unread. An unread precondition is
//     named, never dropped (V-M7).
//   - Every mitigation the advisory names that is evidenced, with its
//     evidence, and whether it is operator-attested.
//
// An evidence ID takes one of three forms, each tied to its source, so an
// operator's entry can never stand as a device read:
//   - the C2 invocation ID (a lowercase UUID) of a device read, which is
//     C1 0.3's observation ref and keys the identity record C5 keeps (#439);
//   - the event.EventID string (<node_id>:<stream>:<seq>) of a stored
//     record, such as a passive observation later (R6.7);
//   - audit:<node_id>:<seq>, an audit record of the chain (C8), for an
//     operator entry. Each carries its
//
// source, so R6.7's observations plug in as new records with source passive
// and no change to this contract. Evidence that is no longer current is
// kept and marked stale, so a finding that fell from confirmed names it
// (D4-49 Q6 (ii)).
//
// # A reclassification is a change, never an overwrite
//
// A finding is recorded once and never edited. Re-evaluation that changes
// anything in it records a new finding with Revision + 1, Previous set to
// the hash of the one it replaces, and From set to that one's class (V-M7).
// Revision 1 has neither. The record is hashed over its bytes exactly as
// stored (Hash), as baselines are (C10).
//
// # What a finding never states
//
// No field states exploitability, risk or severity, and none is free text
// a matcher writes. confirmed means the advisory's stated conditions hold on
// this device with current evidence, never that exploitation was tested or
// is possible (P10, R9.2). It means the conditions hold on what the device
// reported: a compromised or spoofed device can misreport its FID, and no
// platform control detects that (AP-29). Nothing is probed to reach any
// class (R9.4).
// TestNoFieldStatesExploitability holds the field names to that.
//
// # What Validate checks, and what it cannot
//
// Validate checks the rules that hold on one record: confirmed only on a
// device-read identity with every precondition evidenced by current
// device-read or passive evidence; an unread precondition only on
// applicable-by-version, or on mitigated (D4-52, subject to C6); a
// precondition not met only as D4-49 Q5 allows; mitigated exactly
// when a mitigation is evidenced; and each not-applicable class only on its
// identity source (device-read, operator, passive). Whether the evidence
// was current (point 3 of "what confirmed needs") depends on records stored
// after it, so it is the matcher's rule, tested over GT-ADV, not the
// record's.
package finding
