// Package advisory is C11, otsec.advisory/0.1: the signed, versioned advisory
// set a site node uses offline to say which advisories apply to its assets
// (R9.3, V-M7, V-M8). The approved text is docs/phase4/C3-c11-advisory.md,
// sections 1.1 to 1.6 (D4-53); this package codes it.
//
// What it covers:
//
//   - The envelope (Envelope): the register's pattern, an Ed25519 signature
//     over SigningInput(payload), where the input starts with SigningDomain so
//     no other signed artifact verifies as a set.
//   - The set and its entries (Set, Entry), decoded strictly (Decode) and
//     checked by Validate against every rule in 1.2 to 1.4: a cited source on
//     every entry, no test_only entry in a release set, the closed schemes,
//     kinds and ops, sel-fid ranges per branch, and the limits.
//   - The load rule (1.5) in two calls. Verify runs steps 1 to 4 (size and
//     envelope, key, signature, payload) against the advisory anchors pinned
//     now; a node also calls it on the stored set at every start and on every
//     anchor change (D4-53). Admit runs steps 5 to 7 (set, order, purpose)
//     against the node's floor. Each refusal is a Refusal with one Code.
//   - The advisory anchors (Anchor), a trust root separate from admin,
//     release and node keys (1.6). ValidateAnchors refuses a test key in a
//     release build (TestKeyIDs).
//
// What it leaves out: where the set is stored, when the file is read, the
// audit records and the health lines are the node's (C5's note, C8 0.11).
// How versions compare and how preconditions are read are the matcher's
// (C12, docs/phase4/C4-matcher.md); C11 only names the scheme. An entry has
// no severity, CVSS or exploitability field (R9.2).
//
// The package does no I/O. acceptTestSets in Admit and allowTestKeys in
// ValidateAnchors are the caller's build switch (otsec_testclock); no
// configuration sets them.
//
// Evidence class: desk. No advisory feed has been read, and every set built
// so far is a test set (HR-18: no real advisory is entered until the owner
// says who publishes the set and holds its key).
package advisory
