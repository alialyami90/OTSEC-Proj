// Package applicability is the R9 matcher: it matches one asset's identity
// against every entry of the advisory set in use (C11) and returns C12
// findings. Its design is docs/phase4/C4-matcher.md, and the cells it must
// produce are GT-ADV's (tests/integration/gt_adv).
//
// It is a pure function. It reads only what the node passes in, and it has
// no clock, store, file or network, so it can send nothing to a device
// (V-M8). The node stores what it returns.
//
// For each entry, the first step that applies decides the class (note §5):
//
//  1. The entry does not name the identity's product: not-applicable, by the
//     identity's source, with reason product-not-named.
//  2. The FID cannot be placed on a branch (an X branch, a form not read, or
//     parts that disagree with model and firmware_version):
//     applicable-by-version, with firmware-version unread. Such a FID is
//     never not-applicable, unless the product is not named. A range with no
//     endpoint still covers it.
//  3. Outside every range: not-applicable, by source, with reason
//     outside-range. Branches are never ordered.
//  4. Inside: (a) a precondition read false decides first (D4-49 Q5);
//     (b) any mitigation that holds gives mitigated; (c) a current
//     device-read identity with every precondition evidenced gives
//     confirmed; (d) otherwise applicable-by-version, with each unread
//     precondition named and stale identity evidence marked, citing the read
//     that made it stale.
//
// A finding is returned only when it is new or differs from the asset's
// latest one for that entry in anything C12 §7 lists, and then as the next
// revision. A change to identity.latest_read alone records nothing.
package applicability
