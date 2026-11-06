// Package register is contract C3, the approved command register format
// otsec.register/0.4 (A1 owns the format, A2 the content).
//
// A register package lists, for one device family, every line the collector
// may send and the conditions under which it may send them. It serves risk 1
// in docs/architecture.md ("read-only is not guaranteed by the device"), B-02,
// HR-2, AP-7 and V-S5, and carries A3's changes C-A2-1 and C-A2-2.
//
// The format is built so that an unrestricted line cannot be expressed:
//
//   - Operations are line templates made of upper-case ASCII letters and
//     digits separated by single spaces, plus typed parameters (bounded
//     unsigned integers or fixed enumerations). No regular expression, free
//     text or control character can reach a rendered line.
//   - Only read-only operations are invocable (C2 names them by ID).
//     Session-control lines (ACC, QUI) live in a separate list, carry the
//     transport phase that may send them, and are never invocable (C-A2-1).
//     An operation runs in the operate phase unless it also lists probe
//     (sel.id, sent before ACC for the firmware check, C3-1); a probe
//     operation is literal and needs access level 0 (C3-A2 note 5).
//   - Deny rules are regular expressions over outgoing lines. They document
//     known dangerous lines and act as a second barrier: a package whose
//     approved line matches a deny rule is invalid.
//   - Anything not listed is denied.
//   - Lines are produced only by Matcher.Render, which refuses a rendered
//     line that does not classify as its own operation, and every line the
//     transport sends must pass Matcher.Permit for its phase at egress.
//   - Device settings the collector checks are in the package: preconditions
//     refuse collection when they do not hold (LANG := ENGLISH), branch
//     conditions refuse a firmware branch (EHTTP := N), and warnings are
//     reported by ID without refusing (MAXACC, FTPACC, HTTPACC above 1,
//     C3-2).
//   - Context reads (0.2, D3-2) name a setting an operation needs to be
//     read correctly, read with another operation of the package in the
//     same session: DATE_F, read with SHO G, for SER. A context read refuses
//     nothing and adds no line; it lets the collector send its read_by line
//     only in a run of an operation in for (adapter CheckLines). read_by
//     runs in operate at an access level no higher than any operation in
//     for. Its line counts against the run's line and rate limits and is
//     kept in the raw capture like any other.
//   - Limits and runs (0.3, P4-A2, D4-13) let one session read many lines.
//     An operation's limits give the bytes and time its reply may take. A run
//     is a named, ordered list of operations sent in one session, which a C2
//     invocation may name. A step is a literal, read-only operation that runs
//     in operate at access level 1 or lower and has limits; a run holds at
//     most 32 steps, none twice, leads with the precondition and
//     firmware-condition reads, and holds the warning reads and each step's
//     context read (before it). Its total bytes and deadline are at most C2's
//     ceilings (1 MiB, 600 s), and a step's limits are within them. A run
//     fails as a whole: when a step fails, the adapter sends QUI, keeps every
//     byte read and reports the read failed. Matcher.RenderRun produces the
//     lines, and Matcher.Permit still checks every one on its own, so a run
//     adds no line the register does not already permit. A run is read-only
//     without exception: a state-changing or Level 2 step is invalid.
//   - SNMP operations (0.4, C3 0.4, D4-53) are SNMPv3 reads. The PDU is a
//     closed enum of get, getnext and getbulk, so a SET cannot be written,
//     and every OID is literal dotted decimal under 1.3.6.1. A get names 1 to
//     16 OIDs; a getnext or getbulk walks one subtree within its walk bounds
//     (at most 2048 varbinds and 64 requests), getbulk with max_repetitions
//     1 to 32. Limits are required, and max_reply_bytes, 484 to 65,507 (the
//     largest UDP payload over IPv4; C1 on #445), is the msgMaxSize every
//     request advertises. A run is all SNMP steps or all
//     line steps, because one run is one session on one transport, and an
//     SNMP run has no gate, warning or context reads. SNMP operations never
//     reach Matcher: they are not lines, so Render and RenderRun refuse
//     them, and the SNMP client reads them with Package.SNMPOperation. What
//     the collector does with them (discovery, USM, retransmission) is in
//     docs/phase4/C2-c1-0.3-c3-0.4.md §2.3 and C3's #437.
//   - The firmware allowlist for the family ships in the same package, so it
//     is covered by the same signature and anti-rollback floor (C-A2-2).
//
// # Versions
//
//   - 0.1: the Phase 1 format.
//   - 0.2 adds context. A 0.1 package with context is invalid.
//   - 0.3 adds limits and runs.
//   - 0.4 adds snmp_operations, and a package may hold SNMP operations only.
//     This reader decodes 0.1 to 0.4 packages. A later minor is invalid
//     here, because the reader is strict, so a node that has not been
//     upgraded refuses a 0.4 package and keeps the floor it has (fail
//     closed).
//   - A key introduced at a version is refused by its presence in any package
//     below that version, whatever its value: an empty list and null count,
//     as an older reader refuses the key (D4-16). That covers context before
//     0.2, runs and limits before 0.3, and snmp_operations before 0.4. The
//     envelope's
//     contract is an unsigned label: C7 accepts any stamp in Readable (D3-4),
//     and the signed payload names its own contract. SigningDomain stays
//     "otsec.register/0.1 package\n" in every minor, so a signature made over
//     a 0.1 package is unchanged.
//
// Readers are strict: unknown fields, unknown parameter kinds and unknown
// classifications make the package invalid. A package that fails validation
// must be treated as absent, and a family with no valid package is not
// collected from.
//
// Signature verification rules (key handling, the anti-rollback floor kept by
// the node) belong to C7. This package defines only the envelope's shape.
//
// Out of scope here: the secret line sent after the password prompt (never a
// register line; the transport handles it), binary protocols, and the
// rendering of bytes on the wire (the transport's egress check).
package register
