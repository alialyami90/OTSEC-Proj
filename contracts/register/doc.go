// Package register is contract C3, the approved command register format
// otsec.register/0.3 (A1 owns the format, A2 the content).
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
//   - The firmware allowlist for the family ships in the same package, so it
//     is covered by the same signature and anti-rollback floor (C-A2-2).
//
// # Versions
//
//   - 0.1: the Phase 1 format.
//   - 0.2 adds context. A 0.1 package with context is invalid.
//   - 0.3 adds limits and runs. This reader decodes 0.1, 0.2 and 0.3
//     packages; a package before 0.3 with limits or runs is invalid. A later
//     minor is invalid here, because the reader is strict, so a node that has
//     not been upgraded refuses a 0.3 package and keeps the floor it has (fail
//     closed). The envelope's
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
