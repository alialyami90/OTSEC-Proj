// Package register is contract C3, the approved command register format
// otsec.register/0.1 (A1 owns the format, A2 the content).
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
//     operation is literal.
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
//   - The firmware allowlist for the family ships in the same package, so it
//     is covered by the same signature and anti-rollback floor (C-A2-2).
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
