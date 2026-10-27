// Package config is contract C9, otsec.config/0.1. It defines a device's
// configuration as read in one session (the snapshot), the semantic difference
// between two snapshots, and, per family, the rule that decides what in a
// reply is a setting and what is not (P4-A2; R3.1, R3.3, R3.5, R3.7).
// The design note is docs/phase4/B2-c9-config.md.
//
// # What it covers
//
//   - A Snapshot. It is one config.read of one asset: one Section per
//     settings class the family's rule lists, in the rule's order, so a
//     snapshot is complete by construction. Each section points at the reply
//     in the C2 transcript of the session that read it, by span, and carries
//     the SHA-256 of those bytes. It never copies them (D4-8). The transcript
//     is named by its C5 evidence ref ("sha256:<hex>", the C4
//     native.evidence.ref of the same session), so a snapshot is read
//     together with the capture the store already keeps.
//   - Each setting is a name and a value exactly as printed. A value that
//     wraps is its printed pieces joined by one space. A setting carries no
//     span of its own: CheckAgainst re-reads every setting from its
//     section's bytes by the rule, so the section span is the evidence and
//     the snapshot stays about the size of the transcript (B5, C5 0.4's
//     per-snapshot cap).
//   - A section is present or absent. It is absent when the relay answered
//     the command with the rule's "not available" reply. The reply's bytes are
//     kept, and an absent section is never a parse failure or an empty
//     section.
//   - A Difference between two snapshots of the same asset under the same
//     rule: every setting changed, added or removed, with both values, and
//     every section that appeared or disappeared.
//   - The digest of a snapshot or a difference (Digest): "sha256:" and the
//     SHA-256 of the document's stored bytes, exactly as written, with no
//     canonical JSON. It is the same rule as C10's baseline hash (D4-4 item
//     5). C7 0.6's node.change_approval and node.baseline_ack name a
//     snapshot by it (baseline_digest). C8 0.5's config.change_detected
//     names the snapshot and the difference by it (snapshot_digest and
//     difference_digest). A Difference names its two snapshots by it. A
//     configuration baseline is the snapshot an administrator acknowledged,
//     so its baseline_digest is that snapshot's digest.
//
// # The rule for SEL-751 SHO replies (sel-751-sho/1)
//
// The rule is stated here, in RuleSEL751SHO's classes, and in
// CheckAgainst, which enforces it against the transcript. A snapshot that
// passes CheckAgainst was tokenized by this rule and no other. The layout is
// S22 Figure 7.43 (p. 7.78 to 7.79), Figure D.3 and the examples on
// p. G.29. It is documented-untested: no relay has been read.
//
// A section's bytes are the reply's message text: what the relay sent after
// it echoed the command line and before the next prompt, without the STX and
// ETX that frame it (S22 p. 7.28). Lines end in CR LF, LF or CR. Each line
// is exactly one of these:
//
//   - **Blank**: only spaces.
//   - **Header**: holds "Date: <d> Time: <t>" or "Time Source: <s>", the
//     command-response header of S22 p. 7.31. A header is never a setting
//     and never a continuation, wherever it falls, so a header printed again
//     mid-reply (a page break) changes nothing.
//   - **Setting line**: holds ":=". It carries one or more settings. Each
//     setting is a name ([A-Z0-9][A-Z0-9_]*, which may start with a digit,
//     as in 51SAT, S22 Table 4.84), zero or more spaces, ":=", zero or more
//     spaces, and a value. The name starts the line after leading spaces, or
//     follows the previous value after two or more spaces. The value runs to
//     the first run of two or more spaces or to the line end. So a value may
//     hold single spaces (TID := FEEDER RELAY; a SELOGIC equation), and a
//     name may sit zero or one space from ":=" (LEA_S_R := 180.00,
//     DST_BEGM:= OFF).
//   - **Continuation**: holds no ":=", is not blank or a header, and directly
//     follows a setting line or another continuation, with no blank line
//     between. It continues the value of the last setting on the line
//     before, and its text without leading and trailing spaces is the next
//     piece of that value. This is the rule for a SELOGIC equation the relay
//     wraps (the settings sheet prints FAULT wrapped, S22 Table 4.84). S22
//     prints no wrapped SHO reply, so the rule is an assumption until a
//     capture exists (H-13, D4-8).
//   - **Heading**: any other line, such as "Group 1", "Config Settings" or
//     "DNP Map 1 Settings". Every documented heading follows a blank line or
//     starts the reply, which is what separates it from a continuation.
//
// Only settings are semantic. Headings, headers, blank lines, the column a
// setting is printed at, how a value wraps, the order of settings within a
// section, and the bytes of the frame are not. So two reads of an unchanged
// relay give an empty Difference even when the time differs, a header is
// printed again, or a value wraps at another column. The section hashes
// differ in that case, which is why the Difference compares settings and
// not hashes.
//
// Four things fail the read rather than produce a snapshot. The adapter
// keeps their bytes, as C2 requires, and reports a C2 failure, never a
// snapshot that claims to be complete:
//
//   - a reply with any other layout, or a present reply with no setting;
//   - a setting with an empty value, a value that holds ":=", or a
//     continuation that holds two spaces together;
//   - a setting name printed twice in one section;
//   - an absent reply to a class that cannot be absent.
//
// # What it deliberately leaves out
//
//   - Any write, restore or push of settings (brief §1.3). C9 describes
//     what was read and nothing else.
//   - Settings files read over FTP (ADR-0008 decision 4; the SEL-751 stays
//     on rung 3 until Q3) and every family but the SEL-751.
//   - Whether a change was approved, and baseline state (recorded, awaiting
//     acknowledgement, active). Those are C7 0.6, C8 0.5 and the node
//     (P4-A3, P4-A5).
//   - Meaning. A Difference names settings and values as printed. It does
//     not say that 50P1P is a pickup or that a change is dangerous.
//   - Masking. A section the rule marks sensitive (the port settings, which
//     hold addresses, the router and FTPUSER; S22 Table 4.104) carries its
//     values like any other section. Sensitive tells a display or an alarm
//     to mask them. No settings class prints a password: passwords are set
//     with PAS (S22 Table 7.52), not as settings.
//
// # Compatibility
//
// Readers accept every 0.x minor and ignore unknown fields (contracts/README.md).
// Section state and change kind are closed enums. A rule ID a reader does not
// know is refused, because a difference under an unknown rule cannot be
// computed or trusted. A new family or a changed rule is a new rule ID in a
// later minor, never an edit of sel-751-sho/1.
//
// Every example in testdata is constructed, not captured. The setting lines
// are copied from S22's printed examples and settings tables, and the
// evidence class of everything here is desk or simulated.
package config
