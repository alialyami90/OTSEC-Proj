# SEL-2730M documented example

- Fixture class: `documented-example`. This is not device output.
- Source document: *SEL-2730M Managed Ethernet Switch Instruction Manual* (S43), date code 20260408, owner-supplied. Appendix E, Syslog, the sample message in Introduction, p. 126.
- Transcribed by A2 on 2026-10-26. The manual wraps the message across two printed lines. It is one line here, with one space where the wrap was. Wrap point: after `by:`. The parts table that follows on the same page prints `Invalid login attempt by: root at 192.168.1.1` on one line, which confirms the single space.

What the example shows, and why to treat it with care:
- PRI `<34>` = facility 4 (security/authorization) × 8 + severity 2 (Critical).
- **The message does not match the switch's own event table.** Table E.3, sheet 1, p. 128, lists the failed login as `Login to {interface}: failed from {IP address}`, with tag `Login`, severity Notice and facility SECURITY. That would be PRI `<37>` with a `Login:` tag. The sample has no tag and a Critical severity, and its text is in no Table E.3 row. It reads as a generic RFC 3164 illustration, not something the SEL-2730M emits. The SEL-2488 example (S26 p. D.2), which follows its own table, does have the `<37>` and `Login:` form.
- The header time is `Jul 09 2009 08:17:29`: a year after the day, and the day zero-padded, as in the SEL-2488 and RTAC examples. A strict RFC 3164 parser misreads it.
- The parts table puts `myhostname` in HEADER and starts MSG at `Invalid`. There is no tag.
- No UTC offset is described for the SEL-2730M.

Other facts from the same pages:
- RFC 3164 over UDP port 514. Up to three remote destinations and 60,000 local messages, each destination with its own logging threshold (Section 5, Syslog Settings). The packet size limit is 1024 bytes (p. 125).
- Table E.3 lists every event the switch logs, with tag, severity and facility. Variables appear in braces, for example `{username}`.

A golden for this dialect should keep the raw bytes, and should not take the tag or severity of a real SEL-2730M login failure from this sample.
