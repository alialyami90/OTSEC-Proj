# SEL-2488 documented example

- Fixture class: `documented-example`. This is not device output.
- Source document: *SEL-2488 Satellite-Synchronized Network Clock Instruction Manual* (S26), date code 20260918, owner-supplied. Appendix D, Syslog, the sample message before Table D.3, p. D.2.
- Transcribed by A2 on 2026-10-26. The manual wraps the message across two printed lines. It is one line here, with one space where the wrap was. Wrap point: after `web:`. Table D.3 on the same page prints the same message on one line, which confirms the single space.

What the example shows:
- PRI `<37>` = facility 4 (security/authorization) × 8 + severity 5 (Notice). This matches Table D.4 p. D.6, where `Login to {interface}: failed from {user_ip}` has tag `Login`, severity Notice and facility SECURITY.
- The header time is `Jul 09 2009 08:17:29`: a year after the day, and the day zero-padded. RFC 3164's TIMESTAMP has neither, so a strict RFC 3164 parser misreads it. The RTAC example (S23 p. 636) has the same year-after-day form.
- `Login:` is the tag (Table D.4's Tag column), followed by the message text.

**The UTC offset is not in this example (D24).** Section 18, Remote Syslog Reporting, p. 18.4, says the SEL-2488 sends RFC 3164 "with the enhancement that the SEL-2488 time stamps include the local time offset to UTC". The only printed wire message, this one, carries no offset. The manual gives no other wire example, so where the offset goes in the header, and in what form, is **unknown** from S26.

The only printed form of the offset is the *local* web Syslog Report (Section 18, Figure 18.1, p. 18.2). It is not the wire format:
- The text says `{date} {time}{offset from UTC}`, with the date as YYYY-MM-DD and the time as hh:mm:ss.zzzzzz. The offset is "the number of hours and minutes the local time is offset from UTC". A positive offset means local time is ahead of UTC, so the offset is subtracted to get UTC.
- The figure shows values such as `2015-09-29 15:23:06.582712-07`: the offset is printed as hours only (`-07`), not hours and minutes. Some values have five fraction digits (`2015-09-29 13:29:38.61733-07`), so trailing zeros appear to be dropped.

A parser should not assume the wire time stamp looks like either form until a capture shows it. The safe default is to keep the raw header, and to read the offset as unknown when it is not where the parser expects it. That avoids reading the offset as the hostname.

Other facts from the same pages:
- UDP port 514, fixed and not settable. Up to three destinations, each with its own severity threshold (Table 18.1 p. 18.5, default Warning). The packet size limit is 1024 bytes (p. D.1).
- Times are local time, from the Local Time Zone Offset and Daylight Saving Time Mode settings (p. 18.2).
