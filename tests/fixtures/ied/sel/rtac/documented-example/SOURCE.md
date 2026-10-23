# SEL RTAC documented example

- Fixture class: `documented-example`. This is not device output.
- Source document: *ACSELERATOR RTAC SEL-5033 Software Instruction Manual*, date code 20260925, owner-supplied. Section 8, Syslog, Table 8.16 and the example after it, p. 636.
- Transcribed by A2 on 2026-10-23. The manual wraps the message across three printed lines; it is one line here, with single spaces where the wraps were. Wrap points: after `2015-03-21` and after `'SEL`. The space before `User_Logged_On` is as printed. Whether the real message contains it is unknown.

Facts from the same pages:
- RFC 3164 format, packet size limit 1024 bytes.
- Facility fixed at 23, so PRI = 184 + severity; `<190>` = Informational.
- The header time is the RTAC system time when sent. The event time inside MSG is the tag time stamp, in milliseconds.
- In the example the two times differ by 9.4 s (12:09:58.593 vs 12:10:08), so the header time must not be used as the event time.
- The header includes a year (`Mar 21 2015`), which RFC 3164's TIMESTAMP field does not. A strict RFC 3164 parser will misread it.
- The hostname is `SEL-3530-xxxxxx` with the manual's own placeholder.
