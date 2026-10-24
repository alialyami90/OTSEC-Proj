# C6 `RenderAudit` and `ParseAudit`: A6 review

- **Reviewed:** PR #63 at `e1dfca8` (`contracts/syslog/audit.go`), A4.
- **Reviewer:** A6, 2026-10-24.
- **Method:**
  - A6 sealed its own chain of five records with `audit.Seal`. One record has a detail with U+202E, and one has a detail with a line feed.
  - Each record went through `RenderAudit` on an audit target at exactly `MinAuditOctets`, and was read back with `ParseAudit`.
  - `audit.VerifyChain` then ran over the bytes read back.
  - Each message was then changed one way at a time.
  - The probe is in the project files at `phase1/reviews/C6-audit-A6-probes.go.txt`. A6 commits it as a contract test once #63 merges.
- **Evidence class:** `desk`.

## Outcome: accepted

Change 1 should be made in C8, and it does not block this PR.

## Probes

| Case | Result |
| --- | --- |
| Five records rendered, parsed back, and the chain verified over the bytes read back, against a head checkpoint | passes; MSG is exactly the sealed bytes |
| A detail with a line feed | escaped by the seal (`\n`); no control byte in the message |
| An audit target one octet below `MinAuditOctets` | refused |
| A pending (unsealed) record passed to `RenderAudit` | refused |
| `hash`, `seq`, `node`, HOSTNAME, severity, MSGID or TIMESTAMP changed | each refused by `ParseAudit` |
| `seq="02"`; an extra parameter; a second SD element; `\]` hidden in a parameter | refused |
| One byte of MSG changed; MSG with a BOM; MSG with a trailing LF | refused (hash mismatch) |
| Record 1's header carried with record 2's MSG | refused |

The largest record, with a 63-character node ID and a 512-byte detail, is 919 bytes, well inside `MaxRecordBytes` (16 KiB). The header and SD element take a few hundred octets, so `MinAuditOctets` (`MaxRecordBytes` + 1024) holds any record C8 accepts. `RenderAudit`'s too-large error is therefore reachable only through a broken contract, which matches what `doc.go` says.

## Should (C8, A3)

**1. A bidi control in `detail` reaches the SIEM raw.** `Seal` re-encodes with `encoding/json`, which escapes control bytes, `<`, `>`, `&`, U+2028 and U+2029, but not other format characters. A detail containing U+202E (right-to-left override) is sealed raw, and `RenderAudit` puts it unchanged into MSG, as it must. A SIEM that displays MSG can then show the text reordered.

C6 sends Cf characters in device text as `dtext_b64` for this reason. Audit cannot do the same, because MSG must stay the sealed bytes, so the fix belongs in C8. Change: either have `ValidatePending` refuse Unicode format characters (category Cf) in free-text fields, or have `Seal` escape every non-ASCII rune as `\uXXXX`, so that sealed records are ASCII.
