# C6 examples

None of these is device output. Host names use `example.net` (RFC 2606), addresses come from the RFC 5737 documentation range, `admin-example`, `site-a-ca`, `site-a-node1-forwarder` and `commissioning/siem-a/durable-ack` are illustrative references (TODO(A3 node key ref)); no durable-acknowledgement check has been run against any collector.

## Targets

`targets/valid/` holds one target per transport. `targets/invalid/` holds files that each break one rule. The `Schema` column says whether `schema/target.json` alone rejects the file (checked with Python `jsonschema` 4.26). Every other rule needs `Target.Validate`.

| File | Code | Schema | What it shows |
| --- | --- | --- | --- |
| `valid/relp-tls-required.json` | | | The only transport that may be `required`: mode A, with a RELP window, the node's client key (mutual TLS) and a passed durable-acknowledgement check. |
| `valid/relp-plain-best-effort.json` | | | Plain RELP: mode A acknowledgements, but best-effort and insecure; acknowledged lab-only, no device content. |
| `valid/tls-best-effort.json` | | | RFC 5425: mode B, with a one-hour replay window. |
| `valid/tcp-lf-insecure.json` | | | RFC 6587 with LF framing, for collectors that cannot count octets. Insecure: acknowledged lab-only, no device content (D1-22). |
| `valid/udp-rfc3164.json` | | | RFC 5426 with the RFC 3164 form, 1024 octets. Insecure: acknowledged lab-only, no device content. |
| `valid/relp-tls-audit.json` | | | Also carries the C8 audit stream: required relp-tls, RFC 5424, 17408 octets (D1-15). |
| `invalid/required-on-tls.json` | required-class | no | RFC 5425 cannot confirm delivery. |
| `invalid/required-on-tcp.json` | required-class | no | Neither can plain TCP. |
| `invalid/required-on-udp.json` | required-class | no | Nor UDP. |
| `invalid/required-on-relp.json` | required-class | no | Plain RELP acknowledgements can be forged on the path. |
| `invalid/tls-lf-framing.json` | framing | no | RFC 5425 requires octet counting. |
| `invalid/udp-octet-counting.json` | framing | no | UDP carries one message per datagram. |
| `invalid/size-below-floor.json` | size | yes | Below 480 octets, the RFC 5426 floor. |
| `invalid/rfc3164-over-1024.json` | size | no | RFC 3164 caps messages at 1024 octets. |
| `invalid/relp-tls-without-tls.json` | tls | no | A TLS transport names the server and trust anchor. |
| `invalid/tcp-with-tls.json` | tls | no | TLS settings on a transport without TLS. |
| `invalid/mode-b-without-replay.json` | delivery | no | A mode B target needs a replay window. |
| `invalid/relp-with-replay.json` | delivery | no | A mode A target advances on acknowledgements, not a window. |
| `invalid/misspelt-class.json` | unknown-field | yes | `clas`: targets are strict, so a typo cannot fall back to a default. |
| `invalid/case-variant-class.json` | unknown-field | yes | `CLASS` beside `class`: strictjson rejects case variants. |
| `invalid/other-major.json` | schema | yes | `otsec.syslog/1.0`. |
| `invalid/unknown-transport.json` | enum | yes | `dtls` is not a 0.1 transport. |
| `invalid/audit-over-udp.json` | audit | no | Audit over UDP: no acknowledgement that a record or checkpoint arrived (D1-15, A6 negative test). |
| `invalid/audit-over-tls.json` | audit | no | RFC 5425 TLS is authenticated but still unacknowledged. |
| `invalid/audit-target-too-small.json` | audit | no | Required relp-tls, but 2048 octets cannot hold a 16 KiB sealed record. |
| `invalid/required-without-client-credential.json` | tls | no | A required target authenticates the node with mutual TLS (C6-A3-2). |
| `invalid/required-without-durable-ack.json` | delivery | no | A required target records the commissioning check that its collector acknowledges after a durable write (C6-A6-1). |
| `invalid/malformed-spki-pin.json` | tls | yes | An SPKI pin is a base64 SHA-256. |
| `invalid/insecure-without-acknowledgement.json` | acknowledgement | no | Plain TCP without an admin's acknowledgement (D1-22). |
| `invalid/acknowledgement-production-scope.json` | acknowledgement | yes | `same-segment`: 0.1 accepts an insecure target for lab-only. |
| `invalid/acknowledgement-on-tls.json` | acknowledgement | no | An acknowledgement on a TLS target, where there is nothing to accept. |

## Rendered messages

Each file in `rendered/` is `Render` output for one C4 golden example (`contracts/event/testdata/valid/`) on one valid target. They were generated once with `go test ./contracts/syslog -run Golden -update` and then frozen. A4 checked them by hand against the parameter table in `render.go`: the PRI (facility 16, severity 5 for device events and 4 for health), the header, the order of the parameters, escaping, and the summary. `TestRenderReadBack` also reads every example back on every target, so they are not only self-consistent. The files are marked `-text` so a Windows checkout cannot change their bytes.

| File | Event | Target |
| --- | --- | --- |
| `sel751-row8.rfc5424.txt` | SEL-751 Figure 10.16 row 8 | `tls-best-effort` |
| `sel751-row8.rfc3164.txt` | the same row, without device content (`content_omitted="config"`: no `dtext`, `subj`, `val`, `cat` or summary; D1-22) | `udp-rfc3164` |
| `rtac-syslog.rfc5424.txt` | the RTAC Syslog example. The RTAC's own message, `<190>` included, sits escaped in `dtext`. | `relp-tls-required` |
| `health-ser-gap.rfc5424.txt` | a `ser.gap` platform event, severity 4 | `relp-tls-required` |
| `constructed-invalid-date.rfc5424.txt` | the constructed `02/30/2007` row: `dt` without `dwall` | `tls-best-effort` |

Hostile content (LF injection, CR LF, NUL, SD escapes, BOM, invalid UTF-8, U+2028, C1 controls) is built in `TestHostileContent` rather than stored, because it is generated from the RTAC example.
