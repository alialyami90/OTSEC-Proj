package adapter

import (
	"bytes"
	"regexp"
)

// The language probe (ADR-0005, A1 ruling 4687c17; A6 F-007). Before ACC,
// the transport sends QUI once at Level 0, and only after it has received
// the "=" prompt (A3, C3 re-check): a bare line end may wake the port, but
// no register line is sent before the prompt. In English, QUIT is valid at
// Level 0 and changes nothing (S22 Table 7.59). The reply must match the
// grammar below, or the transport closes without elevating and the
// invocation ends with refused.language_probe_rejected. Any other reply fails
// closed, because the reply of a non-English port is undocumented.
//
// The grammar, over the bytes received after the probe line until the
// prompt, in ABNF (RFC 5234) with case-sensitive strings unless marked:
//
//	reply      = *blank [echo *blank] [header *blank] [level0 *blank] "="
//	echo       = "QUI" ["T"] *SP eol            ; the relay echoing the line (A3 §8.3, unverified)
//	header     = rid-line tid-line              ; S22 Table 7.16, Figure 1.4
//	rid-line   = id-text 1*SP "Date:" 1*SP date 1*SP "Time:" 1*SP time *SP eol
//	tid-line   = id-text 1*SP "Time Source:" 1*SP source *SP eol
//	id-text    = 0*16(ALPHA / DIGIT / "." / "-" / SP)   ; RID, TID: S22 Table 4.1
//	date       = 1*2DIGIT "/" 1*2DIGIT "/" 4DIGIT / 4DIGIT "/" 1*2DIGIT "/" 1*2DIGIT  ; DATE_F
//	time       = 2DIGIT ":" 2DIGIT ":" 2DIGIT ["." 3DIGIT]  ; Figure 1.4 has no ms; Table 7.16 has
//	source     = %i"internal" / %i"external"
//	level0     = "Level 0" *SP eol
//	blank      = *SP eol
//	eol        = CR LF / LF / CR
//
// Before matching, the stream bytes stripFraming names are removed: NUL
// (0x00), XON (0x11) and XOFF (0x13), which the relay may send on the ASCII
// stream (S22 Appendix C; Phase 0 §7), and STX (0x02) and ETX (0x03), which
// frame every relay message (S22 p. 7.28). They stay in the transcript.
// Nothing may follow the "=" prompt, and "=>" or any other prompt fails the
// probe.
//
// Evidence: S22 Figure 1.4 (p. 1.12) shows QUIT answered by the two header
// lines and "="; that example is from Level 1. The Level 0 reply, the echo
// and any "Level 0" line are not documented (H-13). Until a hardware capture
// confirms the form, a reply this grammar rejects is refused, never guessed.
var probeReply = regexp.MustCompile(`^` +
	blank + `*` +
	`(?:QUIT? *` + eol + blank + `*)?` +
	`(?:` + idText + ` +Date: +` + date + ` +Time: +` + clock + ` *` + eol +
	idText + ` +Time Source: +(?i:internal|external) *` + eol + blank + `*)?` +
	`(?:Level 0 *` + eol + blank + `*)?` +
	`=$`)

const (
	eol    = `(?:\r\n|\n|\r)`
	blank  = `(?: *` + eol + `)`
	idText = `[A-Za-z0-9.\- ]{0,16}`
	date   = `(?:[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}|[0-9]{4}/[0-9]{1,2}/[0-9]{1,2})`
	clock  = `[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?`
)

// ProbeReplyAccepted reports whether rx, the bytes received after the probe line,
// is an accepted reply to the language probe.
func ProbeReplyAccepted(rx []byte) bool {
	clean := stripFraming(rx)
	for _, c := range clean {
		if c > 0x7e || (c < 0x20 && c != '\r' && c != '\n') {
			return false
		}
	}
	return probeReply.Match(clean)
}

// stripFraming removes the bytes of the SEL ASCII stream that carry no text:
// NUL, XON and XOFF (S22 Appendix C), and the STX and ETX that frame every
// message. S22 p. 7.28: "The relay transmits all messages in the following
// format: <STX><MESSAGE LINE 1><CRLF> ... <LAST MESSAGE LINE><CRLF><ETX>".
// Where the prompt sits relative to ETX is not documented (H-13), so the
// probe grammar ignores both wherever they occur, and prompt detection
// (promptOf) treats them as line boundaries. Records and observations still
// point into the bytes as received, and never include a framing byte.
func stripFraming(rx []byte) []byte {
	return bytes.Map(func(r rune) rune {
		switch r {
		case 0x00, 0x02, 0x03, 0x11, 0x13:
			return -1
		}
		return r
	}, rx)
}
