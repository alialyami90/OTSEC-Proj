package sel751

import (
	"bytes"
	"errors"

	"otsec.local/otsec/contracts/adapter"
)

// The SEL ASCII port frames every message: "<STX><MESSAGE LINE 1><CRLF> ...
// <LAST MESSAGE LINE><CRLF><ETX>" (S22 p. 7.28). The command echo comes
// before STX and the prompt after ETX; where the prompt sits relative to
// ETX is not documented (H-13), and the C2 goldens and A6's simulator both
// assume after.
const (
	stx = 0x02
	etx = 0x03
)

// message is the text of one framed reply and where it starts in the bytes
// it was cut from, so spans point into the bytes as received (C2 EP-2).
type message struct {
	text []byte
	off  int64
}

var (
	errNoMessage   = errors.New("sel751: no STX ... ETX message in the reply")
	errTwoMessages = errors.New("sel751: more than one framed message in the reply")
)

// frame cuts the one framed message out of a reply. off is where rx starts
// in the transcript. A reply with no message, an unterminated one, or two
// is refused rather than guessed at.
func frame(rx []byte, off int64) (message, error) {
	s := bytes.IndexByte(rx, stx)
	if s < 0 {
		return message{}, errNoMessage
	}
	e := bytes.IndexByte(rx[s+1:], etx)
	if e < 0 {
		return message{}, errNoMessage
	}
	e += s + 1
	if bytes.IndexByte(rx[e+1:], stx) >= 0 || bytes.IndexByte(rx[s+1:e], stx) >= 0 {
		return message{}, errTwoMessages
	}
	return message{text: rx[s+1 : e], off: off + int64(s) + 1}, nil
}

// line is one line of a message without its line end.
type line struct {
	b   []byte
	off int64 // in the transcript
}

// lines splits a message at CR LF, CR or LF. Line ends are never part of a
// line, so no record span holds one (C6-A2).
func (m message) lines() []line {
	var out []line
	start := 0
	for i := 0; i < len(m.text); i++ {
		c := m.text[i]
		if c != '\r' && c != '\n' {
			continue
		}
		out = append(out, line{b: m.text[start:i], off: m.off + int64(start)})
		if c == '\r' && i+1 < len(m.text) && m.text[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(m.text) {
		out = append(out, line{b: m.text[start:], off: m.off + int64(start)})
	}
	return out
}

// span returns the transcript span of b[i:j] within l.
func (l line) span(i, j int) adapter.Span {
	return adapter.Span{Offset: l.off + int64(i), Length: int64(j - i)}
}

// trimmed is the line without trailing spaces: the manual's columns are
// space-padded, and a span ends at the last printed character.
func (l line) trimmed() []byte { return bytes.TrimRight(l.b, " ") }
