package syslog

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// MaxRELPDataLen bounds the DATA of an inbound RELP frame. The responses a
// collector sends are a status line, or the offers answering "open"; 4096
// octets holds both with room to spare (E-A4-03).
const MaxRELPDataLen = 4096

// ErrIncomplete reports that the buffer holds the start of a valid frame
// but not all of it. The caller reads more bytes and calls again. It never
// accompanies a frame that has already broken the grammar.
var ErrIncomplete = errors.New("syslog: incomplete RELP frame")

// RELPResponse is everything a node takes from an upstream collector.
type RELPResponse struct {
	TXNR  uint64
	Close bool // serverclose: the collector is closing the session
	OK    bool // rsp with status 200
	// Data is the rsp data after the status line, for example the offers
	// answering "open". Nothing in it advances a cursor.
	Data []byte
}

// ParseRELPResponse reads one frame from the start of buf. It is the whole
// inbound grammar of TB5: the only bytes a node accepts from a collector
// besides TLS records are
//
//	TXNR SP COMMAND SP DATALEN [SP DATA] LF
//
// with TXNR 1 to 9 digits and no leading zero, COMMAND "rsp" or
// "serverclose", DATALEN 1 to 4 digits, at most MaxRELPDataLen, and DATA of
// exactly DATALEN octets, present exactly when DATALEN > 0. An rsp must name
// a transaction for which outstanding reports true, and its data must start
// with "200 OK" (an acknowledgement) or "500" (a refusal), followed by end,
// SP or LF. A serverclose has TXNR 0 and no data.
//
// It returns the frame and the number of octets it used, ErrIncomplete, or
// an *Error with CodeRELPViolation. On a violation the forwarder closes the
// connection, saves no cursor from it and reconnects: a collector that
// breaks the grammar is never believed.
func ParseRELPResponse(buf []byte, outstanding func(txnr uint64) bool) (RELPResponse, int, error) {
	var r RELPResponse
	s := &relpScan{b: buf}
	txnr, err := s.number(9)
	if err != nil {
		return r, 0, err
	}
	if err := s.expect(' '); err != nil {
		return r, 0, err
	}
	cmd, err := s.word(len("serverclose"))
	if err != nil {
		return r, 0, err
	}
	if cmd != "rsp" && cmd != "serverclose" {
		return r, 0, violation("command %q is not rsp or serverclose", cmd)
	}
	if err := s.expect(' '); err != nil {
		return r, 0, err
	}
	n, err := s.number(4)
	if err != nil {
		return r, 0, err
	}
	if n > MaxRELPDataLen {
		return r, 0, violation("DATALEN %d exceeds %d", n, MaxRELPDataLen)
	}
	var data []byte
	if n > 0 {
		if err := s.expect(' '); err != nil {
			return r, 0, err
		}
		if len(buf)-s.i < int(n) {
			return r, 0, ErrIncomplete
		}
		data = buf[s.i : s.i+int(n)]
		s.i += int(n)
	}
	if err := s.expect('\n'); err != nil {
		return r, 0, err
	}
	r.TXNR = txnr
	switch cmd {
	case "serverclose":
		if txnr != 0 || n != 0 {
			return RELPResponse{}, 0, violation("serverclose has TXNR 0 and no data")
		}
		r.Close = true
	case "rsp":
		if txnr == 0 || outstanding == nil || !outstanding(txnr) {
			return RELPResponse{}, 0, violation("rsp for transaction %d, which is not outstanding", txnr)
		}
		code, rest := data, []byte(nil)
		if len(data) > 3 {
			code, rest = data[:3], data[3:]
			if rest[0] != ' ' && rest[0] != '\n' {
				return RELPResponse{}, 0, violation("status %q", data[:4])
			}
		}
		switch string(code) {
		case "200":
			if !bytes.HasPrefix(rest, []byte(" OK")) || (len(rest) > 3 && rest[3] != ' ' && rest[3] != '\n') {
				return RELPResponse{}, 0, violation("status 200 without OK")
			}
			r.OK = true
		case "500":
		default:
			return RELPResponse{}, 0, violation("status %q is not 200 or 500", code)
		}
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			r.Data = rest[i+1:]
		}
	}
	return r, s.i, nil
}

func violation(format string, a ...any) error {
	return &Error{Code: CodeRELPViolation, Field: "relp", Detail: fmt.Sprintf(format, a...)}
}

type relpScan struct {
	b []byte
	i int
}

// number reads 1 to max digits with no leading zero, followed by a byte
// that is not a digit.
func (s *relpScan) number(max int) (uint64, error) {
	start := s.i
	for s.i < len(s.b) && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
		s.i++
		if s.i-start > max {
			return 0, violation("number longer than %d digits", max)
		}
	}
	if s.i == len(s.b) {
		return 0, ErrIncomplete
	}
	digits := s.b[start:s.i]
	if len(digits) == 0 {
		return 0, violation("digits expected at %d", start)
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, violation("leading zero at %d", start)
	}
	return strconv.ParseUint(string(digits), 10, 64)
}

// word reads 1 to max lowercase letters, followed by a byte that is not one.
func (s *relpScan) word(max int) (string, error) {
	start := s.i
	for s.i < len(s.b) && s.b[s.i] >= 'a' && s.b[s.i] <= 'z' {
		s.i++
		if s.i-start > max {
			return "", violation("command longer than %d letters", max)
		}
	}
	if s.i == len(s.b) {
		return "", ErrIncomplete
	}
	if s.i == start {
		return "", violation("command expected at %d", start)
	}
	return string(s.b[start:s.i]), nil
}

func (s *relpScan) expect(c byte) error {
	if s.i == len(s.b) {
		return ErrIncomplete
	}
	if s.b[s.i] != c {
		return violation("%q expected at %d, found %q", c, s.i, s.b[s.i])
	}
	s.i++
	return nil
}
