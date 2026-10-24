package syslog

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// MaxRELPDataLen bounds the DATA of an inbound RELP frame. The responses a
// collector sends are a status line, or the offers answering "open"; 4096
// octets holds both with room to spare (E-A4-03).
const MaxRELPDataLen = 4096

// MaxRELPFrameLen is the longest frame the grammar allows: a 9-digit TXNR,
// SP, "serverclose", SP, a 4-digit DATALEN, SP, MaxRELPDataLen octets of
// DATA and LF. ParseRELPResponse never returns ErrIncomplete for a buffer
// this long, so a caller that buffers at most MaxRELPFrameLen octets per
// frame is bounded however slowly the collector sends (C6-A1-3).
const MaxRELPFrameLen = 9 + 1 + 11 + 1 + 4 + 1 + MaxRELPDataLen + 1

// DefaultRELPResponseTimeout bounds the wait for the response to the oldest
// outstanding transaction. When it expires, the forwarder closes the
// session and sends every unacknowledged transaction again on the next one
// (C6-A3-8), and reports the target as stalled.
const DefaultRELPResponseTimeout = 30 * time.Second

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
// A transaction stops being outstanding when its first response is parsed
// (Window.Answer), so a second response for the same TXNR is a violation,
// never a second acknowledgement (C6-A1-1, C6-A3-1).
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

// Errors from Window. Both end the session: the forwarder closes the
// connection and, on the next session, sends again every transaction that
// was not acknowledged. Nothing is skipped.
var (
	ErrRefused       = errors.New("syslog: RELP transaction refused (500)")
	ErrSessionClosed = errors.New("syslog: RELP session closed by the collector")
	ErrWindowFull    = errors.New("syslog: RELP window full")
	ErrBadOpen       = errors.New("syslog: RELP open not acknowledged with commands=syslog")
)

// Window applies the mode A cursor rule to one RELP session (C6-A3-1). It
// is pure bookkeeping: the forwarder maps each TXNR to the C5 seq it
// carried.
//
//   - Transactions are sent in increasing TXNR order, at most size in flight.
//   - The open transaction's acknowledgement advances nothing, and its offers
//     must include commands=syslog, or the session is closed.
//   - The cursor advances to transaction N only when every transaction sent
//     up to N has a 200 OK. An OK for N while an earlier one is still in
//     flight advances nothing until the earlier one is acknowledged.
//   - A 500, a serverclose, a timeout or a closed connection ends the
//     session. The cursor stays at the last contiguous acknowledgement, and
//     every transaction after it is sent again.
//
// Use Outstanding as the outstanding argument of ParseRELPResponse.
type Window struct {
	size    int
	open    uint64
	last    uint64
	pending []uint64 // sent, in order, not yet covered by the cursor
	answer  map[uint64]bool
	dead    error
}

// NewWindow starts a session whose open command is transaction openTXNR.
func NewWindow(size int, openTXNR uint64) *Window {
	return &Window{size: size, open: openTXNR, last: openTXNR, answer: map[uint64]bool{}}
}

// Send records that transaction txnr was sent.
func (w *Window) Send(txnr uint64) error {
	switch {
	case w.dead != nil:
		return w.dead
	case w.open != 0:
		return ErrBadOpen
	case txnr <= w.last:
		return fmt.Errorf("syslog: TXNR %d after %d", txnr, w.last)
	case len(w.pending) >= w.size:
		return ErrWindowFull
	}
	w.pending = append(w.pending, txnr)
	w.last = txnr
	return nil
}

// Outstanding reports whether txnr was sent and has had no response.
func (w *Window) Outstanding(txnr uint64) bool {
	if txnr == w.open && w.open != 0 {
		return true
	}
	for _, t := range w.pending {
		if t == txnr {
			_, answered := w.answer[t]
			return !answered
		}
	}
	return false
}

// Answer applies one parsed response. It returns the TXNR the cursor may
// now advance to, or 0 when it does not move.
func (w *Window) Answer(r RELPResponse) (uint64, error) {
	if w.dead != nil {
		return 0, w.dead
	}
	if r.Close {
		w.dead = ErrSessionClosed
		return 0, w.dead
	}
	if !w.Outstanding(r.TXNR) {
		w.dead = violation("rsp for transaction %d, which is not outstanding", r.TXNR)
		return 0, w.dead
	}
	if r.TXNR == w.open {
		if !r.OK || !offersSyslog(r.Data) {
			w.dead = ErrBadOpen
			return 0, w.dead
		}
		w.open = 0
		return 0, nil
	}
	w.answer[r.TXNR] = r.OK
	if !r.OK {
		w.dead = ErrRefused
		return 0, w.dead
	}
	var advance uint64
	for len(w.pending) > 0 && w.answer[w.pending[0]] {
		advance = w.pending[0]
		delete(w.answer, advance)
		w.pending = w.pending[1:]
	}
	return advance, nil
}

// offersSyslog reports whether the offers answering open include a
// commands offer that lists syslog.
func offersSyslog(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if v, ok := bytes.CutPrefix(line, []byte("commands=")); ok {
			for _, c := range bytes.Split(v, []byte(",")) {
				if string(c) == "syslog" {
					return true
				}
			}
		}
	}
	return false
}
