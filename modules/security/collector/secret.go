package collector

import (
	"bytes"
	"errors"
	"sync"
)

var (
	// ErrSecretUsed is returned by a second Use in one session: the
	// credential slot opens at most once per session (C7-A6-2).
	ErrSecretUsed = errors.New("collector: the credential slot was already used in this session")
	// ErrSecretClosed is returned by Use after the run is over.
	ErrSecretClosed = errors.New("collector: the credential slot is closed")
)

// SecretHandle is the single-use credential slot for one run (HR-3, C-17):
// the sel751.Secret of the seam agreed with A2. It holds the decrypted
// secret from Acquire until Close, which the collector calls after the
// adapter's Run returns, and then zeroes it.
//
// The secret is kept in a byte slice, never a string, so it can be wiped.
// Go cannot promise that no other copy exists (design section 10); the
// handle keeps the window short.
type SecretHandle struct {
	mu      sync.Mutex
	b       []byte
	used    bool
	scanned bool // EchoSpans has seen the first reply after Use
	closed  bool
}

// Use calls f once with a copy of the secret, and wipes the copy when f
// returns, so the adapter cannot keep or change the stored bytes. A second
// Use fails with ErrSecretUsed without calling f.
func (h *SecretHandle) Use(f func(secret []byte) error) error {
	h.mu.Lock()
	switch {
	case h.closed:
		h.mu.Unlock()
		return ErrSecretClosed
	case h.used:
		h.mu.Unlock()
		return ErrSecretUsed
	}
	h.used = true
	c := append([]byte(nil), h.b...)
	h.mu.Unlock()
	defer clear(c)
	return f(c)
}

// minPartialEcho is the shortest leading part of the secret that EchoSpans
// redacts at the end of a cut reply.
const minPartialEcho = 3

// EchoSpans returns the non-overlapping ranges of rx that equal the secret,
// as half-open [start, end) offsets, so the adapter can redact each one.
//
// The first reply after Use, the reply to the password line, can also end
// inside an echo, when it was cut by the response budget, a timeout or a
// close. For that reply only, a trailing run of at least minPartialEcho bytes
// that equals the start of the secret is returned too. Later replies get
// whole matches only: a partial match on device data would redact it, and
// the redaction would show the secret's first bytes (A6 on #106). The first
// reply is the first call after Use, which is how the SEL-751 adapter calls
// it (#99: every non-empty reply once the secret is sent, in order).
//
// A reply that ends in a prompt was not cut, so its tail is never treated as
// a partial echo: no partial match is returned when rx, without trailing
// spaces, NUL, XON and XOFF, ends in "=", ">" or "?", the last byte of every
// SEL prompt (=, =>, =>>, Password: ?). A cut echo that ends in one of those
// bytes is then not redacted; that, and a cut shorter than minPartialEcho,
// is what this leaves. It returns nil once the handle is closed.
func (h *SecretHandle) EchoSpans(rx []byte) [][2]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.b) == 0 {
		return nil
	}
	var spans [][2]int
	off := 0
	for off <= len(rx)-len(h.b) {
		i := bytes.Index(rx[off:], h.b)
		if i < 0 {
			break
		}
		spans = append(spans, [2]int{off + i, off + i + len(h.b)})
		off += i + len(h.b)
	}
	first := h.used && !h.scanned
	if h.used {
		h.scanned = true
	}
	if !first || endsInPromptByte(rx) {
		return spans
	}
	for n := min(len(h.b)-1, len(rx)-off); n >= minPartialEcho; n-- {
		if bytes.Equal(rx[len(rx)-n:], h.b[:n]) {
			spans = append(spans, [2]int{len(rx) - n, len(rx)})
			break
		}
	}
	return spans
}

// endsInPromptByte reports whether rx, without trailing spaces, NUL, XON and
// XOFF, ends in the last byte of a SEL prompt.
func endsInPromptByte(rx []byte) bool {
	t := bytes.TrimRight(rx, " \x00\x11\x13")
	if len(t) == 0 {
		return false
	}
	switch t[len(t)-1] {
	case '=', '>', '?':
		return true
	}
	return false
}

// Close wipes the secret. It is safe to call more than once.
func (h *SecretHandle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.b)
	h.b = nil
	h.closed = true
}
