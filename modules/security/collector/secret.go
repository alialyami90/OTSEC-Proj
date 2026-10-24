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
	mu     sync.Mutex
	b      []byte
	used   bool
	closed bool
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

// EchoSpans returns the non-overlapping ranges of rx that equal the secret,
// as half-open [start, end) offsets, so the adapter can redact each one. It
// returns nil once the handle is closed.
func (h *SecretHandle) EchoSpans(rx []byte) [][2]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.b) == 0 {
		return nil
	}
	var spans [][2]int
	for off := 0; off <= len(rx)-len(h.b); {
		i := bytes.Index(rx[off:], h.b)
		if i < 0 {
			break
		}
		spans = append(spans, [2]int{off + i, off + i + len(h.b)})
		off += i + len(h.b)
	}
	return spans
}

// Close wipes the secret. It is safe to call more than once.
func (h *SecretHandle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.b)
	h.b = nil
	h.closed = true
}
