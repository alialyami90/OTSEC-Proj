package security

// C7 0.4 on the collector (#153, D2-11): a spent admin nonce is refused
// across a restart, from the state file alone; capacity holds; and a clock
// that jumps forward and back must not let a spent nonce be spent again
// while the request it belongs to still verifies. A6's own state files
// through the collector's exported State; ground truth is D2-11 ("a signed
// request is good for one decision, even across a restart"). Class:
// simulated.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collector"
)

type a6Clock struct{ t time.Time }

func (c *a6Clock) now() time.Time { return c.t }

func a6NewNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, authz.AdminNonceLen)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func a6State(t *testing.T, c *a6Clock) (string, *collector.State) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := collector.InitState(path, c.t); err != nil {
		t.Fatal(err)
	}
	s, err := collector.OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return path, s
}

func a6AdminCheck(err error) authz.AdminCheck {
	var r *authz.AdminRejected
	if errors.As(err, &r) {
		return r.Check
	}
	return ""
}

func TestAdminNonceSpentAcrossRestart(t *testing.T) {
	c := &a6Clock{time.Date(2026, 10, 26, 15, 0, 0, 0, time.UTC)}
	path, s := a6State(t, c)
	n := a6NewNonce(t)
	exp := c.t.Add(10 * time.Minute)
	if err := s.SpendAdminNonce(n, exp); err != nil {
		t.Fatal(err)
	}
	// A restart: a new State from the file, nothing carried in memory.
	for i := 0; i < 2; i++ {
		r, err := collector.OpenState(path, c.now)
		if err != nil {
			t.Fatal(err)
		}
		if got := a6AdminCheck(r.SpendAdminNonce(n, exp)); got != authz.AdminCheckReplay {
			t.Fatalf("restart %d: spending the nonce again gave check %q, want replay", i, got)
		}
		c.t = c.t.Add(time.Minute)
	}
}

func TestAdminNonceCapacityAcrossRestart(t *testing.T) {
	c := &a6Clock{time.Date(2026, 10, 26, 15, 0, 0, 0, time.UTC)}
	path, s := a6State(t, c)
	exp := c.t.Add(10 * time.Minute)
	for i := 0; i < collector.MaxAdminNonces; i++ {
		if err := s.SpendAdminNonce(a6NewNonce(t), exp); err != nil {
			t.Fatalf("nonce %d: %v", i, err)
		}
	}
	r, err := collector.OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := a6AdminCheck(r.SpendAdminNonce(a6NewNonce(t), exp)); got != authz.AdminCheckCapacity {
		t.Fatalf("past capacity after a restart: check %q", got)
	}
	c.t = exp.Add(time.Second)
	if err := r.SpendAdminNonce(a6NewNonce(t), c.t.Add(10*time.Minute)); err != nil {
		t.Fatalf("after every held nonce expired: %v", err)
	}
}

// The nonce of a request still inside its window must stay spent, whatever
// the clock did meanwhile. A clock moved forward past the expiry drops the
// nonce at the next spend; moved back inside the window, the same signed
// request must still be refused: as a replay, or as expired at the
// collector's admin clock, which never goes back (A3's fix on #153). Either
// refusal holds across a restart. A clock that only lags a little, never
// having gone forward, still finds the nonce spent.
func TestAdminNonceSurvivesAClockJump(t *testing.T) {
	start := time.Date(2026, 10, 26, 15, 0, 0, 0, time.UTC)
	c := &a6Clock{start}
	path, s := a6State(t, c)
	n := a6NewNonce(t)
	exp := start.Add(10 * time.Minute)
	if err := s.SpendAdminNonce(n, exp); err != nil {
		t.Fatal(err)
	}
	if got := a6AdminCheck(s.SpendAdminNonce(n, exp)); got != authz.AdminCheckReplay {
		t.Fatalf("spent twice at once: check %q, want replay", got)
	}
	c.t = start.Add(time.Hour) // forward, past the expiry
	if err := s.SpendAdminNonce(a6NewNonce(t), c.t.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.t = start.Add(time.Minute) // back, inside the first request's window
	refused := func(where string, err error) {
		t.Helper()
		if got := a6AdminCheck(err); got != authz.AdminCheckReplay && got != authz.AdminCheckWindow {
			t.Errorf("%s: a spent nonce spent again after the clock went forward and back: check %q, err %v", where, got, err)
		}
	}
	refused("same process", s.SpendAdminNonce(n, exp))
	r, err := collector.OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	refused("after a restart", r.SpendAdminNonce(n, exp))
}
