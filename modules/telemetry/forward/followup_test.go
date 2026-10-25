package forward

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
)

// A new best-effort target starts at the first event committed in its
// replay window, not at the first retained event (C6-A5-2, A6 #89).
func TestBestEffortStartsAtWindow(t *testing.T) {
	srv, err := relptest.Start(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tg := newTarget(t, srv.Addr().Port, plainRELP) // replay_seconds 3600
	dial, err := DialTCP(tg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := newStore()
	e := row8(t)
	for range 10 {
		m.commitAt(t, serStream, e, time.Now().Add(-2*time.Hour))
	}
	for range 5 {
		m.commit(t, serStream, e)
	}
	r := &rig{t: t, m: m, srv: srv, tg: tg, cfg: Config{
		Target:       tg,
		Streams:      []Stream{{ID: serStream, Outbox: m, Cursors: m, Index: m}, {ID: hlStream, Outbox: m, Cursors: m, Index: m}},
		HealthStream: hlStream, Dial: dial, Health: sink{t: t, m: m},
		ResponseTimeout: 2 * time.Second, Poll: 10 * time.Millisecond, RetryMin: 5 * time.Millisecond,
	}}
	r.run(func() bool { return m.cursor(serStream) == 15 }, nil)
	ids := eids(t, srv.Acked())
	if want := (event.EventID{NodeID: node, Stream: serStream, Seq: 11}).String(); len(ids) != 5 || ids[0] != want {
		t.Errorf("sent %v, want the 5 events from %s", ids, want)
	}
	if n := r.healthCount(event.HealthForwardUnreachable); n != 0 {
		t.Errorf("%d forward.unreachable for events outside the window", n)
	}

	// A best-effort event stream must come with a commit index.
	c := r.cfg
	c.Streams = []Stream{{ID: serStream, Outbox: m, Cursors: m}, {ID: hlStream, Outbox: m, Cursors: m, Index: m}}
	if _, err := New(c); !errors.Is(err, ErrConfig) {
		t.Errorf("best-effort stream without a commit index: %v", err)
	}
}

// The node's client certificate is checked at load for client
// authentication and its validity dates (A3 #89).
func TestClientTLSChecksLeaf(t *testing.T) {
	p := newPKI(t)
	tg := newTarget(t, 2514, nil)
	now := time.Now()
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	for name, c := range map[string]struct {
		usage       []x509.ExtKeyUsage
		from, until time.Time
		ok          bool
	}{
		"valid, clientAuth": {client, now.Add(-time.Hour), now.Add(time.Hour), true},
		"no EKU extension":  {nil, now.Add(-time.Hour), now.Add(time.Hour), true},
		"any EKU":           {[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, now.Add(-time.Hour), now.Add(time.Hour), true},
		"serverAuth only":   {[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(time.Hour), false},
		"expired":           {client, now.Add(-2 * time.Hour), now.Add(-time.Hour), false},
		"not yet valid":     {client, now.Add(time.Hour), now.Add(2 * time.Hour), false},
	} {
		cert := p.issueAt(t, string(node), nil, c.usage, c.from, c.until)
		_, err := ClientTLS(tg, p.roots, &cert)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v is not ErrConfig", name, err)
		}
	}
}

var _ store.CommitIndex = (*memStore)(nil)
