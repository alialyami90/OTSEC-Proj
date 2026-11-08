package sel751datef

// C2 0.9 (docs/phase4/D2-c2-0.9.md §6), D6's test 2, SEL half: over a real
// TCP socket on loopback, the result's session.local_addr is the address
// the far end saw the connection come from, and connected_at is no later
// than the first byte. The far end is A6's scripted relay behind a
// listener, which reports the peer address itself, so the value is checked
// from outside the adapter. Evidence class: simulated.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/modules/ied/sel751"
)

func TestC2v09LocalAddrIsWhatTheRelaySaw(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	rl := &relay{showG: globals("MDY"), ser: serBody("10/24/2026")}
	var (
		mu   sync.Mutex
		seen []string
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			seen = append(seen, c.RemoteAddr().String())
			mu.Unlock()
			go rl.serve(c)
		}
	}()
	f := load(t, nil)
	clock := time.Date(2026, 10, 24, 9, 15, 0, 0, time.UTC)
	var cmu sync.Mutex
	cfg := sel751.Config{
		Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: &secret{}, Floor: floor{},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
		Now: func() time.Time {
			cmu.Lock()
			defer cmu.Unlock()
			clock = clock.Add(50 * time.Millisecond)
			return clock
		},
		TIDLE: func(time.Duration) {},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := sel751.Run(ctx, f.inv, cfg)
	if code(r) != "ok" {
		t.Fatalf("code %s: %+v", code(r), r.Error)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("the relay saw %d connections, want 1: %v", len(seen), seen)
	}
	s := r.Session
	if !s.Connected || s.LocalAddr != seen[0] || !adapter.ValidLocalAddr(s.LocalAddr) {
		t.Errorf("local_addr %q (connected %v), the relay saw %q", s.LocalAddr, s.Connected, seen[0])
	}
	at, err1 := time.Parse(time.RFC3339Nano, s.ConnectedAt)
	first, err2 := time.Parse(time.RFC3339Nano, r.Transcript.Segments[0].At)
	start, err3 := time.Parse(time.RFC3339Nano, r.StartedAt)
	if err1 != nil || err2 != nil || err3 != nil || at.After(first) || at.Before(start) {
		t.Errorf("connected_at %s, started_at %s, first segment %s", s.ConnectedAt, r.StartedAt, r.Transcript.Segments[0].At)
	}
}
