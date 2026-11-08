package sel751

import (
	"context"
	"net"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// The ok session reports its connection (C2 0.9): the dialed socket's local
// address, and when the dial returned, no earlier than started_at and no
// later than the first byte.
func TestConnection(t *testing.T) {
	f := load(t)
	want := golden(t, "ok")
	near, far := pipe()
	done := farEnd(far, script(want), false)
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(), TIDLE: func(time.Duration) {},
		hooks: &hooks{quiet: 20 * time.Millisecond, wakeWait: 50 * time.Millisecond},
		Dial:  func(context.Context, string, string) (net.Conn, error) { return near, nil }}
	got := Run(context.Background(), f.inv, cfg)
	if err := <-done; err != nil {
		t.Errorf("far end: %v", err)
	}
	check(t, f, got)
	if got.Status != adapter.StatusOK || got.Session.LocalAddr != "192.0.2.10:49152" {
		t.Fatalf("status %s, local_addr %q", got.Status, got.Session.LocalAddr)
	}
	at, _ := time.Parse(time.RFC3339Nano, got.Session.ConnectedAt)
	start, _ := time.Parse(time.RFC3339Nano, got.StartedAt)
	first, _ := time.Parse(time.RFC3339Nano, got.Transcript.Segments[0].At)
	if at.Before(start) || !at.Before(first) {
		t.Errorf("connected_at %s, started_at %s, first segment %s", got.Session.ConnectedAt, got.StartedAt, got.Transcript.Segments[0].At)
	}
}

// A connection with no IP local address cannot be tied to its flow, so the
// adapter sends nothing and reports a session that never connected.
func TestConnectionWithoutAddress(t *testing.T) {
	f := load(t)
	near, far := net.Pipe()
	got := make(chan int, 1)
	go func() {
		n, _ := far.Read(make([]byte, 64))
		got <- n
	}()
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
		Dial: func(context.Context, string, string) (net.Conn, error) { return near, nil }}
	r := Run(context.Background(), f.inv, cfg)
	check(t, f, r)
	if r.Error == nil || r.Error.Code != adapter.FailedInternal || r.Session.Connected || len(r.Transcript.Data) != 0 {
		t.Fatalf("result %s", jsonOf(t, r))
	}
	if n := <-got; n != 0 {
		t.Errorf("the far end received %d bytes", n)
	}
}
