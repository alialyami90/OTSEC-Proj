package node

import (
	"strings"
	"testing"

	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// read_buffer_bytes is for a syslog-udp listener only, and within the
// receiver's own bounds, so the loader refuses what receive.New would.
func TestReadBufferConfig(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
		n         int
		want      string // empty: loads
	}{
		{"default", "syslog-udp", 0, ""},
		{"asked", "syslog-udp", 1 << 20, ""},
		{"smallest", "syslog-udp", MinReadBuffer, ""},
		{"largest", "syslog-udp", MaxReadBuffer, ""},
		{"too small", "syslog-udp", MinReadBuffer - 1, "read_buffer_bytes"},
		{"too large", "syslog-udp", MaxReadBuffer + 1, "read_buffer_bytes"},
		{"negative", "syslog-udp", -1, "read_buffer_bytes"},
		{"tcp", "syslog-tcp", 1 << 20, "applies to syslog-udp only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc, _ := listenConfig(t, func(nc *nodeconfigtest.Config) {
				nc.AddListener("lab", tc.transport, "127.0.0.1:0")
				nc.Listeners[0].ReadBuffer = tc.n
			})
			_, err := ParseConfig(nc.Bytes())
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// The node's bounds are the receiver's: at each end of the loader's range
// the receiver the node builds accepts the value (nothing is bound, so no
// large buffer is allocated).
func TestReadBufferBoundsAreTheReceivers(t *testing.T) {
	for _, n := range []int{MinReadBuffer, MaxReadBuffer} {
		nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
			nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
			nc.Listeners[0].ReadBuffer = n
		})
		r, _, _ := start(t, parse(t, nc), dir)
		if _, err := NewListening(r); err != nil {
			t.Errorf("read_buffer_bytes %d: %v", n, err)
		}
		r.Close()
	}
}

// The node passes the request to the socket, shows what the OS granted and
// what was asked, and raises AlarmReadBufferShort only when the grant fell
// short.
func TestReadBufferIsAppliedAndShown(t *testing.T) {
	const asked = 1 << 20
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
		nc.AddListener("lab-default", "syslog-udp", "127.0.0.1:0")
		nc.Listeners[0].ReadBuffer = asked
	})
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	ls.Publish()
	got := st.Snapshot("x").Listeners
	set, def := got["lab-udp"], got["lab-default"]
	if set.ReadBufferAsked != asked || def.ReadBufferAsked != 0 {
		t.Fatalf("asked: %d and %d", set.ReadBufferAsked, def.ReadBufferAsked)
	}
	if set.ReadBuffer == 0 || set.ReadBuffer == def.ReadBuffer {
		t.Fatalf("granted %d with a request, %d without: the request did not reach the socket", set.ReadBuffer, def.ReadBuffer)
	}
	short := set.ReadBuffer < asked || set.ReadBufferErr != ""
	if n := countAlarms(st, AlarmReadBufferShort); (n == 1) != short || n > 1 {
		t.Fatalf("%d %s alarms, granted %d of %d asked (err %q)", n, AlarmReadBufferShort, set.ReadBuffer, asked, set.ReadBufferErr)
	}
}
