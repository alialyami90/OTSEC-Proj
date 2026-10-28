package receive

import (
	"crypto/tls"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/store"
)

// TestReadBufferGranted: a UDP listener reports the receive buffer the OS
// granted, the default without a request, and a request changes it. The
// request is a quarter of the default: Linux doubles a request and caps it
// at rmem_max, Windows keeps it, so only a smaller request is sure to
// differ from the default on both.
func TestReadBufferGranted(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("granted size not checked on", runtime.GOOS)
	}
	def := newRig(t, asset.SyslogUDP, nil).r.Status()
	if def.ReadBuffer <= 0 || def.ReadBufferErr != "" {
		t.Fatalf("default: granted %d, error %q", def.ReadBuffer, def.ReadBufferErr)
	}
	want := max(def.ReadBuffer/4, minReadBuffer)
	g := newRig(t, asset.SyslogUDP, func(c *Config) { c.Limits.ReadBuffer = want })
	st := g.r.Status()
	if st.ReadBuffer <= 0 || st.ReadBuffer == def.ReadBuffer || st.ReadBufferErr != "" {
		t.Fatalf("asked %d of a default %d: granted %d, error %q", want, def.ReadBuffer, st.ReadBuffer, st.ReadBufferErr)
	}
	t.Logf("default %d; asked %d, granted %d", def.ReadBuffer, want, st.ReadBuffer)
	// The listener still receives.
	c := g.udp(addrA)
	defer c.Close()
	g.wait("a datagram stored", func() bool {
		c.Write([]byte("<13>Oct 27 12:00:00 host app: hello"))
		return g.store.count() > 0
	})
}

func TestReadBufferIsForUDPOnly(t *testing.T) {
	for _, tr := range []asset.Transport{asset.SyslogTCP, asset.SyslogTLS} {
		log, err := store.NewLog(&memCommitter{}, testNode, map[store.StreamID]store.StreamClass{testStream: store.ClassSyslogStream},
			store.GroupOptions{MaxEvents: 100, MaxWait: 5 * time.Millisecond}, nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg := Config{Node: testNode, ID: "lab", Stream: testStream, Transport: tr, Address: "127.0.0.1:0",
			Target: asset.Simulated, Plaintext: tr == asset.SyslogTCP, Senders: testSenders(),
			Log: log, Health: &sink{}, Received: received}
		if tr == asset.SyslogTLS {
			cfg.TLS = &tls.Config{}
		}
		// The same listener without a read buffer is accepted, so the
		// refusal below is the read buffer's.
		if _, err := New(cfg); err != nil {
			t.Fatalf("%s: %v", tr, err)
		}
		cfg.Limits.ReadBuffer = 1 << 20
		if _, err := New(cfg); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "read buffer") {
			t.Errorf("%s with a read buffer: %v", tr, err)
		}
	}
	if st := newRig(t, asset.SyslogTCP, nil).r.Status(); st.ReadBuffer != 0 || st.ReadBufferErr != "" {
		t.Errorf("a stream listener reports no read buffer: %+v", st)
	}
	for _, n := range []int{-1, minReadBuffer - 1, maxReadBuffer + 1} {
		if err := (Limits{ReadBuffer: n}).withDefaults(true).validate(); err == nil {
			t.Errorf("read buffer %d accepted", n)
		}
	}
	for _, n := range []int{0, minReadBuffer, maxReadBuffer} {
		if err := (Limits{ReadBuffer: n}).withDefaults(true).validate(); err != nil {
			t.Errorf("read buffer %d: %v", n, err)
		}
	}
}
