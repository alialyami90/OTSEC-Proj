package syslogreceive

// The UDP receive buffer (#274, Limits.ReadBuffer): 0 or 4 KiB to 256 MiB
// is accepted, for UDP listeners only, and Status.ReadBuffer is what the OS
// granted. B6's own cases; evidence class: simulated (this OS's sockets).

import (
	"errors"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
)

func b6Receiver(t *testing.T, tr asset.Transport, buf int) (*receive.Receiver, error) {
	t.Helper()
	log, _ := open(t, 64<<20)
	stream := sDgram
	if tr != asset.SyslogUDP {
		stream = sStream
	}
	return receive.New(receive.Config{
		Node: node, ID: "b6", Stream: stream, Transport: tr, Address: "127.0.0.1:0",
		Target: asset.Simulated, Plaintext: true,
		Senders: receive.Senders{ipA: {AssetID: assetA, Target: asset.Simulated, Dialect: normalize.DialectRFC}},
		Log:     log, Health: &healths{}, Received: received, Limits: receive.Limits{ReadBuffer: buf},
	})
}

func TestB6ReadBufferBounds(t *testing.T) {
	for _, c := range []struct {
		buf int
		ok  bool
	}{{0, true}, {4 << 10, true}, {256 << 20, true}, {4<<10 - 1, false}, {256<<20 + 1, false}, {-1, false}, {1, false}} {
		_, err := b6Receiver(t, asset.SyslogUDP, c.buf)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, receive.ErrConfig)) {
			t.Errorf("UDP read buffer %d: %v, want accepted %v", c.buf, err, c.ok)
		}
	}
	if _, err := b6Receiver(t, asset.SyslogTCP, 64<<10); !errors.Is(err, receive.ErrConfig) {
		t.Errorf("TCP with a read buffer: %v", err)
	}
	if _, err := b6Receiver(t, asset.SyslogTCP, 0); err != nil {
		t.Errorf("TCP without a read buffer: %v", err)
	}
}

// The granted size is read back, not echoed: asking for less than the OS
// default gives less than the default, and the stream listener reports 0.
func TestB6ReadBufferGranted(t *testing.T) {
	granted := func(buf int) receive.Status {
		r, err := b6Receiver(t, asset.SyslogUDP, buf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Listen(); err != nil {
			t.Fatal(err)
		}
		return r.Status()
	}
	def, small := granted(0), granted(4<<10)
	t.Logf("OS default %d, asked 4096 and granted %d", def.ReadBuffer, small.ReadBuffer)
	if def.ReadBufferErr != "" || small.ReadBufferErr != "" || def.ReadBuffer <= 0 || small.ReadBuffer <= 0 || small.ReadBuffer >= def.ReadBuffer {
		t.Errorf("default %+v, 4 KiB %+v: the small request was not applied, or not read back", def, small)
	}
	r, err := b6Receiver(t, asset.SyslogTCP, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Listen(); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); st.ReadBuffer != 0 {
		t.Errorf("TCP listener reports read buffer %d", st.ReadBuffer)
	}
}
