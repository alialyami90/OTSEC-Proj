package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// listenConfig is a node with the SEL-751 asset sending Syslog from
// 127.0.0.1 on syslog-udp and syslog-tcp, and mod's listeners.
func listenConfig(t *testing.T, mod func(*nodeconfigtest.Config)) (*nodeconfigtest.Config, string) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300).
		AddSyslogSender(relayID, "syslog-udp-out", "syslog-udp", "127.0.0.1", 0).
		AddSyslogSender(relayID, "syslog-tcp-out", "syslog-tcp", "127.0.0.1", 0).
		AddSyslogSender(relayID, "syslog-tls-out", "syslog-tls", "127.0.0.1", 0)
	mod(nc)
	return nc, dir
}

// serve starts the node's listeners and stops them at cleanup.
func serve(t *testing.T, r *Runtime) *Listening {
	t.Helper()
	ls, err := NewListening(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := ls.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { defer close(done); ls.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return ls
}

// waitStored waits until listener id has stored n messages, as status
// shows it.
func waitStored(t *testing.T, ls *Listening, st *Status, id string, n int64) ListenerStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ls.Publish()
		got := st.Snapshot("x").Listeners[id]
		if got.Stored >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %s: %+v, want %d stored", id, got, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func streamEvents(t *testing.T, r *Runtime, stream c5.StreamID) []*event.Event {
	t.Helper()
	got, err := r.Store(stream).Read(bg, stream, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []*event.Event
	for _, s := range got {
		e, err := event.Decode(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func dialFrom(t *testing.T, network, local string, to net.Addr) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	switch network {
	case "udp":
		d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(local)}
	default:
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
	}
	c, err := d.Dial(network, to.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// The node receives on every configured listener: a datagram from the
// asset's address is stored byte for byte on the listener's stream and
// attributed to the asset; a stream message from an address no asset
// sends from is kept, unattributed, and alarmed on the health stream; and
// status shows each listener's counts.
func TestListenersStoreAndAttribute(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0").AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
	})
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)

	msg := []byte("<134>1 2026-10-26T12:00:00.000001Z relay1 sel 1 ID47 - SER: 52BKR1 Asserted")
	if _, err := dialFrom(t, "udp", "127.0.0.1", ls.Addr("lab-udp")).Write(msg); err != nil {
		t.Fatal(err)
	}
	udp := waitStored(t, ls, st, "lab-udp", 1)
	if !udp.Open || udp.Received != 1 || udp.LastMessage.IsZero() || udp.Transport != "syslog-udp" || !udp.Plaintext {
		t.Fatalf("udp listener status: %+v", udp)
	}
	// Each plaintext listener is recorded at start (D3-5).
	var posture []string
	for _, rec := range auditRecords(t, r) {
		if rec.Action == audit.ActionNodePostureChange && rec.ReasonCode == ReasonPlaintextListener {
			posture = append(posture, rec.Detail)
		}
	}
	if len(posture) != 2 || !strings.HasPrefix(posture[0], "listener lab-udp receives syslog-udp on 127.0.0.1:") || !strings.HasPrefix(posture[1], "listener lab-tcp receives syslog-tcp on 127.0.0.1:") {
		t.Fatalf("plaintext listeners recorded: %q", posture)
	}
	evs := streamEvents(t, r, ListenerStream("lab-udp"))
	if len(evs) != 1 {
		t.Fatalf("%d events on the udp stream", len(evs))
	}
	e := evs[0]
	if e.Kind != event.KindSyslog || e.Native == nil || !bytes.Equal(e.Native.Bytes, msg) {
		t.Fatalf("stored event: kind %s native %+v", e.Kind, e.Native)
	}
	if e.Source.Asset == nil || e.Source.Asset.ID != relayID {
		t.Fatalf("datagram from the asset's address not attributed: %+v", e.Source)
	}

	tcp := dialFrom(t, "tcp", "127.0.0.2", ls.Addr("lab-tcp"))
	if _, err := tcp.Write([]byte("<13>Oct 26 12:00:00 unknown hello\n")); err != nil {
		t.Fatal(err)
	}
	waitStored(t, ls, st, "lab-tcp", 1)
	evs = streamEvents(t, r, ListenerStream("lab-tcp"))
	if len(evs) != 1 || evs[0].Source.Asset != nil || !slices.Contains(evs[0].Flags, "asset-unresolved") {
		t.Fatalf("unknown sender's message: %+v", evs)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.ContainsFunc(streamEvents(t, r, HealthStream), func(e *event.Event) bool {
		return e.Health != nil && e.Health.Type == "syslog.unknown-source"
	}) {
		if time.Now().After(deadline) {
			t.Fatal("no syslog.unknown-source on the health stream")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := st.Snapshot("x").Listeners["lab-tcp"]; got.UnknownSenders != 1 {
		t.Fatalf("tcp listener status: %+v", got)
	}
}

// A syslog-tls listener takes its certificate and the senders' CA set from
// its references in tls_dir. With require_sender_cert, a sender with a
// certificate from that CA is stored as tls-mutual, and one with none is
// refused at the handshake with nothing stored.
func TestTLSListenerFromReferences(t *testing.T) {
	var p *nodeconfigtest.PKI
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		var err error
		if p, err = nc.WritePKI("127.0.0.1", "test-ca", "test-client"); err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredential(p, "test-listener", "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
		nc.Listeners[0].TLS.SenderCARef = "test-ca"
		nc.Listeners[0].TLS.RequireSenderCert = true
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)

	dial := func(certs []tls.Certificate) (*tls.Conn, error) {
		raw := dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tls"))
		c := tls.Client(raw, &tls.Config{RootCAs: p.Roots, ServerName: "127.0.0.1", Certificates: certs, MinVersion: tls.VersionTLS12})
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if err := c.Handshake(); err != nil {
			return nil, err
		}
		return c, nil
	}
	// With TLS 1.3 the client's handshake returns before the server has
	// checked its certificate, so the refusal shows on the first read.
	if c, err := dial(nil); err == nil {
		c.Write([]byte("<13>1 - - - - - - no certificate\n"))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("a sender with no certificate was read from")
		}
	}
	c, err := dial([]tls.Certificate{p.Client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("<13>1 - - - - - - mutual\n")); err != nil {
		t.Fatal(err)
	}
	if got := waitStored(t, ls, st, "lab-tls", 1); got.Plaintext {
		t.Fatalf("tls listener shown as plaintext: %+v", got)
	}
	if slices.ContainsFunc(auditRecords(t, r), func(rec *audit.Record) bool { return rec.ReasonCode == ReasonPlaintextListener }) {
		t.Fatal("tls listener recorded as plaintext")
	}
	evs := streamEvents(t, r, ListenerStream("lab-tls"))
	if len(evs) != 1 || !bytes.Contains(evs[0].Native.Bytes, []byte("mutual")) || evs[0].Source.OriginAuth != "tls-mutual" {
		t.Fatalf("stored: %d events, %+v", len(evs), evs)
	}
	if got := st.Snapshot("x").Listeners["lab-tls"]; got.Refused["tls"] < 1 {
		t.Fatalf("refused handshake not counted: %+v", got)
	}
}

// A TLS listener whose reference names a missing key stops the node before
// anything listens; nothing falls back to plaintext.
func TestTLSListenerBadReferenceStops(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredential(p, "other", "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := NewListening(r); err == nil || !strings.Contains(err.Error(), "listener lab-tls") {
		t.Fatalf("missing credential: %v", err)
	}
}

// If one listener cannot bind, Listen fails and releases the ones it bound,
// so the node stops rather than run without a listener it names.
func TestListenFailureReleasesBound(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	free.Close()
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("a-first", "syslog-tcp", freeAddr).AddListener("b-second", "syslog-tcp", busy.Addr().String())
	})
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls, err := NewListening(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := ls.Listen(); err == nil {
		t.Fatal("a listener on a bound address listened")
	}
	again, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Fatalf("the first listener's address was not released: %v", err)
	}
	again.Close()
}

// The listener's Log refuses, writing nothing, while its stream's database
// is not open; the receiver then holds or drops as its class says.
func TestLiveLogRefusesWithoutDatabase(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {})
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := (liveLog{r, ListenerStream("absent")}).AppendBatch(bg, []c5.Record{{Stream: ListenerStream("absent")}}); err == nil {
		t.Fatal("a batch for a stream with no open database was accepted")
	}
}

// The loader's listener rules: plaintext only behind the lab flag, TLS only
// with references, and no flag or section on the wrong transport.
func TestListenerConfigRules(t *testing.T) {
	for name, c := range map[string]struct {
		mod  func(*nodeconfigtest.Listener)
		want string
	}{
		"udp without plaintext": {func(l *nodeconfigtest.Listener) { l.Transport, l.TLS, l.Plaintext = "syslog-udp", nil, false }, `needs "plaintext": true`},
		"tcp without plaintext": {func(l *nodeconfigtest.Listener) { l.Transport, l.TLS, l.Plaintext = "syslog-tcp", nil, false }, `needs "plaintext": true`},
		"tls with plaintext":    {func(l *nodeconfigtest.Listener) { l.Plaintext = true }, "plaintext is set on a syslog-tls"},
		"tls without a section": {func(l *nodeconfigtest.Listener) { l.TLS = nil }, "needs a tls section"},
		"udp with a tls section": {func(l *nodeconfigtest.Listener) {
			l.Transport, l.Plaintext = "syslog-udp", true
		}, "tls is set on a syslog-udp"},
		"require without a CA":   {func(l *nodeconfigtest.Listener) { l.TLS.RequireSenderCert = true }, "needs sender_ca_ref"},
		"credential is a path":   {func(l *nodeconfigtest.Listener) { l.TLS.CredentialRef = "../key" }, "is not a reference"},
		"credential is a device": {func(l *nodeconfigtest.Listener) { l.TLS.CredentialRef = "nul" }, "is not a reference"},
		"empty credential":       {func(l *nodeconfigtest.Listener) { l.TLS.CredentialRef = "" }, "is not a reference"},
		"CA is a path":           {func(l *nodeconfigtest.Listener) { l.TLS.SenderCARef = "a/b" }, "is not a reference"},
	} {
		nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddListener("lab-tls", "syslog-tls", "127.0.0.1:6514")
		c.mod(&nc.Listeners[0])
		if _, err := ParseConfig(nc.Bytes()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddListener("lab-tls", "syslog-tls", "127.0.0.1:6514")
	nc.Listeners[0].TLS.SenderCARef, nc.Listeners[0].TLS.RequireSenderCert = "test-ca", true
	nc.TLSDir = ""
	if _, err := ParseConfig(nc.Bytes()); err == nil || !strings.Contains(err.Error(), "tls_dir is required") {
		t.Errorf("references without tls_dir: %v", err)
	}
}
