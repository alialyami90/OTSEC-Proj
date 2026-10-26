package receive

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
)

const (
	testNode   = "site-a-node1"
	testStream = store.StreamID("syslog/lab")
	assetA     = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	assetB     = "c41f8a2d-6b0e-4e97-8d13-5a2c9f7b0e64"
)

var (
	addrA = netip.MustParseAddr("127.0.0.1")
	addrB = netip.MustParseAddr("127.0.0.2")
)

// memCommitter is an in-memory C5 Committer behind a real store.Log, so
// every receipt is a real one. With refuse set it refuses every batch as a
// full quota does, having written nothing.
type memCommitter struct {
	mu     sync.Mutex
	recs   []store.Record
	refuse atomic.Bool
	calls  atomic.Int64
}

func (m *memCommitter) CommitBatch(_ context.Context, stream store.StreamID, recs []store.Record) (store.Commit, error) {
	m.calls.Add(1)
	if m.refuse.Load() {
		return store.Commit{}, &store.Error{Code: store.CodeQuotaReached, Detail: "test quota"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	first := store.Seq(len(m.recs) + 1)
	m.recs = append(m.recs, recs...)
	return store.Commit{Node: testNode, Stream: stream, FirstSeq: first, Count: len(recs), Sync: store.SyncFull, At: time.Now()}, nil
}

// events decodes every committed event, in commit order.
func (m *memCommitter) events(t testing.TB) []event.Event {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]event.Event, 0, len(m.recs))
	for _, r := range m.recs {
		var e event.Event
		if err := json.Unmarshal(r.Event, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func (m *memCommitter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recs)
}

// sink records health events.
type sink struct {
	mu   sync.Mutex
	hs   []event.Health
	fail atomic.Bool
}

func (s *sink) Emit(_ context.Context, h event.Health) (store.Key, error) {
	if s.fail.Load() {
		return store.Key{}, fmt.Errorf("test: health refused")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hs = append(s.hs, h)
	return store.Key{NodeID: testNode, Stream: "platform/health", Seq: store.Seq(len(s.hs))}, nil
}

func (s *sink) of(typ string) []event.Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []event.Health
	for _, h := range s.hs {
		if h.Type == typ {
			out = append(out, h)
		}
	}
	return out
}

func received() event.Received {
	return event.Received{UTC: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}
}

// rig is one running listener on 127.0.0.1 with an in-memory store.
type rig struct {
	t      *testing.T
	r      *Receiver
	addr   string
	store  *memCommitter
	health *sink
	cancel context.CancelFunc
	done   chan error
}

func testSenders() Senders {
	return Senders{
		addrA: {AssetID: assetA, Target: asset.Simulated, Dialect: normalize.DialectRFC},
		addrB: {AssetID: assetB, Target: asset.Simulated, Dialect: normalize.DialectRFC},
	}
}

func newRig(t *testing.T, transport asset.Transport, mut func(*Config)) *rig {
	t.Helper()
	mc := &memCommitter{}
	class := store.ClassSyslogStream
	if transport == asset.SyslogUDP {
		class = store.ClassSyslogDatagram
	}
	log, err := store.NewLog(mc, testNode, map[store.StreamID]store.StreamClass{testStream: class},
		store.GroupOptions{MaxEvents: 100, MaxWait: 5 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &sink{}
	cfg := Config{
		Node: testNode, ID: "lab", Stream: testStream, Transport: transport, Address: "127.0.0.1:0",
		Target: asset.Simulated, Plaintext: transport != asset.SyslogTLS, Senders: testSenders(),
		Log: log, Health: h, Received: received,
		Limits: Limits{Retry: 10 * time.Millisecond, ReportEvery: 20 * time.Millisecond, Grace: time.Second},
	}
	if mut != nil {
		mut(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &rig{t: t, r: r, addr: a.String(), store: mc, health: h, cancel: cancel, done: make(chan error, 1)}
	go func() { g.done <- r.Serve(ctx) }()
	t.Cleanup(g.stop)
	return g
}

// stop stops the listener and waits for Serve to return.
func (g *rig) stop() {
	g.cancel()
	select {
	case err := <-g.done:
		if err != nil {
			g.t.Errorf("Serve: %v", err)
		}
		g.done <- nil
	case <-time.After(10 * time.Second):
		g.t.Fatal("Serve did not return")
	}
}

// wait polls cond until it holds, or fails the test after 5 s.
func (g *rig) wait(what string, cond func() bool) {
	g.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			g.t.Fatalf("timed out waiting for %s; status %+v", what, g.r.Status())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// dial connects from the loopback address from (127.0.0.1 or 127.0.0.2).
func (g *rig) dial(from netip.Addr) net.Conn {
	g.t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: from.AsSlice()}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", g.addr)
	if err != nil {
		g.t.Fatal(err)
	}
	return c
}

func (g *rig) udp(from netip.Addr) net.Conn {
	g.t.Helper()
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: from.AsSlice()}}
	c, err := d.Dial("udp", g.addr)
	if err != nil {
		g.t.Fatal(err)
	}
	return c
}

// octet frames messages with RFC 5425 octet counting.
func octet(msgs ...string) []byte {
	var b []byte
	for _, m := range msgs {
		b = append(b, strconv.Itoa(len(m))+" "+m...)
	}
	return b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// msgs returns the stored message bytes in commit order.
func msgs(t testing.TB, es []event.Event) []string {
	t.Helper()
	out := make([]string, len(es))
	for i, e := range es {
		if err := e.ValidatePending(); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if e.Native.RecordSHA256 != sha(e.Native.Bytes) {
			t.Fatalf("event %d: hash does not match its bytes", i)
		}
		out[i] = string(e.Native.Bytes)
	}
	return out
}

// pki is a test CA with a listener certificate and a sender certificate.
type pki struct {
	roots  *x509.CertPool
	server tls.Certificate
	client tls.Certificate
	ca     *x509.Certificate
	key    *ecdsa.PrivateKey
}

var serial atomic.Int64

func newPKI(t testing.TB, name string) *pki {
	t.Helper()
	k := ecKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{roots: x509.NewCertPool(), ca: ca, key: k}
	p.roots.AddCert(ca)
	p.server = p.issue(t, "node.test", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	p.client = p.issue(t, "rtac.test", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	return p
}

func ecKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (p *pki) issue(t testing.TB, cn string, usage []x509.ExtKeyUsage, from, until time.Time) tls.Certificate {
	t.Helper()
	k := ecKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: from, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// sender is a TLS sender's configuration: it trusts roots for node.test and
// presents client, if any, whatever CAs the listener names (Go would
// otherwise send no certificate the listener's CA list does not cover).
func sender(roots *x509.CertPool, client *tls.Certificate) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "node.test"}
	if client != nil {
		cc := *client
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cc, nil }
	}
	return c
}
