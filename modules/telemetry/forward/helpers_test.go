package forward

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
)

// Everything here is constructed test data: throwaway keys, targets and
// events made in the test. The one device event is C4's documented example
// (Figure 10.16 row 8, contracts/event/testdata), read from its file.

const (
	node      = event.NodeID("site-a-node1")
	serStream = store.StreamID("sel751-feeder1/ser")
	hlStream  = store.StreamID("platform/health")
	auStream  = store.StreamID("platform/audit")
)

// pki is a throwaway CA with a collector and a node certificate.
type pki struct {
	roots      *x509.CertPool
	server     tls.Certificate
	client     tls.Certificate
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverName string
}

func newPKI(t testing.TB) *pki {
	t.Helper()
	caKey := key(t)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a4-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{roots: x509.NewCertPool(), caCert: ca, caKey: caKey, serverName: "collector.test"}
	p.roots.AddCert(ca)
	p.server = p.issue(t, "collector.test", []string{"collector.test"}, x509.ExtKeyUsageServerAuth)
	p.client = p.issue(t, string(node), nil, x509.ExtKeyUsageClientAuth)
	return p
}

func key(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var serial = big.NewInt(100)

func (p *pki) issue(t testing.TB, cn string, dns []string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	k := key(t)
	serial.Add(serial, big.NewInt(1))
	tmpl := &x509.Certificate{SerialNumber: new(big.Int).Set(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// serverTLS checks the node the way D2-9 commissions a collector: chain to
// the CA and the name on a one-name permitted-peer list.
func (p *pki) serverTLS(permitted string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{p.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.roots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, n := range certNames(cs.PeerCertificates[0]) {
				if n == permitted {
					return nil
				}
			}
			return errors.New("peer not permitted")
		},
	}
}

// targetJSON is a constructed required relp-tls target; port is filled in.
const targetJSON = `{
  "schema": "otsec.syslog/0.2",
  "name": "siem-a",
  "host": "127.0.0.1",
  "port": 1,
  "transport": "relp-tls",
  "format": "rfc5424",
  "framing": "relp",
  "class": "required",
  "max_message_octets": 2048,
  "facility": 16,
  "tls": {"server_name": "collector.test", "trust_anchor_ref": "a4-test-ca", "client_credential_ref": "a4-test-node"},
  "relp_window": 8,
  "durable_ack": {
    "verified_utc": "2026-10-24T09:00:00Z",
    "evidence_ref": "a4-test/durable-ack",
    "peer_check": "name",
    "permitted_peer": "site-a-node1",
    "ack_after": "durable-write"
  }
}`

func newTarget(t testing.TB, port int, mut func(*syslog.Target)) *syslog.Target {
	t.Helper()
	tg, err := syslog.ParseTarget([]byte(targetJSON))
	if err != nil {
		t.Fatal(err)
	}
	tg.Port = port
	if mut != nil {
		mut(tg)
	}
	if err := tg.Validate(); err != nil {
		t.Fatal(err)
	}
	return tg
}

// memStore is an in-memory C5 outbox, cursor store and health sink with
// the behaviour the forwarder depends on: Read past the prune point
// returns the first retained events, SaveCursor refuses regress and ahead.
type memStore struct {
	mu      sync.Mutex
	events  map[store.StreamID][]store.Stored
	last    map[store.StreamID]store.Seq
	cursors map[store.StreamID]map[store.ConsumerID]store.Seq
	saves   []store.Cursor
}

func newStore() *memStore {
	return &memStore{events: map[store.StreamID][]store.Stored{}, last: map[store.StreamID]store.Seq{},
		cursors: map[store.StreamID]map[store.ConsumerID]store.Seq{}}
}

// commit appends e to stream with the next seq and returns its key.
func (m *memStore) commit(t testing.TB, stream store.StreamID, e event.Event) store.Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last[stream]++
	e.ID = event.EventID{NodeID: node, Stream: stream, Seq: m.last[stream]}
	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatal(err)
	}
	m.events[stream] = append(m.events[stream], store.Stored{Key: e.ID, Event: b, CommittedAt: time.Now()})
	return e.ID
}

// commitRaw appends bytes that are not a C4 event (an audit record).
func (m *memStore) commitRaw(stream store.StreamID, b []byte) store.Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last[stream]++
	k := event.EventID{NodeID: node, Stream: stream, Seq: m.last[stream]}
	m.events[stream] = append(m.events[stream], store.Stored{Key: k, Event: b})
	return k
}

func (m *memStore) prune(stream store.StreamID, through store.Seq) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evs := m.events[stream]
	for len(evs) > 0 && evs[0].Key.Seq <= through {
		evs = evs[1:]
	}
	m.events[stream] = evs
}

func (m *memStore) Read(_ context.Context, stream store.StreamID, after store.Seq, max int) ([]store.Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Stored
	for _, e := range m.events[stream] {
		if e.Key.Seq > after && len(out) < max {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memStore) ReadCapture(context.Context, string) (store.Capture, error) {
	return store.Capture{}, errors.New("not used")
}

func (m *memStore) ChainAnchor(context.Context, store.StreamID) (store.ChainLink, error) {
	return store.ChainLink{}, errors.New("not used")
}

func (m *memStore) SaveCursor(_ context.Context, c store.Cursor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs := m.cursors[c.Stream]
	if cs == nil {
		cs = map[store.ConsumerID]store.Seq{}
		m.cursors[c.Stream] = cs
	}
	if c.Through < cs[c.Consumer] {
		return errors.New("cursor regress")
	}
	if c.Through > m.last[c.Stream] {
		return errors.New("cursor ahead")
	}
	cs[c.Consumer] = c.Through
	m.saves = append(m.saves, c)
	return nil
}

func (m *memStore) LoadCursors(_ context.Context, stream store.StreamID) ([]store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Cursor
	for id, through := range m.cursors[stream] {
		out = append(out, store.Cursor{Consumer: id, Stream: stream, Through: through})
	}
	return out, nil
}

func (m *memStore) cursor(stream store.StreamID) store.Seq {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[stream]["siem-a"]
}

// sink commits health events to the health stream of a memStore.
type sink struct {
	t testing.TB
	m *memStore
}

func (s sink) Emit(_ context.Context, h event.Health) (store.Key, error) {
	e := healthEvent(h.Type, h.Details)
	e.Health.Related = h.Related
	e.ID = event.EventID{NodeID: node, Stream: hlStream}
	if err := e.ValidatePending(); err != nil {
		return store.Key{}, err
	}
	return s.m.commit(s.t, hlStream, e), nil
}

func healthEvent(typ string, details map[string]string) event.Event {
	return event.Event{
		Schema:   event.Identifier,
		Origin:   event.OriginPlatform,
		Kind:     event.KindHealth,
		Source:   event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: "2026-10-24T12:00:00.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Health:   &event.Health{Type: typ, Details: details},
	}
}

// row8 is C4's documented example of Figure 10.16 row 8.
func row8(t testing.TB) event.Event {
	t.Helper()
	b, err := os.ReadFile("../../../contracts/event/testdata/valid/sel751-fig10-16-row8.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := event.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return *e
}

// rig is a forwarder, its store and a relptest receiver over mutual TLS.
type rig struct {
	t   *testing.T
	p   *pki
	m   *memStore
	srv *relptest.Server
	tg  *syslog.Target
	cfg Config
}

func newRig(t *testing.T, script func(int, relptest.Message) relptest.Action, mut func(*syslog.Target)) *rig {
	t.Helper()
	p := newPKI(t)
	srv, err := relptest.Start(p.serverTLS(string(node)), script)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	m := newStore()
	tg := newTarget(t, srv.Addr().Port, mut)
	tc, err := ClientTLS(tg, p.roots, &p.client)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, p: p, m: m, srv: srv, tg: tg}
	r.cfg = Config{
		Target:          tg,
		Streams:         []Stream{{ID: serStream, Outbox: m, Cursors: m}, {ID: hlStream, Outbox: m, Cursors: m}},
		HealthStream:    hlStream,
		Dial:            DialTLS(tg, tc, 5*time.Second),
		Health:          sink{t: t, m: m},
		ResponseTimeout: 2 * time.Second, Poll: 10 * time.Millisecond,
		RetryMin: 5 * time.Millisecond, RetryMax: 20 * time.Millisecond,
	}
	return r
}

// run starts the forwarder and stops it when done reports true or the
// deadline passes. It returns the forwarder for its status.
func (r *rig) run(done func() bool, tweak func(*Forwarder)) *Forwarder {
	r.t.Helper()
	f, err := New(r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	if tweak != nil {
		tweak(f)
	}
	ctx, cancel := context.WithCancel(context.Background())
	end := make(chan error, 1)
	go func() { end <- f.Run(ctx) }()
	deadline := time.Now().Add(20 * time.Second)
	for !done() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-end; !errors.Is(err, context.Canceled) {
		r.t.Errorf("Run returned %v", err)
	}
	if !done() {
		r.t.Fatalf("not done within the deadline; status %+v; receiver errors %v", f.Status(), r.srv.Errors())
	}
	return f
}

// eids returns the eid of each acknowledged message, in order.
func eids(t testing.TB, ms []relptest.Message) []string {
	t.Helper()
	var out []string
	for _, m := range ms {
		s := string(m.Data)
		i := strings.Index(s, ` eid="`)
		if i < 0 {
			t.Fatalf("no eid in %q", s)
		}
		s = s[i+6:]
		out = append(out, s[:strings.IndexByte(s, '"')])
	}
	return out
}

// keys returns the eid of every event committed on stream.
func (m *memStore) keys(stream store.StreamID) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for seq := store.Seq(1); seq <= m.last[stream]; seq++ {
		out = append(out, event.EventID{NodeID: node, Stream: stream, Seq: seq}.String())
	}
	return out
}

