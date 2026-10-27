package syslogreceive

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
	"otsec.local/otsec/platform/store"
)

const (
	node    = "node-a6"
	assetA  = "6a6a6a6a-0001-4a6a-8a6a-000000000001"
	assetB  = "6a6a6a6a-0002-4a6a-8a6a-000000000002"
	sStream = c5.StreamID("syslog/a6-stream")
	sDgram  = c5.StreamID("syslog/a6-dgram")
)

var (
	ipA = netip.MustParseAddr("127.0.0.1")
	ipB = netip.MustParseAddr("127.0.0.2")
)

// stored is one committed event as A6 reads it back from the database file
// with its own SQLite connection: the oracle never goes through the
// product's decoder.
type stored struct {
	Seq    int64
	Raw    []byte
	Bytes  []byte
	Record string
	EvSHA  string
	EvLen  int64
	Length int64
	Flags  []string
	Asset  *struct {
		ID      string `json:"id"`
		Binding struct {
			Method     string `json:"method"`
			Confidence string `json:"confidence"`
		} `json:"binding"`
	}
	Sender     string
	Leaf       string // source.sender.tls_leaf_sha256 (C4 0.2)
	OriginAuth string
	Class      string
	ID         event.EventID
	// Received is when the listener read the message (received.utc), taken
	// as each frame is read, before the store.
	Received time.Time
}

func (s stored) has(flag string) bool {
	for _, f := range s.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

// healths records what the listener raises.
type healths struct {
	mu sync.Mutex
	hs []event.Health
	n  int
}

func (h *healths) Emit(_ context.Context, e event.Health) (c5.Key, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hs = append(h.hs, e)
	h.n++
	return c5.Key{NodeID: node, Stream: "platform/health", Seq: c5.Seq(h.n)}, nil
}

func (h *healths) of(typ string) []event.Health {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []event.Health
	for _, e := range h.hs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

type rig struct {
	t      *testing.T
	r      *receive.Receiver
	log    *c5.Log
	addr   net.Addr
	db     string
	stream c5.StreamID
	h      *healths
	stop   context.CancelFunc
	done   chan error
}

// open opens the real syslog database through C5 startup with a quota per
// class, and a real c5.Log over it.
func open(t *testing.T, quota int64) (*c5.Log, string) {
	t.Helper()
	d := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(d, ""); err != nil {
		t.Fatal(err)
	}
	db := c5.Database{
		ID: "syslog", Writer: "telemetry",
		Streams: []c5.StreamSpec{{ID: sStream, Class: c5.ClassSyslogStream}, {ID: sDgram, Class: c5.ClassSyslogDatagram}},
		Classes: []c5.StreamClass{c5.ClassSyslogStream, c5.ClassSyslogDatagram},
		Quotas: []c5.Quota{{Class: c5.ClassSyslogStream, Bytes: quota, WarnFraction: 0.9},
			{Class: c5.ClassSyslogDatagram, Bytes: quota, WarnFraction: 0.9}},
	}
	e, err := store.NewEnv(store.Options{Dir: d, Node: node, Database: db})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(context.Background(), e, c5.StartupPolicy{
		Streams:                db.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50, CompactStepPages: 32, PruneTarget: 0.8,
	})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup: %s %v", r.Mode, r.Alarms)
	}
	t.Cleanup(func() { r.Store.Close(); r.Unlock() })
	sdb, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatal("not a platform store")
	}
	l, err := c5.NewLog(sdb, node, map[c5.StreamID]c5.StreamClass{sStream: c5.ClassSyslogStream, sDgram: c5.ClassSyslogDatagram},
		c5.GroupOptions{MaxEvents: 64, MaxWait: 5 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l, filepath.Join(d, "syslog.db")
}

func received() event.Received {
	return event.Received{UTC: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000,
		Clock: event.Clock{Sync: event.SyncSynchronized}}
}

// start serves one listener on 127.0.0.1 with asset A at 127.0.0.1 and
// asset B at 127.0.0.2, both simulated.
func start(t *testing.T, tr asset.Transport, tlsCfg *tls.Config, lim receive.Limits, mod ...func(*receive.Config)) *rig {
	t.Helper()
	return startQuota(t, 64<<20, tr, tlsCfg, lim, mod...)
}

func startQuota(t *testing.T, quota int64, tr asset.Transport, tlsCfg *tls.Config, lim receive.Limits, mod ...func(*receive.Config)) *rig {
	t.Helper()
	log, path := open(t, quota)
	stream := sStream
	if tr == asset.SyslogUDP {
		stream = sDgram
	}
	h := &healths{}
	cfg := receive.Config{
		Node: node, ID: "a6", Stream: stream, Transport: tr, Address: "127.0.0.1:0",
		Target: asset.Simulated, TLS: tlsCfg, Plaintext: tr != asset.SyslogTLS,
		Senders: receive.Senders{
			ipA: {AssetID: assetA, Target: asset.Simulated, Dialect: normalize.DialectRFC},
			ipB: {AssetID: assetB, Target: asset.Simulated, Dialect: normalize.DialectRFC},
		},
		Log: log, Health: h, Received: received, Limits: lim,
	}
	for _, m := range mod {
		m(&cfg)
	}
	r, err := receive.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := r.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &rig{t: t, r: r, log: log, addr: addr, db: path, stream: stream, h: h, stop: cancel, done: make(chan error, 1)}
	go func() { g.done <- r.Serve(ctx) }()
	t.Cleanup(g.close)
	return g
}

func (g *rig) close() {
	if g.stop == nil {
		return
	}
	g.stop()
	g.stop = nil
	start := time.Now()
	select {
	case err := <-g.done:
		if err != nil {
			g.t.Errorf("Serve: %v", err)
		}
		return
	case <-time.After(serveReturn):
	}
	// Late is still a failure. Keep waiting, up to serveLate, so the
	// failure says whether Serve returned at all: a commit stuck after
	// Grace and a slow store look the same at serveReturn.
	select {
	case err := <-g.done:
		g.t.Errorf("Serve did not return within %v; it returned after %v (err %v)", serveReturn, time.Since(start).Round(time.Millisecond), err)
	case <-time.After(serveLate - serveReturn):
		g.t.Errorf("Serve did not return within %v, nor by %v", serveReturn, serveLate)
	}
}

// serveReturn is the default Limits.Grace (5 s) plus 10 s for the commit in
// flight. serveLate only bounds how long a failing close keeps measuring.
const serveReturn, serveLate = 15 * time.Second, 120 * time.Second

// events reads every event of the listener's stream, in seq order.
func (g *rig) events() []stored {
	g.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		g.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT seq, event FROM events WHERE stream = ? ORDER BY seq", string(g.stream))
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	var out []stored
	for rows.Next() {
		var s stored
		if err := rows.Scan(&s.Seq, &s.Raw); err != nil {
			g.t.Fatal(err)
		}
		var e struct {
			ID       event.EventID  `json:"id"`
			Received event.Received `json:"received"`
			Source   struct {
				Asset *struct {
					ID      string `json:"id"`
					Binding struct {
						Method     string `json:"method"`
						Confidence string `json:"confidence"`
					} `json:"binding"`
				} `json:"asset"`
				Sender *struct {
					Address string `json:"address"`
					Leaf    string `json:"tls_leaf_sha256"`
				} `json:"sender"`
				OriginAuth string `json:"origin_auth"`
				Class      string `json:"evidence_class"`
			} `json:"source"`
			Native *struct {
				Bytes    []byte `json:"bytes"`
				Record   string `json:"record_sha256"`
				Length   int64  `json:"record_length"`
				Evidence struct {
					SHA256 string `json:"sha256"`
					Length int64  `json:"length"`
				} `json:"evidence"`
			} `json:"native"`
			Flags []string `json:"flags"`
		}
		if err := json.Unmarshal(s.Raw, &e); err != nil {
			g.t.Fatalf("seq %d: %v", s.Seq, err)
		}
		if e.Native == nil {
			g.t.Fatalf("seq %d has no native: %s", s.Seq, s.Raw)
		}
		s.ID, s.Bytes, s.Record, s.Length = e.ID, e.Native.Bytes, e.Native.Record, e.Native.Length
		s.EvSHA, s.EvLen, s.Flags, s.Asset = e.Native.Evidence.SHA256, e.Native.Evidence.Length, e.Flags, e.Source.Asset
		s.OriginAuth, s.Class = e.Source.OriginAuth, e.Source.Class
		s.Received, _ = time.Parse(time.RFC3339Nano, e.Received.UTC)
		if e.Source.Sender != nil {
			s.Sender, s.Leaf = e.Source.Sender.Address, e.Source.Sender.Leaf
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		g.t.Fatal(err)
	}
	return out
}

// waitN waits until at least n events are stored, or until no new event
// has been stored for d: a slow store, as on a busy Windows runner, is
// still progress, and only a stall ends the wait early (#183, job
// 121863122339: 193 of 301 after a fixed 20 s). waitN never waits more
// than two minutes in all.
func (g *rig) waitN(n int, d time.Duration) []stored {
	g.t.Helper()
	now := time.Now()
	moved, limit, seen := now, now.Add(2*time.Minute), -1
	for {
		ev := g.events()
		if len(ev) != seen {
			seen, moved = len(ev), time.Now()
		}
		if len(ev) >= n || time.Since(moved) > d || time.Now().After(limit) {
			return ev
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitStatus polls the receiver's status until ok holds or d passes, and
// returns the last status read. Stored and the store's drop counts move
// only after AppendBatch returns, so they can lag the events a reader
// already sees in the database (#187, job 121917868556: stored 256 of 301
// straight after waitN on a slow Windows runner).
func (g *rig) waitStatus(ok func(receive.Status) bool, d time.Duration) receive.Status {
	g.t.Helper()
	limit := time.Now().Add(d)
	for {
		st := g.r.Status()
		if ok(st) || time.Now().After(limit) {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// checkBytes is the oracle: the stored record is exactly what was sent,
// and both hashes are the SHA-256 of those bytes.
func checkBytes(t *testing.T, i int, s stored, want []byte) {
	t.Helper()
	if string(s.Bytes) != string(want) {
		t.Errorf("message %d: stored %q, sent %q", i, s.Bytes, want)
	}
	if s.Record != sum(want) || s.EvSHA != sum(want) {
		t.Errorf("message %d: record_sha256 %s, evidence %s, want %s", i, s.Record, s.EvSHA, sum(want))
	}
	if s.Length != int64(len(want)) || s.EvLen != int64(len(want)) {
		t.Errorf("message %d: lengths %d %d, want %d", i, s.Length, s.EvLen, len(want))
	}
}

func dialFrom(t *testing.T, from netip.Addr, network string, to net.Addr) net.Conn {
	t.Helper()
	var la net.Addr
	if network == "udp" {
		la = &net.UDPAddr{IP: from.AsSlice()}
	} else {
		la = &net.TCPAddr{IP: from.AsSlice()}
	}
	c, err := (&net.Dialer{LocalAddr: la, Timeout: 5 * time.Second}).Dial(network, to.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// pki is A6's own CA and leaf certificates.
type pki struct {
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

var serial int64 = 100

func newCA(t *testing.T, name string) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := x509.NewCertPool()
	p.AddCert(c)
	return &pki{ca: c, key: k, pool: p}
}

func (p *pki) leaf(t *testing.T, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
