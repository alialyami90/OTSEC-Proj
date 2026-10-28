package syslogreceive

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
	"otsec.local/otsec/platform/store"
)

// HR-11 on the real store (#291, B4): with Config.UnknownStream set, unknown
// senders' records go to a syslog-unknown stream whose class quota bounds
// them absolutely. Once that class is full an unknown sender's messages are
// dropped and counted as unknown-full, its connection is read on, and a
// known device on the same listener stores every message. Written from
// HR-11 and B4's design note, not from unknownstream_test.go. The class
// bytes are read by the oracle's own SQL connection. Evidence class:
// simulated, loopback only.

const sUnknown = c5.StreamID("syslog-unknown/a6")

// partCap is the receiver's commit cap here: a part refused at the quota
// is dropped whole, so the class may stop short of its quota by at most
// one part (B4's design note), and the tests hold it to that.
const partCap = 64 << 10

// commitRecords is the Log's record cap here, given to the receiver as its
// MaxCommitRecords, as the node gives both from one group (groupFor).
const commitRecords = 64

var ipU = netip.MustParseAddr("127.0.0.3")

type unknownRig struct {
	t      *testing.T
	r      *receive.Receiver
	addr   net.Addr
	db     string
	quota  int64
	stream c5.StreamID
	stop   context.CancelFunc
	done   chan error
}

func startUnknown(t *testing.T, tr asset.Transport, quota int64, lim receive.Limits) *unknownRig {
	t.Helper()
	d := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(d, ""); err != nil {
		t.Fatal(err)
	}
	known, class := sStream, c5.ClassSyslogStream
	if tr == asset.SyslogUDP {
		known, class = sDgram, c5.ClassSyslogDatagram
	}
	db := c5.Database{
		ID: "syslog", Writer: "telemetry",
		Streams: []c5.StreamSpec{{ID: known, Class: class}, {ID: sUnknown, Class: c5.ClassSyslogUnknown}},
		Classes: []c5.StreamClass{class, c5.ClassSyslogUnknown},
		Quotas: []c5.Quota{{Class: class, Bytes: 64 << 20, WarnFraction: 0.9},
			{Class: c5.ClassSyslogUnknown, Bytes: quota, WarnFraction: 0.5}},
	}
	e, err := store.NewEnv(store.Options{Dir: d, Node: node, Database: db})
	if err != nil {
		t.Fatal(err)
	}
	st := c5.RunStartup(context.Background(), e, c5.StartupPolicy{
		Streams:                db.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50, CompactStepPages: 32, PruneTarget: 0.8,
	})
	if st.Mode != c5.ModeCollecting {
		t.Fatalf("startup: %s %v", st.Mode, st.Alarms)
	}
	t.Cleanup(func() { st.Store.Close(); st.Unlock() })
	sdb, ok := store.AsDB(st.Store)
	if !ok {
		t.Fatal("not a platform store")
	}
	log, err := c5.NewLog(sdb, node, map[c5.StreamID]c5.StreamClass{known: class, sUnknown: c5.ClassSyslogUnknown},
		c5.GroupOptions{MaxEvents: commitRecords, MaxWait: 5 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := receive.New(receive.Config{
		Node: node, ID: "a6", Stream: known, UnknownStream: sUnknown, Transport: tr, Address: "127.0.0.1:0",
		Target: asset.Simulated, Plaintext: true,
		Senders: receive.Senders{ipA: {AssetID: assetA, Target: asset.Simulated, Dialect: normalize.DialectRFC}},
		Log:     log, Health: &healths{}, Received: received, Limits: lim,
		MaxCommitBytes: partCap, MaxCommitRecords: commitRecords,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := r.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &unknownRig{t: t, r: r, addr: addr, db: filepath.Join(d, "syslog.db"), quota: quota, stream: known, stop: cancel, done: make(chan error, 1)}
	go func() { g.done <- r.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-g.done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(serveLate):
			t.Errorf("Serve did not return within %v", serveLate)
		}
	})
	return g
}

// oracle reads, with its own connection, each stream's events (their
// id.stream and asset) and the syslog-unknown class's bytes.
type oracleView struct {
	known, unknown []string // message text after the PRI
	unknownBytes   int64
	misfiled       []string // an event in a stream its id.stream or asset does not fit
}

func (g *unknownRig) view() oracleView {
	g.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		g.t.Fatal(err)
	}
	defer db.Close()
	var v oracleView
	if err := db.QueryRow(`SELECT COALESCE((SELECT bytes FROM class_bytes WHERE class = 'syslog-unknown'), 0)`).Scan(&v.unknownBytes); err != nil {
		g.t.Fatal(err)
	}
	rows, err := db.Query(`SELECT stream, event FROM events WHERE stream IN (?, ?) ORDER BY stream, seq`, string(g.stream), string(sUnknown))
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var ev []byte
		if err := rows.Scan(&s, &ev); err != nil {
			g.t.Fatal(err)
		}
		var e struct {
			ID     struct{ Stream string } `json:"id"`
			Native struct {
				Bytes []byte `json:"bytes"`
			} `json:"native"`
			Source struct {
				Asset *struct {
					ID string `json:"id"`
				} `json:"asset"`
			} `json:"source"`
		}
		if err := json.Unmarshal(ev, &e); err != nil {
			g.t.Fatal(err)
		}
		text := string(e.Native.Bytes)
		if i := strings.IndexByte(text, '>'); i >= 0 {
			text = text[i+1:]
		}
		switch {
		case s != e.ID.Stream:
			v.misfiled = append(v.misfiled, s+": id.stream "+e.ID.Stream)
		case s == string(sUnknown) && e.Source.Asset != nil:
			v.misfiled = append(v.misfiled, s+": an asset's event "+text)
		case s == string(g.stream) && (e.Source.Asset == nil || e.Source.Asset.ID != assetA):
			v.misfiled = append(v.misfiled, s+": an unknown sender's event "+text)
		}
		if s == string(sUnknown) {
			v.unknown = append(v.unknown, text)
		} else {
			v.known = append(v.known, text)
		}
	}
	return v
}

// The budget is set far above the class quota so that the quota, not the
// budget, is what stops the unknown sender.
func unknownLimits() receive.Limits {
	return receive.Limits{Rate: 100000, Burst: 100000, UnknownRate: 100000, UnknownBurst: 100000,
		UnknownBytes: 64 << 20, UnknownWindow: time.Hour}
}

func TestB6UnknownClassFullOverStream(t *testing.T) {
	const quota, n, knownN = 512 << 10, 800, 50
	g := startUnknown(t, asset.SyslogTCP, quota, unknownLimits())
	big := strings.Repeat("u", 900)
	u := dialFrom(t, ipU, "tcp", g.addr)
	a := dialFrom(t, ipA, "tcp", g.addr)
	// The unknown sender writes all of it; each write must complete, so the
	// connection is read on at the quota, not held.
	wrote := make(chan error, 1)
	go func() {
		w := bufio.NewWriter(u)
		for i := 0; i < n; i++ {
			fmt.Fprintf(w, "<13>unknown %03d %s\n", i, big)
		}
		wrote <- w.Flush()
	}()
	for i := 0; i < knownN; i++ {
		if _, err := fmt.Fprintf(a, "<13>device %03d\n", i); err != nil {
			t.Fatal(err)
		}
	}
	// Wait for the receiver's accounting to settle: every message read is
	// stored or dropped, and all n+knownN are read.
	var st receive.Status
	for limit := time.Now().Add(2 * time.Minute); time.Now().Before(limit); time.Sleep(20 * time.Millisecond) {
		st = g.r.Status()
		if st.Received == n+knownN && st.Stored+sumMap(st.Dropped) == st.Received {
			break
		}
	}
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("the unknown sender's writes failed: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the unknown sender's writes did not complete: its connection was held at the quota")
	}
	v := g.view()
	t.Logf("status %+v; known %d, unknown %d stored, unknown class %d of %d bytes", st, len(v.known), len(v.unknown), v.unknownBytes, quota)
	if st.Received != n+knownN || st.Stored+sumMap(st.Dropped) != st.Received {
		t.Fatalf("accounting did not settle: %+v", st)
	}
	if len(v.known) != knownN {
		t.Errorf("the known device: %d of %d stored", len(v.known), knownN)
	}
	for i, s := range v.known {
		if want := fmt.Sprintf("device %03d", i); s != want {
			t.Errorf("known %d: %q, want %q", i, s, want)
			break
		}
	}
	if len(v.unknown) == 0 || len(v.unknown) == n {
		t.Errorf("unknown sender: %d of %d stored; the class should have filled", len(v.unknown), n)
	}
	if got := st.Dropped[receive.DropUnknownFull]; got != int64(n-len(v.unknown)) || sumMap(st.Dropped) != got {
		t.Errorf("dropped %+v, want only %s = %d", st.Dropped, receive.DropUnknownFull, n-len(v.unknown))
	}
	if v.unknownBytes > quota {
		t.Errorf("the syslog-unknown class holds %d bytes, over its quota %d", v.unknownBytes, quota)
	}
	if v.unknownBytes < quota-partCap {
		t.Errorf("the syslog-unknown class stopped at %d bytes, more than one part (%d) short of its quota %d", v.unknownBytes, partCap, quota)
	}
	// What is stored keeps the sender's order.
	for i := 1; i < len(v.unknown); i++ {
		if v.unknown[i][:11] <= v.unknown[i-1][:11] {
			t.Errorf("unknown stored out of order: %.11q after %.11q", v.unknown[i], v.unknown[i-1])
			break
		}
	}
	if len(v.misfiled) != 0 {
		t.Errorf("misfiled: %q", v.misfiled)
	}
}

// floodDatagrams sends n unknown and n known datagrams, interleaved so that
// a batch read together holds both kinds, calls pace after each pair, and
// waits for the receiver's accounting to settle: every datagram read, and
// each stored or dropped.
func floodDatagrams(t *testing.T, g *unknownRig, n int, pace func(i int)) (receive.Status, oracleView) {
	t.Helper()
	u := dialFrom(t, ipU, "udp", g.addr)
	a := dialFrom(t, ipA, "udp", g.addr)
	big := strings.Repeat("u", 900)
	for i := 0; i < n; i++ {
		if _, err := fmt.Fprintf(u, "<13>unknown %03d %s", i, big); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(a, "<13>device %03d", i); err != nil {
			t.Fatal(err)
		}
		pace(i)
	}
	sent := int64(2 * n)
	var st receive.Status
	for limit := time.Now().Add(2 * time.Minute); time.Now().Before(limit); time.Sleep(20 * time.Millisecond) {
		st = g.r.Status()
		if st.Received == sent && st.Stored+sumMap(st.Dropped) == st.Received {
			break
		}
	}
	v := g.view()
	t.Logf("status %+v; known %d, unknown %d stored, unknown class %d of %d bytes", st, len(v.known), len(v.unknown), v.unknownBytes, g.quota)
	if st.Received != sent {
		// The kernel may drop datagrams before the receiver reads them;
		// nobody counts those (F-016), so the cases need every one read.
		t.Fatalf("read %d of %d datagrams", st.Received, sent)
	}
	if st.Stored+sumMap(st.Dropped) != st.Received {
		t.Fatalf("accounting did not settle: %+v", st)
	}
	if v.unknownBytes > g.quota {
		t.Errorf("the syslog-unknown class holds %d bytes, over its quota %d", v.unknownBytes, g.quota)
	}
	if len(v.misfiled) != 0 {
		t.Errorf("misfiled: %q", v.misfiled)
	}
	return st, v
}

// With receive's default limits (the node's, but for UnknownBytes, which
// the node sizes at most at the same 1 MiB an hour) and both senders under
// the per-sender rate, the unknown class fills and a known device on the
// same listener stores every datagram: no known datagram is dropped for
// any reason, queue-full included (HR-11). This is the case that must
// pass; the lifted-limits one below is F-017's. The pace is 80 pairs a second:
// 80 per sender against a rate of 100, 160 in all against a queue of 1024.
func TestB6UnknownClassFullOverDatagrams(t *testing.T) {
	const quota, n = 384 << 10, 600
	g := startUnknown(t, asset.SyslogUDP, quota, receive.Limits{})
	start := time.Now()
	st, v := floodDatagrams(t, g, n, func(i int) {
		// Pair i+1 goes at (i+1)/80 s, so a late wake never sends faster.
		time.Sleep(time.Until(start.Add(time.Duration(i+1) * time.Second / 80)))
	})
	if len(v.known) != n {
		t.Errorf("the known device: %d of %d stored", len(v.known), n)
	}
	for i, s := range v.known {
		if want := fmt.Sprintf("device %03d", i); s != want {
			t.Errorf("known %d: %q, want %q", i, s, want)
			break
		}
	}
	if len(v.unknown) == 0 || len(v.unknown) == n {
		t.Errorf("unknown sender: %d of %d stored; the class should have filled", len(v.unknown), n)
	}
	// Only the unknown sender's datagrams are dropped: at the class quota,
	// and past the hourly budget, which a part refused at the quota also
	// spends (#291).
	full, budget := st.Dropped[receive.DropUnknownFull], st.Dropped[receive.DropUnknownBudget]
	if full == 0 || full+budget != int64(n-len(v.unknown)) || sumMap(st.Dropped) != full+budget {
		t.Errorf("dropped %+v, want only %s (at least 1) and %s, %d in all", st.Dropped, receive.DropUnknownFull, receive.DropUnknownBudget, n-len(v.unknown))
	}
	if v.unknownBytes < quota-partCap {
		t.Errorf("the syslog-unknown class stopped at %d bytes, more than one part (%d) short of its quota %d", v.unknownBytes, partCap, quota)
	}
}

// F-017, a known residual of HR-11: with every rate limit lifted, the
// unknown flood shares the datagram listener's one queue with the known
// device, so while a commit is held (F-016) both are dropped as
// queue-full. On a fast disk nothing known is lost; on the hosted Windows
// runner 84 of 600 were (job 122683927190). This case pins what must hold
// either way, and logs how many known datagrams were lost, so the residual
// is seen on every run: every known datagram is stored, in order, or
// counted as queue-full; no drop has another reason; unknown-full falls
// only on the unknown sender; and the class fills and stays in its bound.
func TestB6F017UnknownFloodSharesTheQueue(t *testing.T) {
	const quota, n = 384 << 10, 600
	g := startUnknown(t, asset.SyslogUDP, quota, receive.Limits{Rate: 100000, Burst: 100000,
		UnknownRate: 100000, UnknownBurst: 100000, UnknownBytes: 64 << 20, UnknownWindow: time.Hour})
	// The pace of job 122683927190: 10 pairs, then 5 ms, so the socket
	// buffer does not drop what the test counts.
	st, v := floodDatagrams(t, g, n, func(i int) {
		if i%10 == 9 {
			time.Sleep(5 * time.Millisecond)
		}
	})
	lostKnown, lostUnknown := int64(n-len(v.known)), int64(n-len(v.unknown))
	full, queue := st.Dropped[receive.DropUnknownFull], st.Dropped[receive.DropQueueFull]
	t.Logf("F-017 residual (simulated): %d of %d known datagrams lost to queue-full with the rate limits lifted; queue-full %d in all", lostKnown, n, queue)
	if other := sumMap(st.Dropped) - full - queue; other != 0 {
		t.Errorf("dropped %+v: only %s and %s are expected", st.Dropped, receive.DropUnknownFull, receive.DropQueueFull)
	}
	if lostKnown+lostUnknown != full+queue {
		t.Errorf("%d known and %d unknown lost, but %d counted", lostKnown, lostUnknown, full+queue)
	}
	if lostKnown > queue {
		t.Errorf("%d known datagrams lost, only %d counted as queue-full", lostKnown, queue)
	}
	if full == 0 || full > lostUnknown {
		t.Errorf("%s %d: the class should have filled, on the unknown sender only (%d of its datagrams lost)", receive.DropUnknownFull, full, lostUnknown)
	}
	if v.unknownBytes < quota-partCap {
		t.Errorf("the syslog-unknown class stopped at %d bytes, more than one part (%d) short of its quota %d", v.unknownBytes, partCap, quota)
	}
	// What is stored keeps the device's order.
	for i := 1; i < len(v.known); i++ {
		if v.known[i] <= v.known[i-1] {
			t.Errorf("known stored out of order: %q after %q", v.known[i], v.known[i-1])
			break
		}
	}
}

func TestB6UnknownStreamConfig(t *testing.T) {
	log, _ := open(t, 64<<20)
	base := receive.Config{Node: node, ID: "a6", Stream: sStream, Transport: asset.SyslogTCP, Address: "127.0.0.1:0",
		Target: asset.Simulated, Plaintext: true, Log: log, Health: &healths{}, Received: received}
	// The control: a valid stream other than Stream is taken.
	ok := base
	ok.UnknownStream = sUnknown
	if _, err := receive.New(ok); err != nil {
		t.Fatalf("UnknownStream %q refused: %v", sUnknown, err)
	}
	for _, s := range []c5.StreamID{sStream, "Not A Stream", " syslog-unknown/a6", "-syslog-unknown"} {
		c := base
		c.UnknownStream = s
		if _, err := receive.New(c); err == nil {
			t.Errorf("UnknownStream %q accepted", s)
		}
	}
}
