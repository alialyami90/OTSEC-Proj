package syslogreceive

import (
	"database/sql"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/modules/telemetry/receive"
	nodecfg "otsec.local/otsec/platform/node"
)

// Unknown-sender sizing (A5, #169; HR-11, D3-3 option (b)). The node sizes
// a listener's hourly unknown budget so that, over syslog_outage_hours,
// unknown senders take at most a quarter of the class quota. Ground truth
// is the store's own quota measure (class_bytes, what a commit is refused
// on), never the receiver's or the node's count. One UnknownWindow stands
// for one hour: receive refills UnknownBytes per window, so the bound is
// UnknownBytes x (1 + T/window) whatever the window's length (receive
// doc.go). Nothing is forwarded or pruned here, which is an outage.

var ipStranger = netip.MustParseAddr("127.0.0.3")

// classBytes is the store's quota count for the datagram class.
func (g *rig) classBytes() int64 {
	g.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		g.t.Fatal(err)
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow(`SELECT COALESCE((SELECT bytes FROM class_bytes WHERE class = 'syslog-datagram'), 0)`).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	return n
}

func TestUnknownShareOverTheOutage(t *testing.T) {
	const (
		quota  = 6 << 20
		hours  = 3
		window = 1500 * time.Millisecond
	)
	cfg := nodecfg.Config{SyslogOutageHours: hours,
		Listeners: []nodecfg.Listener{{ID: "a6-udp", Transport: asset.SyslogUDP}}}
	cfg.Store.Quotas = map[string]int64{"syslog-datagram": quota}
	sz, err := cfg.ListenerSizings()
	if err != nil {
		t.Fatal(err)
	}
	per := sz["a6-udp"].UnknownBytes
	if sz["a6-udp"].UnknownBound > quota/4 || per*(1+hours) > quota/4 {
		t.Fatalf("sizing %+v is over a quarter of %d", sz["a6-udp"], quota)
	}
	g := startQuota(t, quota, asset.SyslogUDP, nil, receive.Limits{Rate: 100000, Burst: 100000, UnknownBytes: per, UnknownWindow: window})
	c := dialFrom(t, ipStranger, "udp", g.addr)
	known := dialFrom(t, ipA, "udp", g.addr)
	msg := []byte("<13>" + strings.Repeat("unknown sender a6 ", 200))
	flood := func(d time.Duration) {
		end := time.Now().Add(d)
		for i := 0; time.Now().Before(end); i++ {
			c.Write(msg)
			if i%20 == 0 {
				fmt.Fprintf(known, "<13>known %d", i)
			}
			time.Sleep(2 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond) // let the queue drain
	}
	unknownBytes := func() (n int64, rows int) {
		for _, s := range g.events() {
			if s.Sender == ipStranger.String() {
				n += int64(len(s.Raw))
				rows++
			}
		}
		return n, rows
	}

	// Within the planned outage: the store holds at most a quarter of the
	// quota from the stranger, and the budget, not the rig, is what held
	// it there (most of the bound is used and messages were dropped).
	flood(hours * window)
	inside, rows := unknownBytes()
	used := g.classBytes()
	st := g.r.Status()
	t.Logf("within %d windows: stranger %d bytes in %d rows; class %d; bound %d; quarter %d; dropped %v",
		hours, inside, rows, used, sz["a6-udp"].UnknownBound, quota/4, st.Dropped)
	if inside > quota/4 {
		t.Errorf("unknown senders stored %d bytes within the planned outage, over a quarter of the quota (%d)", inside, quota/4)
	}
	if inside < sz["a6-udp"].UnknownBound*7/10 || st.Dropped[receive.DropUnknownBudget] == 0 {
		t.Errorf("the budget did not limit the flood: stored %d of a bound of %d, dropped %v", inside, sz["a6-udp"].UnknownBound, st.Dropped)
	}

	// Past the planned outage the budget keeps refilling: this is the
	// documented limit of option (b), not a bound.
	flood(2 * hours * window)
	after, _ := unknownBytes()
	t.Logf("after %d windows: stranger %d bytes; class %d", 3*hours, after, g.classBytes())
	if after <= quota/4 {
		t.Errorf("unknown senders stored %d bytes after three times the planned outage; the documented limit says the share keeps growing past %d", after, quota/4)
	}
	// Known senders were stored throughout.
	n := 0
	for _, s := range g.events() {
		if s.Sender == ipA.String() {
			n++
		}
	}
	if n == 0 {
		t.Error("no known sender's message was stored")
	}
}
