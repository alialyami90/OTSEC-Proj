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
// doc.go). T is taken from the clock: from before the listener starts (the
// budget's refill clock cannot start earlier) to when a known sender's
// marker, sent after the flood, is stored (the receiver handles datagrams
// in order, so every stranger datagram before it has been spent or
// dropped by then). Nothing is forwarded or pruned here, which is an
// outage.
//
// The floor (that the budget, not the rig, held the flood) is taken from
// the flood the listener actually saw: the bucket starts full and holds
// at most UnknownBytes, so the time before the flood adds nothing, and a
// saturating flood that ran for F stores about UnknownBytes x (1 + F/window). Measuring it from
// before startQuota failed on a slow Windows runner, where fewer windows
// were left for the flood (#192, job 121931466677: 984524 of 1572864
// stored, 1011 dropped).

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
	start := time.Now()
	g := startQuota(t, quota, asset.SyslogUDP, nil, receive.Limits{Rate: 100000, Burst: 100000, UnknownBytes: per, UnknownWindow: window})
	c := dialFrom(t, ipStranger, "udp", g.addr)
	known := dialFrom(t, ipA, "udp", g.addr)
	msg := []byte("<13>" + strings.Repeat("unknown sender a6 ", 200))
	markers := 0
	// flood sends until end and sets F to how long it sent, then returns T:
	// the clock from start until a marker sent after the flood is stored.
	var F time.Duration
	flood := func(end time.Time) time.Duration {
		began := time.Now()
		for i := 0; time.Now().Before(end); i++ {
			c.Write(msg)
			if i%20 == 0 {
				fmt.Fprintf(known, "<13>known %d", i)
			}
			time.Sleep(2 * time.Millisecond)
		}
		F = time.Since(began)
		markers++
		mark := fmt.Sprintf("<13>a6 marker %d", markers)
		for wait := time.Now().Add(20 * time.Second); time.Now().Before(wait); {
			known.Write([]byte(mark)) // again each poll: a datagram may be lost
			for _, s := range g.events() {
				if string(s.Bytes) == mark {
					return time.Since(start)
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		g.markerFatalf(mark, "marker %q not stored", mark)
		return 0
	}
	bound := func(T time.Duration) int64 {
		return per + int64(float64(per)*T.Seconds()/window.Seconds())
	}
	// unknownBytes is what the stranger stored: in all, and of that what was
	// received (received.utc, when the listener read and paid for it) by
	// the planned outage's end.
	planned := start.Add(hours * window)
	unknownBytes := func() (n, inPlan int64, rows int) {
		for _, s := range g.events() {
			if s.Sender == ipStranger.String() {
				n += int64(len(s.Raw))
				rows++
				if !s.Received.After(planned) {
					inPlan += int64(len(s.Raw))
				}
			}
		}
		return n, inPlan, rows
	}

	// Within the planned outage: the flood ends hours windows after the
	// listener's start. What the stranger stored by received time within
	// that span is at most the planned bound and a quarter of the quota; all
	// it stored is at most UnknownBytes x (1 + T/window) for the T measured;
	// and the budget, not the rig, is what held it there (most of what the
	// budget allowed over the flood was used, and messages were dropped).
	// The quarter is checked on the planned span, not on all T: on a slow
	// runner the listener reads datagrams the OS held after the flood ends,
	// past the planned span, and the budget has refilled by then (#179,
	// job 121963456949: 1711491 bytes in T 5.15 s, under the 1744237 that
	// T allows). The flood runs for at least one window: a runner that
	// takes the whole planned span to start the listener otherwise floods
	// for 0 s and the floor has nothing to measure (#199, stress run on Go
	// 1.26.0: T 5.53 s, flood 0s, stranger 0 bytes). Flooding past the
	// planned end does not weaken the checks: inPlan counts only what was
	// received by then, and the bound is taken at the T measured.
	end := planned
	if least := time.Now().Add(window); end.Before(least) {
		end = least
	}
	T := flood(end)
	inside, inPlan, rows := unknownBytes()
	used := g.classBytes()
	st := g.r.Status()
	floor := bound(F) * 7 / 10
	t.Logf("within %d windows: T %v, flood %v; stranger %d bytes in %d rows, %d received by the planned end; class %d; bound at T %d; floor %d; planned bound %d; quarter %d; dropped %v",
		hours, T, F, inside, rows, inPlan, used, bound(T), floor, sz["a6-udp"].UnknownBound, quota/4, st.Dropped)
	if inside > bound(T) {
		t.Errorf("unknown senders stored %d bytes over T = %v, past UnknownBytes x (1 + T/window) = %d", inside, T, bound(T))
	}
	if inPlan > sz["a6-udp"].UnknownBound || inPlan > quota/4 {
		t.Errorf("unknown senders stored %d bytes received within the planned outage, past the planned bound %d or a quarter of the quota (%d)", inPlan, sz["a6-udp"].UnknownBound, quota/4)
	}
	if inside < floor || st.Dropped[receive.DropUnknownBudget] == 0 {
		t.Errorf("the budget did not limit the flood: stored %d, under 70%% of the %d it allows over a %v flood, dropped %v", inside, bound(F), F, st.Dropped)
	}

	// Past the planned outage the budget keeps refilling: this is the
	// documented limit of option (b), not a bound. The second flood runs
	// for 2 x hours windows from now, not to a time fixed from start, so
	// a slow start cannot shorten it: with the first flood's share that
	// is past a quarter of the quota.
	T = flood(time.Now().Add(2 * hours * window))
	after, _, _ := unknownBytes()
	t.Logf("after %d more windows: T %v, flood %v; stranger %d bytes; bound at T %d; class %d", 2*hours, T, F, after, bound(T), g.classBytes())
	if after > bound(T) {
		t.Errorf("unknown senders stored %d bytes over T = %v, past UnknownBytes x (1 + T/window) = %d", after, T, bound(T))
	}
	if after <= quota/4 {
		t.Errorf("unknown senders stored %d bytes after three times the planned outage or more; the documented limit says the share keeps growing past %d", after, quota/4)
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
