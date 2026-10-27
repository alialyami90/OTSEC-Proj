package node

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// sizingConfig is a configuration with listeners of the given transports
// and the two syslog quotas.
func sizingConfig(stream, datagram int64, hours int, transports ...string) *Config {
	c := &Config{SyslogOutageHours: hours, Store: StoreConfig{Quotas: map[string]int64{
		string(c5.ClassSyslogStream): stream, string(c5.ClassSyslogDatagram): datagram,
	}}}
	for i, tr := range transports {
		c.Listeners = append(c.Listeners, Listener{ID: fmt.Sprintf("l%d", i), Transport: asset.Transport(tr)})
	}
	return c
}

// Each listener's hourly unknown budget is a share of its class quota:
// every listener of the class together may store at most a quarter of the
// quota from unknown senders over the planned outage, and no listener more
// than A4's 1 MiB an hour. The bound is what the node shows.
func TestListenerSizings(t *testing.T) {
	const mib = 1 << 20
	for _, tc := range []struct {
		name       string
		c          *Config
		id         string
		per, bound int64
		class      c5.StreamClass
		hours      int64
	}{
		{"one listener, default outage", sizingConfig(64*mib, 64*mib, 0, "syslog-tcp"), "l0", 64 * mib / 4 / 25, 64 * mib / 4 / 25 * 25, c5.ClassSyslogStream, 24},
		{"two of a class share it", sizingConfig(64*mib, 64*mib, 0, "syslog-tls", "syslog-tcp"), "l1", 64 * mib / 4 / 50, 64 * mib / 4 / 50 * 50, c5.ClassSyslogStream, 24},
		{"classes are sized apart", sizingConfig(64*mib, 32*mib, 0, "syslog-tls", "syslog-udp"), "l1", 32 * mib / 4 / 25, 32 * mib / 4 / 25 * 25, c5.ClassSyslogDatagram, 24},
		{"capped at A4's default", sizingConfig(4096*mib, 64*mib, 0, "syslog-tcp"), "l0", mib, 25 * mib, c5.ClassSyslogStream, 24},
		{"a longer outage takes less an hour", sizingConfig(512*mib, 64*mib, 168, "syslog-tcp"), "l0", 512 * mib / 4 / 169, 512 * mib / 4 / 169 * 169, c5.ClassSyslogStream, 168},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.c.ListenerSizings()
			if err != nil {
				t.Fatal(err)
			}
			sz := got[tc.id]
			if sz.UnknownBytes != tc.per || sz.UnknownBound != tc.bound || sz.Class != tc.class || sz.OutageHours != tc.hours {
				t.Fatalf("%+v, want %d an hour, bound %d, class %s, %d h", sz, tc.per, tc.bound, tc.class, tc.hours)
			}
			if sz.UnknownBound > sz.Quota/UnknownQuotaShare || sz.limits().UnknownBytes != tc.per || sz.limits().UnknownWindow != time.Hour {
				t.Fatalf("bound %d over a quarter of %d, or limits %+v", sz.UnknownBound, sz.Quota, sz.limits())
			}
		})
	}
}

// A quota too small for the unknown senders' floor over the outage, or a
// stream quota that cannot hold one whole batch beside their share, is
// refused, and so is the configuration that names it (HR-11, D3-3).
func TestListenerSizingsRefused(t *testing.T) {
	const mib = 1 << 20
	for _, tc := range []struct {
		name string
		c    *Config
		want string
	}{
		{"below the floor", sizingConfig(25*mib-1, 64*mib, 0, "syslog-tcp"), "must be at least 26214400 bytes"},
		{"three listeners share it", sizingConfig(64*mib, 64*mib, 0, "syslog-tcp", "syslog-tls", "syslog-tcp"), "too small for 3 listeners"},
		{"datagram too", sizingConfig(64*mib, 10*mib, 0, "syslog-udp"), "store.quotas.syslog-datagram"},
		{"no room for a held batch", sizingConfig(4*mib, 64*mib, 1, "syslog-tcp"), "cannot hold one received stream batch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.c.ListenerSizings(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	// A datagram batch is dropped, not held, so the same quota is enough
	// for a UDP listener.
	if _, err := sizingConfig(64*mib, 4*mib, 1, "syslog-udp").ListenerSizings(); err != nil {
		t.Fatal(err)
	}
	// The exact floor passes.
	if _, err := sizingConfig(25*mib, 64*mib, 0, "syslog-tcp").ListenerSizings(); err != nil {
		t.Fatal(err)
	}
}

// The loader checks syslog_outage_hours and refuses a quota the listeners
// cannot be sized from; without listeners, any quota loads.
func TestOutageHoursConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*nodeconfigtest.Config)
		want string
	}{
		{"negative", func(nc *nodeconfigtest.Config) { nc.SyslogOutageHours = -1 }, "syslog_outage_hours -1 not in [0, 720]"},
		{"too long", func(nc *nodeconfigtest.Config) { nc.SyslogOutageHours = 721 }, "syslog_outage_hours 721 not in [0, 720]"},
		{"quota too small", func(nc *nodeconfigtest.Config) {
			nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
			nc.Store.Quotas["syslog-stream"] = 1 << 20
		}, "HR-11, D3-3"},
		{"longest outage with the test quota", func(nc *nodeconfigtest.Config) {
			nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
			nc.SyslogOutageHours = 720
		}, "too small for 1 listeners"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc, _ := listenConfig(t, tc.mod)
			if _, err := ParseConfig(nc.Bytes()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	nc, _ := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.Store.Quotas["syslog-stream"] = 1 << 20
		nc.SyslogOutageHours = 720
	})
	if _, err := ParseConfig(nc.Bytes()); err != nil {
		t.Fatalf("no listeners: %v", err)
	}
}

// The node passes the sized budget to the listener: with a stream quota
// that sizes it at A4's 256 KiB floor, an unknown sender's messages past it
// are dropped as unknown-budget well before A4's 1 MiB default would drop
// them, and status shows the budget, the bound and the bytes stored.
func TestListenerUsesSizedBudget(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
		nc.Store.Quotas["syslog-stream"] = MinUnknownBytes * 25 * UnknownQuotaShare
	})
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)

	line := "<13>Oct 26 12:00:00 stranger " + strings.Repeat("x", 8000) + "\n"
	c := dialFrom(t, "tcp", "127.0.0.2", ls.Addr("lab-tcp"))
	const sent = 40
	for range sent {
		if _, err := c.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	var got ListenerStatus
	for {
		ls.Publish()
		got = st.Snapshot("x").Listeners["lab-tcp"]
		if got.Stored+got.Dropped["unknown-budget"] >= sent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener status: %+v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got.Dropped["unknown-budget"] == 0 || got.Stored == 0 {
		t.Fatalf("stored %d, dropped %v: the sized budget was not applied", got.Stored, got.Dropped)
	}
	u := got.Unknown
	if u == nil || u.HourlyBytes != MinUnknownBytes || u.BoundBytes != MinUnknownBytes*25 || u.OutageHours != 24 || u.QuotaBytes != MinUnknownBytes*100 {
		t.Fatalf("unknown share in status: %+v", u)
	}
	var stored int64
	got2, err := r.Store(ListenerStream("lab-tcp")).Read(bg, ListenerStream("lab-tcp"), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got2 {
		stored += int64(len(s.Event))
	}
	// The receiver spends the pending event's bytes and the store keeps it
	// with its seq written in, so the two differ by the seq's digits only.
	if diff := stored - u.StoredBytes; u.StoredBytes == 0 || diff < 0 || diff > int64(len(got2))*4 || u.StoredBytes > MinUnknownBytes+4096 {
		t.Fatalf("unknown stored %d bytes in status, %d in the stream (%d events)", u.StoredBytes, stored, len(got2))
	}
}

// A syslog-tls listener's certificate expiry is in status, and the node
// raises syslog-listener-certificate-expiring once when it comes within 30
// days and once more when it has passed.
func TestListenerCertExpiry(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredential(p, "test-listener", "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls, err := NewListening(r)
	if err != nil {
		t.Fatal(err)
	}
	na := ls.notAfter["lab-tls"]
	if na.IsZero() {
		t.Fatal("no certificate expiry kept")
	}
	alarms := func() []string {
		var out []string
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == AlarmListenerCertExpiring && a.Target == "listener lab-tls" {
				out = append(out, a.Detail)
			}
		}
		return out
	}
	at := func(d time.Duration) {
		r.opt.Now = func() time.Time { return na.Add(d) }
		ls.Publish()
	}
	at(-31 * 24 * time.Hour)
	if got := st.Snapshot("x").Listeners["lab-tls"]; !got.CertNotAfter.Equal(na) || len(alarms()) != 0 {
		t.Fatalf("31 days out: %+v, alarms %q", got, alarms())
	}
	at(-29 * 24 * time.Hour)
	at(-28 * 24 * time.Hour)
	if a := alarms(); len(a) != 1 || !strings.Contains(a[0], "expires at "+na.UTC().Format(time.RFC3339)) || !strings.Contains(a[0], "test-listener.crt") {
		t.Fatalf("29 days out: %q", a)
	}
	at(time.Second)
	at(time.Hour)
	if a := alarms(); len(a) != 2 || !strings.Contains(a[1], "expired at") {
		t.Fatalf("expired: %q", a)
	}
}

// With listeners, a target whose max_message_octets cannot carry a
// received message's text whole is warned about at start; one sized at
// RecommendedTargetOctets is not, and without listeners nothing is raised.
func TestTargetSmallForListeners(t *testing.T) {
	// A4's worst case on #169, an 8147-byte RTAC frame, renders at 21161.
	if RecommendedTargetOctets != 22528 || RecommendedTargetOctets < 21161 {
		t.Fatalf("RecommendedTargetOctets %d", RecommendedTargetOctets)
	}
	targets := func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("small", "127.0.0.1", 6514, "test-ca", "test-client", "V-S6-test", false)
		nc.AddRELPTarget("whole", "127.0.0.1", 6515, "test-ca", "test-client", "V-S6-test", false)
		nc.Targets[1]["max_message_octets"] = RecommendedTargetOctets
	}
	raised := func(withListener bool) []StatusAlarm {
		nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
			targets(nc)
			if withListener {
				nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
			}
		})
		r, st, _ := start(t, parse(t, nc), dir)
		defer r.Close()
		ls, err := NewListening(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := ls.Listen(); err != nil {
			t.Fatal(err)
		}
		defer ls.close(ls.receivers)
		return slices.DeleteFunc(st.Snapshot("x").Alarms, func(a StatusAlarm) bool { return a.Code != AlarmTargetSmallForListeners })
	}
	got := raised(true)
	if len(got) != 1 || got[0].Target != "small" || !strings.Contains(got[0].Detail, "max_message_octets is 2048; a received message whose text does not fit") ||
		!strings.Contains(got[0].Detail, fmt.Sprint(RecommendedTargetOctets)) {
		t.Fatalf("with a listener: %+v", got)
	}
	if got := raised(false); len(got) != 0 {
		t.Fatalf("without listeners: %+v", got)
	}
}

// The stored event of any frame a listener accepts stays within
// ReceivedRecordBound of its MaxMessage, at the node's 8192 and at
// receive's minimum of 2048, where small frames come nearest (A6 on
// #174): hostile fills in each dialect's longest fields, the RTAC Logger's
// tag at its 1024-byte packet limit, and the truncated flag a listener
// adds. A4's normalize TestSyslogSizeBounds covers more shapes at 8192.
func TestReceivedRecordBound(t *testing.T) {
	const (
		h3164 = "<13>Oct 26 12:00:00 host app: "
		h5424 = "<13>1 2026-10-26T12:00:00Z host app - - "
		hRTAC = "<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx RTAC Logger: 2015-03-21 12:09:58.593, I, S, "
	)
	for _, maxMessage := range []int64{2048, streamMaxMessage} {
		cut := func(s string) []byte { return []byte(s[:min(len(s), int(maxMessage))]) }
		bound := ReceivedRecordBound(maxMessage)
		var worst int
		for _, c := range []string{"<", `"`, `\`, "]", "\x01", "\xff", "a"} {
			fill := strings.Repeat(c, int(maxMessage))
			frames := [][]byte{
				cut(h3164 + fill),
				cut(h5424 + "- " + fill),
				cut(h5424 + `[x@1 a="` + fill[:int(maxMessage)-len(h5424)-12] + `"]`),
				cut(fill),
				cut(hRTAC + strings.Repeat(c, 1024-len(hRTAC)-3) + ", m"),
			}
			for _, frame := range frames {
				for _, d := range normalize.Dialects {
					e, err := normalize.Syslog(normalize.SyslogInput{Node: "site-a-node1", Stream: "syslog/l0", Message: frame,
						Sender: "127.0.0.1", Auth: event.AuthNone, EvidenceClass: asset.Simulated, Dialect: d,
						Flags:    []string{normalize.FlagTruncated},
						Received: event.Received{UTC: "2026-10-26T15:00:00.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}})
					if err != nil {
						t.Fatalf("%d-byte frame %q, %s: %v", len(frame), frame[:16], d, err)
					}
					b, err := json.Marshal(e)
					if err != nil {
						t.Fatal(err)
					}
					if int64(len(b)) > bound {
						t.Errorf("MaxMessage %d: %d-byte frame %q (%s) stores as %d bytes, bound %d", maxMessage, len(frame), frame[:16], d, len(b), bound)
					}
					worst = max(worst, len(b))
				}
			}
		}
		t.Logf("MaxMessage %d: worst stored %d, bound %d (margin %.1f%%)", maxMessage, worst, bound, 100*float64(bound-int64(worst))/float64(bound))
	}
}

// flood sends n unknown-sender messages of about 8 KiB to listener id and
// waits until each is stored or dropped; it returns the listener's status.
func flood(t *testing.T, ls *Listening, st *Status, id string, n int64) ListenerStatus {
	t.Helper()
	line := "<13>Oct 26 12:00:00 stranger " + strings.Repeat("x", 8000) + "\n"
	c := dialFrom(t, "tcp", "127.0.0.2", ls.Addr(id))
	before := st.Snapshot("x").Listeners[id]
	for range n {
		if _, err := c.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ls.Publish()
		got := st.Snapshot("x").Listeners[id]
		if got.Stored+got.Dropped["unknown-budget"] >= before.Stored+before.Dropped["unknown-budget"]+n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener status: %+v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// streamBytes is the sum of len(event) over stream's stored events.
func streamBytes(t *testing.T, r *Runtime, stream c5.StreamID) int64 {
	t.Helper()
	got, err := r.Store(stream).Read(bg, stream, 0, store.MaxRead)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, s := range got {
		n += int64(len(s.Event))
	}
	return n
}

// A restart does not refill the unknown budget (D3-3): the node counts what
// unknown senders stored on the stream in the hour before the start and
// passes it to the listener, so a flood after a restart gets only what is
// left of the hour's budget, not a fresh one.
func TestUnknownBudgetAcrossRestart(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
		nc.Store.Quotas["syslog-stream"] = MinUnknownBytes * 25 * UnknownQuotaShare
	})
	stream := ListenerStream("lab-tcp")
	c := parse(t, nc)
	r, st, _ := start(t, c, dir)
	ls := serve(t, r)
	// Each message is stored as an event of about 20 KiB: about half of
	// the 256 KiB budget, all of it stored.
	first := flood(t, ls, st, "lab-tcp", 6)
	if first.Dropped["unknown-budget"] != 0 || first.Unknown.SpentAtStart != 0 {
		t.Fatalf("first run: %+v %+v", first, first.Unknown)
	}
	spent := streamBytes(t, r, stream)
	ls.close(ls.receivers)
	r.Close()

	r, st, _ = start(t, c, dir)
	defer r.Close()
	ls = serve(t, r)
	ls.Publish()
	if got := st.Snapshot("x").Listeners["lab-tcp"].Unknown; got.SpentAtStart != spent {
		t.Fatalf("started %d bytes spent, the stream holds %d", got.SpentAtStart, spent)
	}
	second := flood(t, ls, st, "lab-tcp", 40)
	if second.Dropped["unknown-budget"] == 0 {
		t.Fatalf("the restart refilled the budget: %+v", second)
	}
	// Only the remainder is stored, give or take the hour's refill over
	// the test and the store's seq digits.
	if left := MinUnknownBytes - spent; second.Unknown.StoredBytes > left+1024 || second.Stored == 0 {
		t.Fatalf("after the restart unknown senders stored %d bytes, %d were left of the budget", second.Unknown.StoredBytes, left)
	}
	if countAlarms(st, AlarmUnknownSpentUncounted) != 0 {
		t.Fatal("uncounted alarm raised")
	}
}

// A received time after now counts as inside the window, so a clock set
// back does not hand out a fresh budget; one before the window does not
// count. A known sender's records never count (A3 on #198). A received
// time that does not parse would count as inside, but C4 refuses such an
// event at commit, so no stored record has one.
func TestUnknownSpentWindow(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
	})
	stream := ListenerStream("lab-tcp")
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	got := flood(t, ls, st, "lab-tcp", 3)
	stored := streamBytes(t, r, stream)
	// The asset sends from 127.0.0.1: its records are stored beside the
	// unknown sender's and are not counted.
	if _, err := dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tcp")).Write([]byte("<13>Oct 26 12:00:00 relay1 known " + strings.Repeat("y", 4000) + "\n")); err != nil {
		t.Fatal(err)
	}
	waitStored(t, ls, st, "lab-tcp", got.Stored+1)
	if streamBytes(t, r, stream) <= stored {
		t.Fatal("the known sender's message was not stored")
	}
	now := r.opt.Now()
	for name, tc := range map[string]struct {
		now  time.Time
		want int64
	}{
		"now":             {now, stored},
		"clock set back":  {now.Add(-24 * time.Hour), stored},
		"an hour later":   {now.Add(time.Hour + time.Minute), 0},
		"inside the hour": {now.Add(59 * time.Minute), stored},
	} {
		got, err := unknownSpent(bg, r.Store(stream), stream, time.Hour, tc.now)
		if err != nil || got != tc.want {
			t.Errorf("%s: %d %v, want %d", name, got, err, tc.want)
		}
	}
}

// If the stream cannot be read at start, the budget starts empty (fail
// closed), the node says why, and known senders are not affected.
func TestUnknownSpentUncountedFailsClosed(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
	})
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	stream := ListenerStream("lab-tcp")
	if _, err := unknownSpent(bg, nil, stream, time.Hour, time.Now()); err == nil {
		t.Fatal("no database, no error")
	}
	r.Store(stream).Close()
	ls, err := NewListening(r)
	if err != nil {
		t.Fatal(err)
	}
	ls.Publish()
	u := st.Snapshot("x").Listeners["lab-tcp"].Unknown
	if u == nil || u.SpentAtStart != u.HourlyBytes || u.HourlyBytes == 0 {
		t.Fatalf("budget not started empty: %+v", u)
	}
	if countAlarms(st, AlarmUnknownSpentUncounted) != 1 {
		t.Fatal("uncounted alarm not raised")
	}
}

// The count reads the stream a page at a time to its end: unknown records
// behind more than a page of known ones, and spread over several pages,
// are all counted (A6 on #198).
func TestUnknownSpentPages(t *testing.T) {
	defer func(n int) { unknownSpentPage = n }(unknownSpentPage)
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
	})
	stream := ListenerStream("lab-tcp")
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	known := dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tcp"))
	for i := range 5 {
		if _, err := fmt.Fprintf(known, "<13>Oct 26 12:00:00 relay1 known %d\n", i); err != nil {
			t.Fatal(err)
		}
	}
	waitStored(t, ls, st, "lab-tcp", 5)
	before := streamBytes(t, r, stream)
	flood(t, ls, st, "lab-tcp", 3)
	want := streamBytes(t, r, stream) - before
	for _, page := range []int{1, 2, 4, 5, 6} {
		unknownSpentPage = page
		type result struct {
			n   int64
			err error
		}
		done := make(chan result, 1)
		go func() {
			n, err := unknownSpent(bg, r.Store(stream), stream, time.Hour, r.opt.Now())
			done <- result{n, err}
		}()
		select {
		case got := <-done:
			if got.err != nil || got.n != want {
				t.Errorf("page %d: %d %v, want %d", page, got.n, got.err, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("page %d: the count did not end", page)
		}
	}
}
