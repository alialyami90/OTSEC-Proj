package node

import (
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// unknownQuota is a syslog-unknown quota small enough that a few hundred
// datagrams fill it, and well under the listener's hourly unknown budget,
// so the class is what stops the unknown senders, not the budget.
const unknownQuota = 256 << 10

// HR-11, C5 0.4: unknown senders store in their own class. When it is full
// their datagrams are dropped and counted as unknown-full, the store raises
// syslog-unknown-full, and a known sender's datagrams keep storing in the
// listener's own stream. What the unknown stream holds never passes the
// class quota, however many datagrams arrive.
func TestUnknownClassFullDoesNotStopKnownSenders(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
		nc.Store.Quotas["syslog-unknown"] = unknownQuota
	})
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)

	unknown := dialFrom(t, "udp", "127.0.0.2", ls.Addr("lab-udp"))
	known := dialFrom(t, "udp", "127.0.0.1", ls.Addr("lab-udp"))
	text := "<13>Oct 26 12:00:00 stranger " + strings.Repeat("x", 1000)
	var sent, last int
	deadline := time.Now().Add(60 * time.Second)
	for {
		// A burst, then look: the class is full once the store says so.
		for range 20 {
			if _, err := unknown.Write([]byte(text)); err != nil {
				t.Fatal(err)
			}
			sent++
		}
		time.Sleep(100 * time.Millisecond)
		ls.Publish()
		if got := st.Snapshot("x").Listeners["lab-udp"]; got.Dropped["unknown-full"] > 0 {
			last = int(got.Dropped["unknown-full"])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d datagrams sent and the class never filled: %+v", sent, st.Snapshot("x").Listeners["lab-udp"])
		}
	}
	if last == 0 {
		t.Fatal("no drop counted")
	}
	// The known sender still stores, in the listener's own stream.
	msg := []byte("<134>1 2026-10-26T12:00:00.000001Z relay1 sel 1 ID47 - SER: 52BKR1 Asserted")
	if _, err := known.Write(msg); err != nil {
		t.Fatal(err)
	}
	waitKnown(t, ls, st, r, "lab-udp", 1)
	if n := len(streamEvents(t, r, ListenerStream("lab-udp"))); n != 1 {
		t.Fatalf("%d events on the listener's own stream, want the known sender's 1", n)
	}
	// The class bound holds: stored bytes never pass the quota.
	if n := streamBytes(t, r, UnknownStream("lab-udp")); n == 0 || n > unknownQuota {
		t.Fatalf("the unknown stream holds %d bytes, quota %d", n, unknownQuota)
	}
	if countAlarms(st, string(c5.AlarmSyslogUnknownFull)) == 0 {
		t.Fatalf("no %s alarm: %+v", c5.AlarmSyslogUnknownFull, st.Snapshot("x").Alarms)
	}
	// The other classes are untouched: the known stream's class has no
	// full alarm.
	if countAlarms(st, string(c5.AlarmQuotaReached)) != 0 {
		t.Fatalf("a class other than syslog-unknown reached its quota: %+v", st.Snapshot("x").Alarms)
	}
}

// waitKnown waits until the listener's own stream holds n events.
func waitKnown(t *testing.T, ls *Listening, st *Status, r *Runtime, id string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(streamEvents(t, r, ListenerStream(id))) < n {
		if time.Now().After(deadline) {
			t.Fatalf("listener %s: %+v, want %d known events", id, st.Snapshot("x").Listeners[id], n)
		}
		ls.Publish()
		time.Sleep(20 * time.Millisecond)
	}
}

// A node with a listener and no syslog-unknown quota does not start, and
// the error names the class (the layout needs one, as for any class).
func TestListenerNeedsAnUnknownQuota(t *testing.T) {
	nc, _ := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
		delete(nc.Store.Quotas, "syslog-unknown")
	})
	_, err := ParseConfig(nc.Bytes())
	if err == nil || !strings.Contains(err.Error(), "syslog-unknown") {
		t.Fatalf("error %v, want one naming syslog-unknown", err)
	}
	// Without listeners the class is not in the layout and needs no quota.
	nc, _ = listenConfig(t, func(nc *nodeconfigtest.Config) { delete(nc.Store.Quotas, "syslog-unknown") })
	if _, err := ParseConfig(nc.Bytes()); err != nil {
		t.Fatalf("no listeners: %v", err)
	}
}
