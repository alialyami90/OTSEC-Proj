//go:build otsec_testclock

package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// The test clock's tests (D4-40, V-M4). They run only in a build tagged
// otsec_testclock. Evidence class: simulated.

var clockT0 = time.Date(2030, 11, 4, 10, 0, 0, 0, time.UTC)

// useClock puts the node on a test clock at t0 for the test, and returns a
// step that moves it and waits until the clock has read the step.
func useClock(t *testing.T, t0 time.Time) func(time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clock")
	write := func(at time.Time) {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(at.Format(time.RFC3339Nano)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// On Windows a rename over the file is refused while the clock
		// is reading it (C5 on #400), so it is retried for a moment.
		var err error
		for end := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
			if err = os.Rename(tmp, path); err == nil || time.Now().After(end) {
				break
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	write(t0)
	prev := nodeClock
	if err := UseTestClock(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeClock = prev })
	return func(at time.Time) {
		t.Helper()
		write(at)
		for end := time.Now().Add(5 * time.Second); !nodeClock.Now().Equal(at); {
			if time.Now().After(end) {
				t.Fatalf("the clock is at %s, not the step to %s", nodeClock.Now(), at)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

func fired(c <-chan time.Time) bool {
	select {
	case <-c:
		return true
	case <-time.After(20 * TestClockPoll):
		return false
	}
}

// Now is the file's time; a timer and a ticker fire when a step reaches
// them and never between steps; a step back is refused and leaves the clock
// where it was.
func TestTestClockSteps(t *testing.T) {
	step := useClock(t, clockT0)
	if got := nodeClock.Now(); !got.Equal(clockT0) {
		t.Fatalf("Now %s, want %s", got, clockT0)
	}
	timer, stopTimer := nodeClock.NewTimer(time.Minute)
	tick, stopTick := nodeClock.NewTicker(TickInterval)
	defer stopTick()
	if fired(timer) || fired(tick) {
		t.Fatal("fired with the clock not stepped")
	}
	step(clockT0.Add(59 * time.Second))
	if fired(timer) || fired(tick) {
		t.Fatal("fired a second early")
	}
	step(clockT0.Add(time.Minute))
	if !fired(timer) || !fired(tick) {
		t.Fatal("did not fire at the step")
	}
	if stopTimer() {
		t.Fatal("a fired timer stopped as if it were waiting")
	}
	// A step past three periods sends one tick, as a time.Ticker drops the
	// ticks nobody took, and the next is due a period after the step.
	step(clockT0.Add(4 * time.Minute))
	if !fired(tick) || fired(tick) {
		t.Fatal("not one tick for a step past several periods")
	}
	step(clockT0.Add(4*time.Minute + 59*time.Second))
	if fired(tick) {
		t.Fatal("ticked before its next period")
	}

	// Back: refused, the clock stays.
	at := nodeClock.Now()
	nodeClock.(*fileClock).set(clockT0)
	if got := nodeClock.Now(); !got.Equal(at) {
		t.Fatalf("a step back moved the clock to %s", got)
	}
	stopped, stop := nodeClock.NewTimer(time.Minute)
	if !stop() {
		t.Fatal("a waiting timer did not stop")
	}
	step(at.Add(2 * time.Minute))
	if fired(stopped) {
		t.Fatal("a stopped timer fired")
	}
}

// One clock for the node, the store included (C5 on the design): a runtime
// with no Now of its own stamps received and committed times from the test
// clock, and the feeder passes those events as the clock is stepped. With
// committed_at on the wall clock, a stream read in full batches would hold
// the watermark years behind the events.
func TestTestClockReachesTheStoreAndTheFeeder(t *testing.T) {
	step := useClock(t, clockT0)
	c, dir := configNode(t, func(nc *nodeconfigtest.Config) {
		nc.AddEventBaseline(relayID).AddListener(feedListener, "syslog-udp", "127.0.0.1:5514").
			AddSyslogSender(relayID, "syslog", "syslog-udp", "127.0.0.2", 0)
	})
	r, _, _ := start(t, c, dir)
	defer r.Close()
	stream := ListenerStream(feedListener)
	for i := range 3 {
		at := clockT0.Add(time.Duration(i) * 10 * time.Minute)
		step(at)
		ev, err := normalize.Syslog(normalize.SyslogInput{Node: c.NodeID, Stream: event.Stream(stream),
			Message: []byte("<13>1 - relay - - - - test"), Sender: "127.0.0.2", Auth: event.AuthNone,
			AssetID: relayID, EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC, Received: r.received()})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(&ev)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassSyslogDatagram, Event: b}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.Store(stream).Read(bg, stream, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range got {
		want := clockT0.Add(time.Duration(i) * 10 * time.Minute)
		var ev struct{ Received struct{ UTC string } }
		if err := json.Unmarshal(s.Event, &ev); err != nil {
			t.Fatal(err)
		}
		if !s.CommittedAt.Equal(want) || ev.Received.UTC != want.Format("2006-01-02T15:04:05.000000Z") {
			t.Fatalf("record %d: committed %s, received %s, want both %s", i, s.CommittedAt, ev.Received.UTC, want)
		}
	}

	log := &feedLog{}
	f, err := newEventFeed(c, func(s c5.StreamID) streamReader { return r.Store(s) }, nodeClock.Now, log)
	if err != nil {
		t.Fatal(err)
	}
	// One record a read, so a stream with more to read bounds the
	// watermark by its last commit time.
	f.batch = 1
	step(clockT0.Add(30 * time.Minute))
	for i := 0; len(log.observed()) < 3; i++ {
		if i == 100 {
			t.Fatalf("the feeder passed %d of 3 events in %d steps: %v", len(log.observed()), i, log.lines)
		}
		if err := f.Step(bg); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range log.lines {
		var asset, at string
		if _, err := fmt.Sscanf(l, "tick %s %s", &asset, &at); err != nil {
			continue
		}
		wm, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			t.Fatal(err)
		}
		if wm.Before(clockT0.Add(-FeedLateness)) {
			t.Fatalf("watermark %s is behind the test clock's start %s: a commit time is not test time: %v", wm, clockT0, log.lines)
		}
	}
}
