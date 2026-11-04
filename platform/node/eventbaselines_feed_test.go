package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

var feedT0 = time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)

const feedListener = "lab-udp"

// feedStreams is a store's committed records, by stream.
type feedStreams struct{ recs map[c5.StreamID][]c5.Stored }

func (f *feedStreams) Read(_ context.Context, s c5.StreamID, after c5.Seq, max int) ([]c5.Stored, error) {
	var out []c5.Stored
	for _, r := range f.recs[s] {
		if r.Key.Seq > after && len(out) < max {
			out = append(out, r)
		}
	}
	return out, nil
}

// add commits ev on s at committed, with cursor as its SourceCursor.
func (f *feedStreams) add(t *testing.T, s c5.StreamID, committed time.Time, ev event.Event, cursor []byte) {
	t.Helper()
	b, err := json.Marshal(&ev)
	if err != nil {
		t.Fatal(err)
	}
	if f.recs == nil {
		f.recs = map[c5.StreamID][]c5.Stored{}
	}
	seq := c5.Seq(1)
	if n := len(f.recs[s]); n > 0 {
		seq = f.recs[s][n-1].Key.Seq + 1
	}
	f.recs[s] = append(f.recs[s], c5.Stored{Key: c5.Key{Stream: event.Stream(s), Seq: seq}, Event: b, SourceCursor: cursor, CommittedAt: committed})
}

// k is an alignment key.
func k(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rcv(at time.Time) event.Received {
	return event.Received{UTC: at.UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000}
}

func feedSER(asset, inv string, at time.Time, key string, align event.Alignment) event.Event {
	return event.Event{Kind: event.KindSER, Source: event.Source{Asset: &event.AssetRef{ID: asset}}, Received: rcv(at),
		Collection: &event.Collection{InvocationID: inv, Alignment: align}, Native: &event.Native{AlignmentKey: key}}
}

func syslogMsg(asset string, at time.Time) event.Event {
	e := event.Event{Kind: event.KindSyslog, Received: rcv(at)}
	if asset != "" {
		e.Source.Asset = &event.AssetRef{ID: asset}
	} else {
		e.Flags = []string{"asset-unresolved"}
	}
	return e
}

func runHealth(asset, typ, status string, at time.Time) event.Event {
	d := map[string]string{"asset_id": asset, "operation": "sel.ser.read_all"}
	if status != "" {
		d["status"] = status
	}
	return event.Event{Kind: event.KindHealth, Origin: event.OriginPlatform, Received: rcv(at), Health: &event.Health{Type: typ, Details: d}}
}

func state(t *testing.T, keys ...string) []byte {
	t.Helper()
	b, err := normalize.EncodeState(keys)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// feedLog is what a sink was given, one line each, and in opens the open
// gap's start each Observe and Tick carried.
type feedLog struct{ lines, opens []string }

func (l *feedLog) open(kind string, at, open time.Time) {
	o := "none"
	if !open.IsZero() {
		o = open.Format(time.RFC3339)
	}
	l.opens = append(l.opens, kind+" "+at.Format(time.RFC3339)+" open "+o)
}

func (l *feedLog) Observe(a string, o eventbaseline.Obs, open time.Time) {
	l.lines = append(l.lines, fmt.Sprintf("obs %s %s %s af=%v nc=%v", a, o.Event.Kind, o.Event.Received.UTC, o.AfterFailure, o.NotCounted))
	at, _ := time.Parse(time.RFC3339Nano, o.Event.Received.UTC)
	l.open("obs", at, open)
}
func (l *feedLog) Gap(a string, from, to time.Time, reason string) {
	l.lines = append(l.lines, fmt.Sprintf("gap %s %s %s %s", a, from.Format(time.RFC3339), to.Format(time.RFC3339), reason))
}
func (l *feedLog) Tick(a string, at, open time.Time) {
	l.lines = append(l.lines, fmt.Sprintf("tick %s %s", a, at.Format(time.RFC3339Nano)))
	l.open("tick", at, open)
}

func (l *feedLog) observed() []string {
	var out []string
	for _, s := range l.lines {
		if strings.HasPrefix(s, "obs ") {
			out = append(out, s)
		}
	}
	return out
}

// feedNode is a node observing the relay, whose SER the schedule reads and
// which also sends Syslog to the listener.
func feedNode(t *testing.T) *Config {
	t.Helper()
	c, err := ParseConfig(ebConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddEventBaseline(relayID).AddListener(feedListener, "syslog-udp", "127.0.0.1:5514").
			AddSyslogSender(relayID, "syslog", "syslog-udp", "127.0.0.2", 0)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type feedRig struct {
	f   *eventFeed
	st  *feedStreams
	log *feedLog
	now time.Time
}

func newFeedRig(t *testing.T) *feedRig {
	t.Helper()
	r := &feedRig{st: &feedStreams{}, log: &feedLog{}, now: feedT0}
	f, err := newEventFeed(feedNode(t), func(c5.StreamID) streamReader { return r.st }, func() time.Time { return r.now }, r.log)
	if err != nil {
		t.Fatal(err)
	}
	r.f = f
	return r
}

func (r *feedRig) step(t *testing.T, at time.Time) {
	t.Helper()
	r.now = at
	if err := r.f.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The relay's streams are its SER stream, the health stream (for its
// collection outcomes) and its listener's stream.
func TestFeedStreamsOfAnAsset(t *testing.T) {
	r := newFeedRig(t)
	var got []c5.StreamID
	for _, s := range r.f.assets[relayID].streams {
		got = append(got, s.id)
	}
	want := []c5.StreamID{SERStream(relayID), HealthStream, ListenerStream(feedListener)}
	if !slices.Equal(got, want) {
		t.Fatalf("streams %v, want %v", got, want)
	}
}

// Two streams interleave by received time, whatever their commit order,
// and nothing is passed until the watermark is past it.
func TestFeedMergesStreamsByReceivedTime(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	// The Syslog stream commits its two messages before the SER read
	// between them.
	r.st.add(t, ListenerStream(feedListener), sec(2), syslogMsg(relayID, sec(2)), nil)
	r.st.add(t, ListenerStream(feedListener), sec(5), syslogMsg(relayID, sec(5)), nil)
	r.st.add(t, SERStream(relayID), sec(6), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), nil)
	r.st.add(t, SERStream(relayID), sec(6), feedSER(relayID, "inv2", sec(4), k("b"), event.AlignOK), state(t, k("a"), k("b")))

	r.step(t, sec(10))
	if got := r.log.observed(); len(got) != 0 {
		t.Fatalf("passed before the watermark: %v", got)
	}
	r.step(t, sec(4).Add(FeedLateness))
	if got := r.log.observed(); len(got) != 3 {
		t.Fatalf("up to 00:00:04 + lateness: %v", got)
	}
	r.step(t, sec(10).Add(FeedLateness))
	got := r.log.observed()
	want := []string{
		"obs " + relayID + " ser 2026-10-28T10:00:01.000000Z af=false nc=false",
		"obs " + relayID + " syslog 2026-10-28T10:00:02.000000Z af=false nc=false",
		"obs " + relayID + " ser 2026-10-28T10:00:04.000000Z af=false nc=false",
		"obs " + relayID + " syslog 2026-10-28T10:00:05.000000Z af=false nc=false",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("order\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// #303's rule at the node: an event that commits late, but within
// FeedLateness of its received time, gives the same output, ticks
// included, as one that committed at once. Past FeedLateness it is late:
// counted and not passed.
func TestFeedDelayedCommitChangesNothing(t *testing.T) {
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	steps := []time.Time{sec(30), sec(90), sec(150), sec(200), sec(260), sec(400)}
	run := func(delay time.Duration) *feedRig {
		r := newFeedRig(t)
		r.st.add(t, SERStream(relayID), sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a")))
		r.st.add(t, ListenerStream(feedListener), sec(3), syslogMsg(relayID, sec(3)), nil)
		late := syslogMsg(relayID, sec(10))
		added := false
		for _, at := range steps {
			if !added && !at.Before(sec(10).Add(delay)) {
				r.st.add(t, ListenerStream(feedListener), sec(10).Add(delay), late, nil)
				added = true
			}
			r.step(t, at)
		}
		return r
	}
	prompt := run(0)
	if n := len(prompt.log.observed()); n != 3 {
		t.Fatalf("prompt run passed %d events: %v", n, prompt.log.lines)
	}
	delayed := run(FeedLateness - 10*time.Second)
	if !slices.Equal(prompt.log.lines, delayed.log.lines) {
		t.Fatalf("a commit delayed within the lateness changed the output\nprompt\n%s\ndelayed\n%s",
			strings.Join(prompt.log.lines, "\n"), strings.Join(delayed.log.lines, "\n"))
	}
	tooLate := run(FeedLateness + 50*time.Second)
	if n := len(tooLate.log.observed()); n != 2 || tooLate.f.assets[relayID].Late != 1 {
		t.Fatalf("an event past the lateness: %d passed, %d late", n, tooLate.f.assets[relayID].Late)
	}
	var ticks []string
	for _, l := range tooLate.log.lines {
		if strings.HasPrefix(l, "tick ") {
			ticks = append(ticks, l)
		}
	}
	if !slices.IsSorted(ticks) || len(slices.Compact(slices.Clone(ticks))) != len(ticks) {
		t.Fatalf("the watermark did not only rise: %v", ticks)
	}
}

// A failed SER collection opens a gap; the next read closes it, and its
// rows, and only its rows, are AfterFailure.
func TestFeedFailureGivesGapAndAfterFailure(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser, h := SERStream(relayID), HealthStream
	r.st.add(t, ser, sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.st.add(t, h, sec(1), runHealth(relayID, HealthCollectionRun, "ok", sec(1)), nil)
	r.st.add(t, h, sec(60), runHealth(relayID, HealthCollectionRun, "failed", sec(60)), nil)
	r.st.add(t, h, sec(120), runHealth(relayID, HealthCollectionOutcomeUnknown, "", sec(120)), nil)
	r.st.add(t, ser, sec(180), feedSER(relayID, "inv4", sec(180), k("b"), event.AlignOK), nil)
	r.st.add(t, ser, sec(180), feedSER(relayID, "inv4", sec(180), k("c"), event.AlignOK), state(t, k("a"), k("b"), k("c")))
	r.st.add(t, h, sec(180), runHealth(relayID, HealthCollectionRun, "ok", sec(180)), nil)
	r.st.add(t, ser, sec(240), feedSER(relayID, "inv5", sec(240), k("d"), event.AlignOK), state(t, k("b"), k("c"), k("d")))
	// Another asset's failure, and a configuration read's, are not this
	// asset's SER gap.
	r.st.add(t, h, sec(200), runHealth("other", HealthCollectionRun, "failed", sec(200)), nil)
	cfgFail := runHealth(relayID, HealthCollectionRun, "failed", sec(210))
	cfgFail.Health.Details["operation"] = "sel.config.read_all"
	r.st.add(t, h, sec(210), cfgFail, nil)

	r.step(t, sec(300).Add(FeedLateness))
	var got []string
	for _, l := range r.log.lines {
		if !strings.HasPrefix(l, "tick ") {
			got = append(got, l)
		}
	}
	want := []string{
		"obs " + relayID + " ser 2026-10-28T10:00:01.000000Z af=false nc=false",
		"gap " + relayID + " 2026-10-28T10:01:00Z 2026-10-28T10:03:00Z collection.run.failed",
		"obs " + relayID + " ser 2026-10-28T10:03:00.000000Z af=true nc=false",
		"obs " + relayID + " ser 2026-10-28T10:03:00.000000Z af=true nc=false",
		"obs " + relayID + " ser 2026-10-28T10:04:00.000000Z af=false nc=false",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A run that fails and is followed by a successful read with no rows
// closes the gap at that run.
func TestFeedGapClosedByARunWithNoRows(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	r.st.add(t, HealthStream, sec(60), runHealth(relayID, HealthCollectionRefused, "", sec(60)), nil)
	r.st.add(t, HealthStream, sec(120), runHealth(relayID, HealthCollectionRun, "ok", sec(120)), nil)
	r.st.add(t, SERStream(relayID), sec(180), feedSER(relayID, "inv3", sec(180), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(300).Add(FeedLateness))
	want := []string{
		"gap " + relayID + " 2026-10-28T10:01:00Z 2026-10-28T10:02:00Z collection.refused",
		"obs " + relayID + " ser 2026-10-28T10:03:00.000000Z af=false nc=false",
	}
	var got []string
	for _, l := range r.log.lines {
		if !strings.HasPrefix(l, "tick ") {
			got = append(got, l)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A possible duplicate whose alignment key the previous read still held is
// not counted (D4-4 item 3); one whose key it did not hold is.
func TestFeedPossibleDuplicatesNotCounted(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser := SERStream(relayID)
	r.st.add(t, ser, sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a"), k("a")))
	r.st.add(t, ser, sec(60), feedSER(relayID, "inv2", sec(60), k("a"), event.AlignPossibleDuplicate), nil)
	r.st.add(t, ser, sec(60), feedSER(relayID, "inv2", sec(60), k("z"), event.AlignPossibleDuplicate), nil)
	r.st.add(t, ser, sec(60), feedSER(relayID, "inv2", sec(60), k("b"), event.AlignOK), state(t, k("a"), k("a"), k("a"), k("z"), k("b")))
	r.step(t, sec(100).Add(FeedLateness))
	got := r.log.observed()
	want := []string{
		"obs " + relayID + " ser 2026-10-28T10:00:01.000000Z af=false nc=false",
		"obs " + relayID + " ser 2026-10-28T10:01:00.000000Z af=false nc=true",
		"obs " + relayID + " ser 2026-10-28T10:01:00.000000Z af=false nc=false",
		"obs " + relayID + " ser 2026-10-28T10:01:00.000000Z af=false nc=false",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A read split across two reads of the stream is held until its last row
// is read, so its rows are passed together and compared together.
func TestFeedHoldsAReadUntilItsLastRow(t *testing.T) {
	r := newFeedRig(t)
	r.f.batch = 2
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser := SERStream(relayID)
	r.st.add(t, ser, sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a")))
	for i, key := range []string{k("a"), k("b"), k("c")} {
		var cur []byte
		if i == 2 {
			cur = state(t, k("a"), k("a"), k("b"), k("c"))
		}
		// The read's commit stalled past FeedLateness, so the stream's
		// bound alone would pass a later event before it.
		r.st.add(t, ser, sec(60).Add(3*FeedLateness), feedSER(relayID, "inv2", sec(60), key, event.AlignPossibleDuplicate), cur)
	}
	r.st.add(t, ListenerStream(feedListener), sec(61), syslogMsg(relayID, sec(61)), nil)
	// The first step reads the first read and one row of the second.
	r.step(t, sec(60).Add(10*FeedLateness))
	if got := r.f.assets[relayID].open; len(got) != 1 {
		t.Fatalf("open read %d rows, want 1", len(got))
	}
	for _, l := range r.log.observed() {
		if strings.Contains(l, "10:01:00") {
			t.Fatalf("a row of the second read was passed before its last row: %v", r.log.observed())
		}
	}
	for range 2 {
		r.step(t, sec(60).Add(11*FeedLateness))
	}
	got := r.log.observed()
	if len(got) != 5 || !strings.HasSuffix(got[1], "nc=true") || strings.HasSuffix(got[2], "nc=true") || strings.HasSuffix(got[3], "nc=true") ||
		!strings.Contains(got[4], "syslog 2026-10-28T10:01:01") || r.f.assets[relayID].Late != 0 {
		t.Fatalf("got %v, late %d", got, r.f.assets[relayID].Late)
	}
}

// Syslog from an unknown sender counts at site level; another asset's
// events are not passed; a pruned range is counted.
func TestFeedUnresolvedAndSkipped(t *testing.T) {
	r := newFeedRig(t)
	l := ListenerStream(feedListener)
	r.st.add(t, l, feedT0, syslogMsg("", feedT0), nil)
	r.st.add(t, l, feedT0, syslogMsg("8c1b9f2e-3a4d-4e5f-8a6b-7c8d9e0f1a2b", feedT0), nil)
	r.st.add(t, l, feedT0, syslogMsg(relayID, feedT0), nil)
	r.st.recs[l] = r.st.recs[l][1:] // seq 1 pruned before the first read
	r.step(t, feedT0.Add(2*FeedLateness))
	if got := r.log.observed(); len(got) != 1 {
		t.Fatalf("passed %v", got)
	}
	var skipped int64
	for _, s := range r.f.streams {
		skipped += s.Skipped
	}
	if r.f.Unresolved != 0 || skipped != 1 {
		t.Fatalf("unresolved %d, skipped %d", r.f.Unresolved, skipped)
	}
	r.st.add(t, l, feedT0.Add(time.Second), syslogMsg("", feedT0.Add(time.Second)), nil)
	r.step(t, feedT0.Add(3*FeedLateness))
	if r.f.Unresolved != 1 {
		t.Fatalf("unresolved %d", r.f.Unresolved)
	}
}

// A stream with more to read bounds the watermark by the commit time of
// the last record read, not by the clock: its unread records may be older
// than what the other streams hold.
func TestFeedUnreadRecordsHoldTheWatermark(t *testing.T) {
	r := newFeedRig(t)
	r.f.batch = 2
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	l := ListenerStream(feedListener)
	for _, n := range []int{1, 2, 4} {
		r.st.add(t, l, sec(5), syslogMsg(relayID, sec(n)), nil)
	}
	r.st.add(t, SERStream(relayID), sec(3), feedSER(relayID, "inv1", sec(3), k("a"), event.AlignFirstRead), state(t, k("a")))
	for range 3 {
		r.step(t, sec(3600))
	}
	got := r.log.observed()
	want := []string{
		"obs " + relayID + " syslog 2026-10-28T10:00:01.000000Z af=false nc=false",
		"obs " + relayID + " syslog 2026-10-28T10:00:02.000000Z af=false nc=false",
		"obs " + relayID + " ser 2026-10-28T10:00:03.000000Z af=false nc=false",
		"obs " + relayID + " syslog 2026-10-28T10:00:04.000000Z af=false nc=false",
	}
	if !slices.Equal(got, want) || r.f.assets[relayID].Late != 0 {
		t.Fatalf("got\n%s\nlate %d", strings.Join(got, "\n"), r.f.assets[relayID].Late)
	}
}

// The watermark never goes back, even when the node's clock does.
func TestFeedWatermarkNeverGoesBack(t *testing.T) {
	r := newFeedRig(t)
	r.st.add(t, ListenerStream(feedListener), feedT0, syslogMsg(relayID, feedT0), nil)
	r.step(t, feedT0.Add(FeedLateness+time.Minute))
	r.step(t, feedT0.Add(FeedLateness)) // the clock stepped back a minute
	r.st.add(t, ListenerStream(feedListener), feedT0.Add(30*time.Second), syslogMsg(relayID, feedT0.Add(30*time.Second)), nil)
	r.step(t, feedT0.Add(FeedLateness+2*time.Minute))
	var ticks []string
	for _, l := range r.log.lines {
		if strings.HasPrefix(l, "tick ") {
			ticks = append(ticks, l)
		}
	}
	if !slices.IsSorted(ticks) || len(slices.Compact(slices.Clone(ticks))) != len(ticks) {
		t.Fatalf("ticks %v", ticks)
	}
	// The message stamped inside the window already passed is late.
	if a := r.f.assets[relayID]; a.Late != 1 || len(r.log.observed()) != 1 {
		t.Fatalf("late %d, passed %v", a.Late, r.log.observed())
	}
}

// A SER row of a new read closes the read before it even if that read's
// last row carried no alignment state; each read is compared with the
// state the feeder last had.
func TestFeedReadsAreComparedApart(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser := SERStream(relayID)
	r.st.add(t, ser, sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.st.add(t, ser, sec(60), feedSER(relayID, "inv2", sec(60), k("a"), event.AlignPossibleDuplicate), nil)
	r.st.add(t, ser, sec(120), feedSER(relayID, "inv3", sec(120), k("a"), event.AlignPossibleDuplicate), state(t, k("a"), k("a"), k("a")))
	r.step(t, sec(200).Add(FeedLateness))
	got := r.log.observed()
	if len(got) != 3 || !strings.HasSuffix(got[1], "nc=true") || !strings.HasSuffix(got[2], "nc=true") {
		t.Fatalf("got %v", got)
	}
}

// Which collection outcomes open a gap and which close one. A wrong entry
// makes a read type-only that should be learned in full, or the reverse.
func TestFeedOutcomeTable(t *testing.T) {
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	for _, c := range []struct {
		typ, status string
		opens       bool // the outcome alone opens a gap
		closes      bool // it closes a gap a failed run opened
	}{
		{HealthCollectionRun, "ok", false, true},
		{HealthCollectionRun, "partial", false, true},
		{HealthCollectionRun, "failed", true, false},
		{HealthCollectionRun, "refused", true, false},
		{HealthCollectionRefused, "", true, false},
		{HealthCollectionNoDecision, "", true, false},
		{HealthCollectionOutcomeUnknown, "", true, false},
		{HealthCollectionQuarantined, "", true, false},
		{HealthCollectionMissed, "", true, false},
		{"node.started", "", false, false},
	} {
		t.Run(strings.TrimSpace(c.typ+" "+c.status), func(t *testing.T) {
			reason := c.typ
			if c.typ == HealthCollectionRun {
				reason += "." + c.status
			}
			// C10's form of a gap reason (contracts/baseline tokenForm).
			if !regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`).MatchString(reason) {
				t.Fatalf("gap reason %q is not a C10 token", reason)
			}
			for _, afterFail := range []bool{false, true} {
				r := newFeedRig(t)
				if afterFail {
					r.st.add(t, HealthStream, sec(30), runHealth(relayID, HealthCollectionRun, "failed", sec(30)), nil)
				}
				r.st.add(t, HealthStream, sec(60), runHealth(relayID, c.typ, c.status, sec(60)), nil)
				r.st.add(t, SERStream(relayID), sec(120), feedSER(relayID, "inv2", sec(120), k("a"), event.AlignFirstRead), state(t, k("a")))
				r.step(t, sec(200).Add(FeedLateness))
				var gap string
				af := false
				switch {
				case !afterFail && c.opens:
					gap, af = "2026-10-28T10:01:00Z 2026-10-28T10:02:00Z "+reason, true
				case afterFail && c.closes:
					gap = "2026-10-28T10:00:30Z 2026-10-28T10:01:00Z collection.run.failed"
				case afterFail:
					gap, af = "2026-10-28T10:00:30Z 2026-10-28T10:02:00Z collection.run.failed", true
				}
				var want []string
				if gap != "" {
					want = append(want, "gap "+relayID+" "+gap)
				}
				want = append(want, fmt.Sprintf("obs %s ser 2026-10-28T10:02:00.000000Z af=%v nc=false", relayID, af))
				var got []string
				for _, l := range r.log.lines {
					if !strings.HasPrefix(l, "tick ") {
						got = append(got, l)
					}
				}
				if !slices.Equal(got, want) {
					t.Fatalf("after a failure %v: got\n%s\nwant\n%s", afterFail, strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
			}
		})
	}
}

// An event received exactly at the watermark already passed is late.
func TestFeedEventAtTheWatermarkIsLate(t *testing.T) {
	r := newFeedRig(t)
	r.step(t, feedT0.Add(FeedLateness))
	r.st.add(t, ListenerStream(feedListener), feedT0.Add(FeedLateness), syslogMsg(relayID, feedT0), nil)
	r.st.add(t, ListenerStream(feedListener), feedT0.Add(FeedLateness), syslogMsg(relayID, feedT0.Add(time.Microsecond)), nil)
	r.step(t, feedT0.Add(2*FeedLateness))
	if a := r.f.assets[relayID]; a.Late != 1 || len(r.log.observed()) != 1 {
		t.Fatalf("late %d, passed %v", a.Late, r.log.observed())
	}
}

// A record whose event does not decode stops its stream there: every step
// says so, the asset is held, and nothing after it is lost. Once the record
// reads, the stream goes on from it.
func TestFeedUndecodableEventStopsItsStream(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	l := ListenerStream(feedListener)
	r.st.add(t, l, sec(1), syslogMsg(relayID, sec(1)), nil)
	r.st.add(t, l, sec(2), syslogMsg(relayID, sec(2)), nil)
	r.st.add(t, l, sec(3), syslogMsg(relayID, sec(3)), nil)
	good := r.st.recs[l][1].Event
	r.st.recs[l][1].Event = []byte("not json")
	r.st.add(t, SERStream(relayID), sec(2), feedSER(relayID, "inv1", sec(2), k("a"), event.AlignFirstRead), state(t, k("a")))
	for i := range 3 {
		r.now = sec(100 * (i + 1)).Add(FeedLateness)
		err := r.f.Step(context.Background())
		if err == nil || !strings.Contains(err.Error(), "seq 2") {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if got := r.log.lines; len(got) != 0 {
		t.Fatalf("the asset was not held: %v", got)
	}
	r.st.recs[l][1].Event = good
	r.step(t, sec(400).Add(FeedLateness))
	var skipped int64
	for _, s := range r.f.streams {
		skipped += s.Skipped
	}
	if got := r.log.observed(); len(got) != 4 || r.f.assets[relayID].Late != 0 || skipped != 0 {
		t.Fatalf("passed %v, late %d, skipped %d", got, r.f.assets[relayID].Late, skipped)
	}
}

// A SER row whose alignment state does not decode stops the stream before
// it changes anything, so the read is taken once, whole, when it reads.
func TestFeedUndecodableStateStopsItsStream(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser := SERStream(relayID)
	r.st.add(t, ser, sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.st.add(t, ser, sec(60), feedSER(relayID, "inv2", sec(60), k("a"), event.AlignPossibleDuplicate), nil)
	r.st.add(t, ser, sec(60), feedSER(relayID, "inv2", sec(60), k("b"), event.AlignOK), []byte("garbage"))
	r.st.add(t, ListenerStream(feedListener), sec(90), syslogMsg(relayID, sec(90)), nil)
	for range 2 {
		r.now = sec(200).Add(FeedLateness)
		if err := r.f.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "alignment state") {
			t.Fatalf("step: %v", err)
		}
	}
	if a := r.f.assets[relayID]; len(a.open) != 1 || len(r.log.lines) != 0 {
		t.Fatalf("open %d rows, passed %v", len(a.open), r.log.lines)
	}
	// The listener's stream is not read while the only asset that reads it
	// is held (C6 on #365), and the stuck stream is read again each Step.
	if s := r.f.streams[len(r.f.streams)-1]; s.id != ListenerStream(feedListener) || s.after != 0 {
		t.Fatalf("stream %s at %d", s.id, s.after)
	}
	r.st.recs[ser][2].SourceCursor = state(t, k("a"), k("a"), k("b"))
	r.step(t, sec(300).Add(FeedLateness))
	got := r.log.observed()
	want := []string{
		"obs " + relayID + " ser 2026-10-28T10:00:01.000000Z af=false nc=false",
		"obs " + relayID + " ser 2026-10-28T10:01:00.000000Z af=false nc=true",
		"obs " + relayID + " ser 2026-10-28T10:01:00.000000Z af=false nc=false",
		"obs " + relayID + " syslog 2026-10-28T10:01:30.000000Z af=false nc=false",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A late failure opens its gap at the watermark, not at its own time, so a
// gap never starts before one already sent; a late success closes nothing.
// Both are counted late.
func TestFeedLateOutcomes(t *testing.T) {
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	nonTick := func(r *feedRig) []string {
		var got []string
		for _, l := range r.log.lines {
			if !strings.HasPrefix(l, "tick ") {
				got = append(got, l)
			}
		}
		return got
	}

	r := newFeedRig(t)
	r.st.add(t, HealthStream, sec(10), runHealth(relayID, HealthCollectionRun, "failed", sec(10)), nil)
	r.st.add(t, HealthStream, sec(20), runHealth(relayID, HealthCollectionRun, "ok", sec(20)), nil)
	r.step(t, sec(100).Add(FeedLateness)) // the watermark is at 00:01:40
	r.st.add(t, HealthStream, sec(110).Add(FeedLateness), runHealth(relayID, HealthCollectionOutcomeUnknown, "", sec(50)), nil)
	r.st.add(t, SERStream(relayID), sec(200), feedSER(relayID, "inv3", sec(200), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(300).Add(FeedLateness))
	want := []string{
		"gap " + relayID + " 2026-10-28T10:00:10Z 2026-10-28T10:00:20Z collection.run.failed",
		"gap " + relayID + " 2026-10-28T10:01:40Z 2026-10-28T10:03:20Z collection.outcome-unknown",
		"obs " + relayID + " ser 2026-10-28T10:03:20.000000Z af=true nc=false",
	}
	if got := nonTick(r); !slices.Equal(got, want) || r.f.assets[relayID].Late != 1 {
		t.Fatalf("a late failure: late %d, got\n%s\nwant\n%s", r.f.assets[relayID].Late, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	r = newFeedRig(t)
	r.st.add(t, HealthStream, sec(60), runHealth(relayID, HealthCollectionRun, "failed", sec(60)), nil)
	r.step(t, sec(100).Add(FeedLateness))
	r.st.add(t, HealthStream, sec(110).Add(FeedLateness), runHealth(relayID, HealthCollectionRun, "ok", sec(30)), nil)
	r.st.add(t, SERStream(relayID), sec(200), feedSER(relayID, "inv3", sec(200), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(300).Add(FeedLateness))
	want = []string{
		"gap " + relayID + " 2026-10-28T10:01:00Z 2026-10-28T10:03:20Z collection.run.failed",
		"obs " + relayID + " ser 2026-10-28T10:03:20.000000Z af=true nc=false",
	}
	if got := nonTick(r); !slices.Equal(got, want) || r.f.assets[relayID].Late != 1 {
		t.Fatalf("a late success: late %d, got\n%s\nwant\n%s", r.f.assets[relayID].Late, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// A late failure while a gap is already open leaves its start alone.
	r = newFeedRig(t)
	r.st.add(t, HealthStream, sec(60), runHealth(relayID, HealthCollectionRun, "failed", sec(60)), nil)
	r.step(t, sec(100).Add(FeedLateness))
	r.st.add(t, HealthStream, sec(110).Add(FeedLateness), runHealth(relayID, HealthCollectionOutcomeUnknown, "", sec(50)), nil)
	r.st.add(t, SERStream(relayID), sec(200), feedSER(relayID, "inv3", sec(200), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(300).Add(FeedLateness))
	if got := nonTick(r); !slices.Equal(got, want) || r.f.assets[relayID].Late != 1 {
		t.Fatalf("a late failure in an open gap: late %d, got\n%s\nwant\n%s", r.f.assets[relayID].Late, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A collection.missed written after its outage opens the gap where the
// series began, so the outage is not collected time; never before the
// watermark or the last gap's end.
func TestFeedMissedGapStartsAtItsSeries(t *testing.T) {
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	missed := func(first, at time.Time) event.Event {
		e := runHealth(relayID, HealthCollectionMissed, "", at)
		e.Health.Details["first_at"] = first.UTC().Format(time.RFC3339Nano)
		return e
	}
	gaps := func(r *feedRig) []string {
		var got []string
		for _, l := range r.log.lines {
			if strings.HasPrefix(l, "gap ") {
				got = append(got, l)
			}
		}
		return got
	}

	r := newFeedRig(t)
	r.st.add(t, HealthStream, sec(300), missed(sec(60), sec(300)), nil)
	r.st.add(t, SERStream(relayID), sec(301), feedSER(relayID, "inv2", sec(301), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(400).Add(FeedLateness))
	if got := gaps(r); len(got) != 1 || got[0] != "gap "+relayID+" 2026-10-28T10:01:00Z 2026-10-28T10:05:01Z collection.missed" {
		t.Fatalf("gaps %v", got)
	}

	// A first_at after the record's own time is not believed: the gap
	// starts at the record.
	r = newFeedRig(t)
	r.st.add(t, HealthStream, sec(300), missed(sec(350), sec(300)), nil)
	r.st.add(t, SERStream(relayID), sec(301), feedSER(relayID, "inv2", sec(301), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(400).Add(FeedLateness))
	if got := gaps(r); len(got) != 1 || got[0] != "gap "+relayID+" 2026-10-28T10:05:00Z 2026-10-28T10:05:01Z collection.missed" {
		t.Fatalf("gaps %v", got)
	}

	// The series began before the watermark: the gap starts at it.
	r = newFeedRig(t)
	r.step(t, sec(30).Add(FeedLateness)) // the watermark is at 00:00:30
	r.st.add(t, HealthStream, sec(300), missed(sec(20), sec(300)), nil)
	r.st.add(t, SERStream(relayID), sec(301), feedSER(relayID, "inv2", sec(301), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(400).Add(FeedLateness))
	if got := gaps(r); len(got) != 1 || got[0] != "gap "+relayID+" 2026-10-28T10:00:30Z 2026-10-28T10:05:01Z collection.missed" {
		t.Fatalf("gaps %v", got)
	}

	// The series began before the watermark and before the end of a gap
	// already sent: the gap starts at the later of the two.
	r = newFeedRig(t)
	r.st.add(t, HealthStream, sec(10), runHealth(relayID, HealthCollectionRun, "failed", sec(10)), nil)
	r.st.add(t, HealthStream, sec(40), runHealth(relayID, HealthCollectionRun, "ok", sec(40)), nil)
	r.step(t, sec(30).Add(FeedLateness)) // the watermark is at 00:00:30
	r.st.add(t, HealthStream, sec(300), missed(sec(20), sec(300)), nil)
	r.st.add(t, SERStream(relayID), sec(301), feedSER(relayID, "inv2", sec(301), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(400).Add(FeedLateness))
	want := []string{
		"gap " + relayID + " 2026-10-28T10:00:10Z 2026-10-28T10:00:40Z collection.run.failed",
		"gap " + relayID + " 2026-10-28T10:00:40Z 2026-10-28T10:05:01Z collection.missed",
	}
	if got := gaps(r); !slices.Equal(got, want) {
		t.Fatalf("gaps\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A restart resumes each stream from the checkpoint's restart point: of the
// records read again, those at or before its read-through seq and its
// watermark were passed before and are skipped, those after the watermark
// were pending and are taken, and nothing is late (slice 1c). Evidence
// class: simulated.
func TestFeedResumeSkipsWhatWasTaken(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	l := ListenerStream(feedListener)
	for _, n := range []int{10, 30, 20, 40} {
		r.st.add(t, l, sec(n), syslogMsg(relayID, sec(n)), nil)
	}
	// Before the restart: seq 1 and 3 (10 s and 20 s) passed at a watermark
	// of 25 s; seq 2 and 4 read and pending.
	a := r.f.assets[relayID]
	c := &eventCheckpoint{Watermark: sec(25).Format(time.RFC3339Nano), Streams: []checkpointStream{{Stream: string(l), RestartAfter: 1, ReadThrough: 3}}}
	for _, s := range a.streams {
		if s.id != l {
			c.Streams = append(c.Streams, checkpointStream{Stream: string(s.id)})
		}
	}
	if err := r.f.resume(a, c, nil); err != nil {
		t.Fatal(err)
	}
	r.f.start()
	r.step(t, sec(100).Add(FeedLateness))
	want := []string{
		"obs " + relayID + " syslog 2026-10-28T10:00:30.000000Z af=false nc=false",
		"obs " + relayID + " syslog 2026-10-28T10:00:40.000000Z af=false nc=false",
	}
	if got := r.log.observed(); !slices.Equal(got, want) || a.Late != 0 {
		t.Fatalf("late %d, got\n%s", a.Late, strings.Join(got, "\n"))
	}
	if p := r.f.positions(a); p[len(p)-1] != (checkpointStream{Stream: string(l), RestartAfter: 4, ReadThrough: 4}) {
		t.Fatalf("positions %+v", p)
	}
}

// A node restart opens a gap at the restored watermark for an asset whose
// SER the node reads: the first successful read after it closes it and its
// rows are AfterFailure (C1 on #372). A checkpoint taken while a read is
// pending restarts before it, with the alignment state it was compared with.
// Evidence class: simulated.
func TestFeedRestartIsAGap(t *testing.T) {
	r := newFeedRig(t)
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser := SERStream(relayID)
	r.st.add(t, ser, sec(10), feedSER(relayID, "inv1", sec(10), k("a"), event.AlignFirstRead), state(t, k("a")))
	r.step(t, sec(15).Add(FeedLateness))
	r.st.add(t, ser, sec(20), feedSER(relayID, "inv2", sec(20), k("b"), event.AlignOK), state(t, k("a"), k("b")))
	r.step(t, sec(16).Add(FeedLateness))
	a := r.f.assets[relayID]
	pos := r.f.positions(a)
	if pos[0] != (checkpointStream{Stream: string(ser), RestartAfter: 1, ReadThrough: 2}) || !slices.Equal(a.prevKeys(), []string{k("a")}) {
		t.Fatalf("positions %+v, prev %v", pos, a.prevKeys())
	}
	c := &eventCheckpoint{Watermark: a.wm.Format(time.RFC3339Nano), Streams: pos, PrevKeys: a.prevKeys()}

	r2 := newFeedRig(t)
	r2.st = r.st
	a2 := r2.f.assets[relayID]
	if err := r2.f.resume(a2, c, nil); err != nil {
		t.Fatal(err)
	}
	r2.f.start()
	r2.f.restarted(a2, sec(60))
	r2.step(t, sec(100).Add(FeedLateness))
	want := []string{
		"gap " + relayID + " 2026-10-28T10:00:16Z 2026-10-28T10:00:20Z " + ReasonNodeRestart,
		"obs " + relayID + " ser 2026-10-28T10:00:20.000000Z af=true nc=false",
	}
	var got []string
	for _, s := range r2.log.lines {
		if !strings.HasPrefix(s, "tick ") {
			got = append(got, s)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Observe and Tick carry the start of the gap still open, zero once it
// closes, the same however the steps fall, and across a restart that
// restores the gap from the checkpoint (D4-45). Evidence class: simulated.
func TestFeedPassesTheOpenGap(t *testing.T) {
	sec := func(n int) time.Time { return feedT0.Add(time.Duration(n) * time.Second) }
	ser, h, lst := SERStream(relayID), HealthStream, ListenerStream(feedListener)
	fill := func(r *feedRig) {
		r.st.add(t, ser, sec(1), feedSER(relayID, "inv1", sec(1), k("a"), event.AlignFirstRead), state(t, k("a")))
		r.st.add(t, h, sec(60), runHealth(relayID, HealthCollectionRun, "failed", sec(60)), nil)
		r.st.add(t, lst, sec(90), syslogMsg(relayID, sec(90)), nil)
		r.st.add(t, lst, sec(150), syslogMsg(relayID, sec(150)), nil)
		r.st.add(t, ser, sec(180), feedSER(relayID, "inv2", sec(180), k("b"), event.AlignOK), state(t, k("a"), k("b")))
		r.st.add(t, lst, sec(200), syslogMsg(relayID, sec(200)), nil)
	}
	obs := func(l *feedLog) []string {
		var out []string
		for _, s := range l.opens {
			if strings.HasPrefix(s, "obs ") {
				out = append(out, s)
			}
		}
		return out
	}
	want := []string{
		"obs 2026-10-28T10:00:01Z open none",
		"obs 2026-10-28T10:01:30Z open 2026-10-28T10:01:00Z",
		"obs 2026-10-28T10:02:30Z open 2026-10-28T10:01:00Z",
		"obs 2026-10-28T10:03:00Z open none", // the read closes the gap first
		"obs 2026-10-28T10:03:20Z open none",
	}

	one := newFeedRig(t)
	fill(one)
	one.step(t, sec(300).Add(FeedLateness))
	if got := obs(one.log); !slices.Equal(got, want) {
		t.Fatalf("one step: got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	many := newFeedRig(t)
	fill(many)
	for _, s := range []int{70, 100} {
		many.step(t, sec(s).Add(FeedLateness))
	}
	ticks := []string{"tick 2026-10-28T10:01:10Z open 2026-10-28T10:01:00Z", "tick 2026-10-28T10:01:40Z open 2026-10-28T10:01:00Z"}
	var gotTicks []string
	for _, s := range many.log.opens {
		if strings.HasPrefix(s, "tick ") {
			gotTicks = append(gotTicks, s)
		}
	}
	if !slices.Equal(gotTicks, ticks) {
		t.Fatalf("ticks in the gap: got\n%s\nwant\n%s", strings.Join(gotTicks, "\n"), strings.Join(ticks, "\n"))
	}

	// A restart in the gap: the checkpoint keeps its start.
	a := many.f.assets[relayID]
	c := &eventCheckpoint{Watermark: a.wm.Format(time.RFC3339Nano), Streams: many.f.positions(a), PrevKeys: a.prevKeys(),
		Gap: &checkpointGap{From: a.failedAt.Format(time.RFC3339Nano), Reason: a.failReason}}
	after := newFeedRig(t)
	after.st = many.st
	a2 := after.f.assets[relayID]
	if err := after.f.resume(a2, c, nil); err != nil {
		t.Fatal(err)
	}
	after.f.start()
	after.f.restarted(a2, sec(120))
	for _, s := range []int{160, 300} {
		after.step(t, sec(s).Add(FeedLateness))
	}
	if got := append(obs(many.log), obs(after.log)...); !slices.Equal(got, want) {
		t.Fatalf("steps and a restart: got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if last := after.log.opens[len(after.log.opens)-1]; last != "tick 2026-10-28T10:05:00Z open none" {
		t.Fatalf("last tick %q", last)
	}
}
