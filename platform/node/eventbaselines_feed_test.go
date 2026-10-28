package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// feedLog is what a sink was given, one line each.
type feedLog struct{ lines []string }

func (l *feedLog) Observe(a string, o eventbaseline.Obs) {
	l.lines = append(l.lines, fmt.Sprintf("obs %s %s %s af=%v nc=%v", a, o.Event.Kind, o.Event.Received.UTC, o.AfterFailure, o.NotCounted))
}
func (l *feedLog) Gap(a string, from, to time.Time, reason string) {
	l.lines = append(l.lines, fmt.Sprintf("gap %s %s %s %s", a, from.Format(time.RFC3339), to.Format(time.RFC3339), reason))
}
func (l *feedLog) Tick(a string, at time.Time) {
	l.lines = append(l.lines, fmt.Sprintf("tick %s %s", a, at.Format(time.RFC3339Nano)))
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
		"gap " + relayID + " 2026-10-28T10:01:00Z 2026-10-28T10:03:00Z collection.run failed",
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
