package eventbaseline_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/modules/telemetry/normalize"
)

// The learner and the detector against B6's GT-INJ event series
// (tests/integration/gt_inj, #251), which was committed before the product
// code existed. The series is synthetic: everything here is `simulated`.

const gtNode = "site-a-node1"

var gtAssets = map[string]string{
	"gt-inj-ser":    "5e3a1c2d-9b8f-4e7a-8c6d-1f2e3d4c5b6a",
	"gt-inj-syslog": "7c4b2d3e-ac9a-4f8b-9d7e-2a3f4e5d6c7b",
}

type gtSeries struct {
	Params baseline.Params `json:"params"`
	Period struct {
		End     string `json:"end"`
		Ack     string `json:"baseline_ack"`
		TestEnd string `json:"test_end"`
	} `json:"period"`
	Expected []struct {
		Rule   string   `json:"rule"`
		Asset  string   `json:"asset"`
		Type   []any    `json:"type"`
		At     string   `json:"at"`
		Events []string `json:"events"`
	} `json:"expected_alarms"`
	Events []gtEvent `json:"events"`
}

type gtEvent struct {
	ID        string `json:"id"`
	Asset     string `json:"asset"`
	Received  string `json:"received_utc"`
	Source    string `json:"source"`
	Element   string `json:"element"`
	State     string `json:"state"`
	Facility  int    `json:"facility"`
	Severity  int    `json:"severity"`
	MsgID     string `json:"msgid"`
	Msg       string `json:"msg"`
	Alignment string `json:"alignment"`
}

func load(t testing.TB, name string) gtSeries {
	t.Helper()
	b, err := os.ReadFile("../../../tests/integration/gt_inj/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var s gtSeries
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func seqOf(t testing.TB, id string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(id[strings.LastIndexByte(id, '-')+1:], 10, 64)
	if err != nil {
		t.Fatalf("event id %q: %v", id, err)
	}
	return n
}

// toEvent is the C4 event the platform would store for a GT-INJ event: a
// Syslog message through the real parser as RFC 5424 with the msgid in its
// place, or a parsed SER row.
func toEvent(t testing.TB, e gtEvent) *event.Event {
	t.Helper()
	rcv := event.Received{UTC: e.Received, ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}
	id := event.EventID{NodeID: gtNode, Stream: "events/gt-inj", Seq: seqOf(t, e.ID)}
	var ev event.Event
	if e.Source == "syslog" {
		msg := fmt.Sprintf("<%d>1 %s gt-inj-host gtinj - %s - %s", e.Facility*8+e.Severity, e.Received, e.MsgID, e.Msg)
		var err error
		ev, err = normalize.Syslog(normalize.SyslogInput{
			Node: gtNode, Stream: "syslog/gt-inj", Message: []byte(msg), Sender: "127.0.0.2",
			Auth: event.AuthNone, AssetID: gtAssets[e.Asset], EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC, Received: rcv,
		})
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
	} else {
		row := fmt.Sprintf("1    11/02/2026 09:00:00.000   %s %s", e.Element, e.State)
		sum := sha256.Sum256([]byte(row))
		align := event.AlignOK
		if e.Alignment != "" {
			align = event.Alignment(e.Alignment)
		}
		ev = event.Event{
			Origin: event.OriginDevice, Kind: event.KindSER, Received: rcv,
			Source:     event.Source{Asset: &event.AssetRef{ID: gtAssets[e.Asset]}},
			Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: align, ParseStatus: event.ParseOK},
			Native:     &event.Native{Bytes: []byte(row), RecordSHA256: hex.EncodeToString(sum[:]), RecordLength: int64(len(row))},
			Normalized: &event.Normalized{Subject: e.Element, SubjectType: "relay-word-bit", Value: e.State, Category: event.Unmapped},
		}
	}
	ev.ID = id
	return &ev
}

func ts(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// gtKey is the type as GT-INJ names it in expected_alarms.
func gtKey(e gtEvent) string {
	if e.Source == "ser" {
		return fmt.Sprintf("ser|%s|%s", e.Element, e.State)
	}
	var b strings.Builder
	digits := false
	for i := 0; i < len(e.Msg); i++ {
		if c := e.Msg[i]; c >= '0' && c <= '9' {
			if !digits {
				b.WriteByte('#')
			}
			digits = true
			continue
		}
		digits = false
		b.WriteByte(e.Msg[i])
	}
	return fmt.Sprintf("syslog|%d|%d|%s", e.Facility, e.Severity, b.String())
}

func typeKey(typ []any) string {
	if len(typ) == 2 {
		return fmt.Sprintf("ser|%v|%v", typ[0], typ[1])
	}
	return fmt.Sprintf("syslog|%v|%v|%v", typ[0], typ[1], typ[2])
}

// learn runs the learner over the events before the period's end, one
// learner per asset, and returns each asset's recorded baseline.
func learn(t testing.TB, s gtSeries, tweak func(*baseline.Params)) map[string]*eventbaseline.Result {
	t.Helper()
	end := ts(t, s.Period.End)
	ls := map[string]*eventbaseline.Learner{}
	for name, id := range gtAssets {
		p := s.Params
		if tweak != nil {
			tweak(&p)
		}
		l, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: gtNode, AssetID: id, Params: p, Version: 1})
		if err != nil {
			t.Fatal(err)
		}
		ls[name] = l
	}
	for _, e := range s.Events {
		if !ts(t, e.Received).Before(end) {
			continue
		}
		if err := ls[e.Asset].Observe(eventbaseline.Obs{Event: toEvent(t, e)}); err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
	}
	out := map[string]*eventbaseline.Result{}
	for name, l := range ls {
		r, err := l.Finish(end)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = r
	}
	return out
}

type raised struct {
	rule  baseline.Rule
	asset string
	key   string
	at    string
	ids   []uint64
}

func (r raised) String() string {
	return fmt.Sprintf("%s %s %s at %s %v", r.rule, r.asset, r.key, r.at, r.ids)
}

// detect replays the events from the acknowledgement on (or other, in place
// of them) against the baselines and returns every alarm, in order.
func detect(t testing.TB, base map[string]*eventbaseline.Result, ack time.Time, events []gtEvent, last time.Time) []raised {
	t.Helper()
	ds := map[string]*eventbaseline.Detector{}
	for name, r := range base {
		d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: ack})
		if err != nil {
			t.Fatal(err)
		}
		ds[name] = d
	}
	byAsset := map[string]string{}
	for name, id := range gtAssets {
		byAsset[id] = name
	}
	keys := map[string]string{}
	var got []raised
	collect := func(name string, o eventbaseline.Output) {
		for _, a := range o.Alarms {
			if err := a.Validate(); err != nil {
				t.Fatalf("invalid alarm: %v", err)
			}
			if _, err := a.Health(); err != nil {
				t.Fatalf("alarm does not fit its health event: %v", err)
			}
			r := raised{rule: a.Rule, asset: name, key: keys[a.Key.String()], at: a.AtUTC}
			for _, id := range a.Events {
				r.ids = append(r.ids, id.Seq)
			}
			got = append(got, r)
		}
	}
	for _, e := range events {
		ev := toEvent(t, e)
		if k, _, ok := baseline.KeyOf(ev); ok {
			keys[k.String()] = gtKey(e)
		}
	}
	for _, e := range events {
		if ts(t, e.Received).Before(ack) {
			continue
		}
		o, err := ds[e.Asset].Observe(eventbaseline.Obs{Event: toEvent(t, e)})
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		collect(e.Asset, o)
	}
	for name, d := range ds {
		o, err := d.Tick(last)
		if err != nil {
			t.Fatal(err)
		}
		collect(name, o)
	}
	sort.SliceStable(got, func(i, j int) bool { return got[i].at < got[j].at })
	return got
}

func ruleOf(s string) baseline.Rule {
	if s == "new" {
		return baseline.RuleNewType
	}
	return baseline.Rule(s)
}

// TestGTINJAlarmsAreExactlyTheExpectedOnes: the baselines learnt from the
// 14 observation days and activated at the acknowledgement raise B6's 16
// expected alarms and no other, each citing the events B6 lists. The
// departure before the acknowledgement, the msgid controls and the catch-up
// controls raise nothing beyond what B6 expects.
func TestGTINJAlarmsAreExactlyTheExpectedOnes(t *testing.T) {
	s := load(t, "events.json")
	base := learn(t, s, nil)
	got := detect(t, base, ts(t, s.Period.Ack), s.Events, ts(t, s.Period.TestEnd))

	var want []raised
	for _, x := range s.Expected {
		r := raised{rule: ruleOf(x.Rule), asset: x.Asset, key: typeKey(x.Type), at: ts(t, x.At).UTC().Format(time.RFC3339Nano)}
		for _, id := range x.Events {
			r.ids = append(r.ids, seqOf(t, id))
		}
		want = append(want, r)
	}
	if len(want) != 16 {
		t.Fatalf("the series expects %d alarms, not 16: it changed after this test was written", len(want))
	}
	sort.SliceStable(want, func(i, j int) bool { return want[i].at < want[j].at })
	norm := func(rs []raised) (out []string) {
		for _, r := range rs {
			out = append(out, r.String())
		}
		sort.Strings(out)
		return out
	}
	g, w := norm(got), norm(want)
	for i := 0; i < max(len(g), len(w)); i++ {
		switch {
		case i >= len(g):
			t.Errorf("missing %s", w[i])
		case i >= len(w):
			t.Errorf("unexpected %s", g[i])
		case g[i] != w[i]:
			t.Errorf("got  %s\n want %s", g[i], w[i])
		}
	}
}

// TestGTINJHeldOutRaisesNothing: the 14 benign days of the held-out series,
// replayed after the same acknowledgement against the same baselines, raise
// no departure alarm (V-M4: at most 0 per asset-day on a synthetic series).
func TestGTINJHeldOutRaisesNothing(t *testing.T) {
	s := load(t, "events.json")
	h := load(t, "events-heldout.json")
	base := learn(t, s, nil)
	ack := ts(t, s.Period.Ack)
	// The held-out series starts at the acknowledgement (#288, D4-15).
	if first := ts(t, h.Events[0].Received); first.Before(ack) || first.Sub(ack) > time.Hour {
		t.Fatalf("the held-out series starts at %s, not at the acknowledgement %s", first, ack)
	}
	last := ts(t, h.Events[len(h.Events)-1].Received)
	if got := detect(t, base, ack, h.Events, last); len(got) != 0 {
		t.Errorf("%d alarms on the benign series: %v", len(got), got)
	}
}

// TestGTINJSameInputSameAlarms: the same events and the same baseline give
// the same alarms, byte for byte (V-M4).
func TestGTINJSameInputSameAlarms(t *testing.T) {
	s := load(t, "events.json")
	a := learn(t, s, nil)
	b := learn(t, s, nil)
	for name := range a {
		if string(a[name].Bytes) != string(b[name].Bytes) || a[name].Hash != b[name].Hash {
			t.Errorf("%s: two runs recorded different baselines", name)
		}
	}
	ack, last := ts(t, s.Period.Ack), ts(t, s.Period.TestEnd)
	x, y := detect(t, a, ack, s.Events, last), detect(t, b, ack, s.Events, last)
	if fmt.Sprint(x) != fmt.Sprint(y) {
		t.Errorf("two runs raised different alarms")
	}
}

// TestGTINJSilentHeartbeatAlarmsAtAckPlusLimit: with every heartbeat after the
// acknowledgement removed, the syslog asset's heartbeat, which went silent
// during the wait and never returns, alarms once, at exactly the
// acknowledgement + interval + tolerance (D4-15; B6's case on #288).
func TestGTINJSilentHeartbeatAlarmsAtAckPlusLimit(t *testing.T) {
	s := load(t, "events.json")
	base := learn(t, s, nil)
	ack := ts(t, s.Period.Ack)
	var evs []gtEvent
	for _, e := range s.Events {
		if !(e.Asset == "gt-inj-syslog" && strings.HasPrefix(e.Msg, "Heartbeat") && !ts(t, e.Received).Before(ack)) {
			evs = append(evs, e)
		}
	}
	var hb *baseline.Type
	for i, ty := range base["gt-inj-syslog"].Baseline.Types {
		if ty.Text == "Heartbeat sequence #" {
			hb = &base["gt-inj-syslog"].Baseline.Types[i]
		}
	}
	if hb == nil || hb.Periodic == nil {
		t.Fatalf("the heartbeat is not periodic: %+v", hb)
	}
	last := ts(t, hb.LastUTC)
	limit := time.Duration(hb.Periodic.IntervalS+hb.Periodic.ToleranceS) * time.Second
	if !last.Add(limit).Before(ack) {
		t.Fatalf("the case is vacuous: the heartbeat's own deadline %s is not before the acknowledgement", last.Add(limit))
	}
	var got []string
	for _, r := range detect(t, base, ack, evs, ts(t, s.Period.TestEnd)) {
		if r.rule == baseline.RuleAbsence && r.asset == "gt-inj-syslog" && strings.Contains(r.key, "Heartbeat") {
			got = append(got, r.at)
		}
	}
	if want := ack.Add(limit).UTC().Format(time.RFC3339Nano); len(got) != 1 || got[0] != want {
		t.Errorf("heartbeat absence alarms %v, want exactly one at %s", got, want)
	}
}
