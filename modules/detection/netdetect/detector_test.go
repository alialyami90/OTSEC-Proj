package netdetect

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// The detector's tests. Constructed fixtures, desk only, as the learner's.

const (
	dxNode       = "node-a"
	dxStreamName = event.Stream("network-observation/" + lxSensor)
)

func dxID(seq uint64) event.EventID {
	return event.EventID{NodeID: dxNode, Stream: dxStreamName, Seq: seq}
}

// dxFn makes o a DNP3 function with code and objects, classed by
// fc-classes/1 as the node would, with the SA outcome sa.
func dxFn(t testing.TB, o *netobs.Observation, code int, objects []string, sa, from string) *netobs.Observation {
	t.Helper()
	o.Kind, o.Flow, o.Service = netobs.KindFunction, nil, nil
	o.Function = &netobs.Function{Code: code, Objects: objects, SA: sa, SAErrorFrom: from}
	row := Classify("dnp3", code, nil, objects)
	o.Node.FunctionClass, o.Node.FunctionTable, o.Node.DNP3NoSA = row.Class, Table, nil
	if sa == netobs.SANone && slices.Contains(netobs.NoSAClasses, row.Class) {
		o.Node.DNP3NoSA = ptr(true)
	}
	if err := o.ValidateStored(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return o
}

func dxAt(t testing.TB, o *netobs.Observation, at time.Time) *netobs.Observation {
	t.Helper()
	o.FirstUTC = at.UTC().Format(time.RFC3339Nano)
	o.LastUTC = o.FirstUTC
	if err := o.ValidateStored(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return o
}

// dxBaseline is the baseline the rule cases judge against, learned from
// the master polling the relay on DNP3, reading (1 with g60v1) and
// operating (5 with g12v1), and an unresolved client on Modbus. A person
// authorizes the master to send controls. Its window is 60 s.
func dxBaseline(t testing.TB) []byte {
	t.Helper()
	cfg := lxConfig()
	cfg.Params.CoalesceWindowS = 60
	l, err := NewLearner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	train := []*netobs.Observation{
		lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000),
		lxObs(t, netobs.KindService, "192.0.2.10", "192.0.2.20", 20000),
		dxFn(t, lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 20000), 1, []string{"g60v1"}, netobs.SANone, ""),
		dxFn(t, lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 20000), 5, []string{"g12v1"}, netobs.SAChallenged, ""),
		lxObs(t, netobs.KindFlow, "198.51.100.7", "192.0.2.20", 502),
		lxEnd(t, "198.51.100.7", "192.0.2.20", 502, false),
		lxUDP(t, "192.0.2.20", 161, "192.0.2.10", 50000), // a UDP reply first: relay→master:50000
	}
	for i, o := range train {
		if err := l.Observe(uint64(i+1), o); err != nil {
			t.Fatal(err)
		}
	}
	draft, err := l.Freeze("2026-11-08T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return accept(t, draft, netobs.Writer{Client: lxMaster, Server: lxRelay, Class: netobs.ClassControl})
}

// accept is the accepted document: draft with a person's writers.
func accept(t testing.TB, draft []byte, writers ...netobs.Writer) []byte {
	t.Helper()
	b, err := netobs.DecodeBaseline(draft)
	if err != nil {
		t.Fatal(err)
	}
	b.AuthorizedWriters = append([]netobs.Writer{}, writers...)
	out, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func dxDetector(t testing.TB, base []byte) *Detector {
	t.Helper()
	d, err := NewDetector(DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base,
		Params: netobs.BaselineParams{TieGraceS: netobs.DefaultTieGraceS, CoalesceWindowS: 60}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ruleCase is one sample: an observation, and the rules it must raise.
type ruleCase struct {
	name    string
	noBase  bool // judged with no acknowledged baseline
	obs     func(t testing.TB) *netobs.Observation
	want    []netobs.Rule
	tagRule netobs.Rule // the rule whose sample or near-miss it is
}

func flowObs(src, dst string, dport int) func(t testing.TB) *netobs.Observation {
	return func(t testing.TB) *netobs.Observation { return lxObs(t, netobs.KindFlow, src, dst, dport) }
}

func fnObs(code int, objects []string, sa, from string) func(t testing.TB) *netobs.Observation {
	return func(t testing.TB) *netobs.Observation {
		return dxFn(t, lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 20000), code, objects, sa, from)
	}
}

// ruleCases are each rule's malicious sample and benign near-miss (§4,
// D6 plan §4), and the rules that fire together.
var ruleCases = []ruleCase{
	{name: "a new client polls the outstation", tagRule: netobs.RuleUnknownPair,
		obs: flowObs("192.0.2.20", "192.0.2.10", 20000), want: []netobs.Rule{netobs.RuleUnknownPair}},
	{name: "the known master on a new source port", tagRule: netobs.RuleUnknownPair,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)
			o.IP.Sport = ptr(40000)
			return o
		}},
	{name: "midstream, the known pair seen from its server", tagRule: netobs.RuleUnknownPair,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 51234)
			o.IP.Sport, o.Direction = ptr(20000), netobs.DirectionMidstream
			return o
		}},
	{name: "midstream, neither orientation known", tagRule: netobs.RuleUnknownPair,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20001)
			o.Direction = netobs.DirectionMidstream
			return o
		}, want: []netobs.Rule{netobs.RuleUnknownPair}},
	{name: "UDP, the reply-first pair's real orientation", tagRule: netobs.RuleUnknownPair,
		obs: func(t testing.TB) *netobs.Observation { return lxUDP(t, "192.0.2.10", 50000, "192.0.2.20", 161) }},
	{name: "UDP, another port at the learned end", tagRule: netobs.RuleUnknownPair,
		obs:  func(t testing.TB) *netobs.Observation { return lxUDP(t, "192.0.2.10", 50001, "192.0.2.20", 161) },
		want: []netobs.Rule{netobs.RuleUnknownPair}},
	{name: "a flow end raises nothing", tagRule: netobs.RuleUnknownPair,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000)
			o.Flow = &netobs.Flow{Phase: "end", End: "fin", Packets: 9, Bytes: 900, SynOnly: ptr(false)}
			return o
		}},
	{name: "a port opened on the relay", tagRule: netobs.RuleNewService,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindService, "192.0.2.10", "192.0.2.20", 23)
			o.Protocol = "telnet"
			return o
		}, want: []netobs.Rule{netobs.RuleNewService}},
	{name: "the known service found by port only", tagRule: netobs.RuleNewService,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindService, "192.0.2.10", "192.0.2.20", 20000)
			o.Service.Basis = "port"
			return o
		}},
	{name: "a reading pair starts a time-sync", tagRule: netobs.RuleNewFunction,
		obs: fnObs(2, []string{"g50v1"}, netobs.SANone, ""), want: []netobs.Rule{netobs.RuleNewFunction}},
	{name: "a pair disables unsolicited reporting", tagRule: netobs.RuleNewFunction,
		obs: fnObs(21, []string{"g60v2"}, netobs.SANone, ""), want: []netobs.Rule{netobs.RuleNewFunction}},
	{name: "the learned read code on a new object", tagRule: netobs.RuleNewFunction,
		obs: fnObs(1, []string{"g60v2"}, netobs.SANone, ""), want: []netobs.Rule{netobs.RuleNewFunction}},
	{name: "the learned read", tagRule: netobs.RuleNewFunction,
		obs: fnObs(1, []string{"g60v1"}, netobs.SANone, "")},
	{name: "a read on an unknown pair is not new-function", tagRule: netobs.RuleNewFunction,
		obs: func(t testing.TB) *netobs.Observation {
			return dxFn(t, lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 20001), 2, []string{"g50v1"}, netobs.SANone, "")
		}},
	{name: "a write from a master authorized only for controls", tagRule: netobs.RuleUnauthorizedWrite,
		obs: fnObs(2, []string{"g34v1"}, netobs.SANone, ""), want: []netobs.Rule{netobs.RuleUnauthorizedWrite}},
	{name: "a control from an unauthorized client", tagRule: netobs.RuleUnauthorizedWrite,
		obs: func(t testing.TB) *netobs.Observation {
			return dxFn(t, lxObs(t, netobs.KindFunction, "192.0.2.20", "192.0.2.10", 20000), 5, []string{"g12v1"}, netobs.SANone, "")
		}, want: []netobs.Rule{netobs.RuleUnauthorizedWrite}},
	{name: "the same control from the authorized master", tagRule: netobs.RuleUnauthorizedWrite,
		obs: fnObs(5, []string{"g12v1"}, netobs.SANone, "")},
	{name: "a spoofed source polls the relay", tagRule: netobs.RuleUnresolvedAddress,
		obs: flowObs("198.51.100.99", "192.0.2.20", 20000), want: []netobs.Rule{netobs.RuleUnknownPair, netobs.RuleUnresolvedAddress}},
	{name: "the known unresolved client as before", tagRule: netobs.RuleUnresolvedAddress,
		obs: flowObs("198.51.100.7", "192.0.2.20", 502)},
	{name: "a UDP flow from an unknown address", tagRule: netobs.RuleUnresolvedAddress,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindFlow, "198.51.100.99", "192.0.2.20", 20000)
			o.IP.L4, o.Direction = "udp", netobs.DirectionNone
			return o
		}, want: []netobs.Rule{netobs.RuleUnknownPair, netobs.RuleUnresolvedAddress}},
	{name: "a challenged control fails SA", tagRule: netobs.RuleSAFailed,
		obs: fnObs(5, []string{"g12v1"}, netobs.SAFailed, "outstation"), want: []netobs.Rule{netobs.RuleSAFailed}},
	{name: "a failed SA write from an unauthorized master", tagRule: netobs.RuleSAFailed,
		obs: fnObs(2, []string{"g34v1"}, netobs.SAFailed, "master"), want: []netobs.Rule{netobs.RuleUnauthorizedWrite, netobs.RuleSAFailed}},
	{name: "the control challenged and passed", tagRule: netobs.RuleSAFailed,
		obs: fnObs(5, []string{"g12v1"}, netobs.SAChallenged, "")},
	{name: "a failed SA with no baseline", noBase: true, tagRule: netobs.RuleSAFailed,
		obs: fnObs(2, []string{"g34v1"}, netobs.SAFailed, "master"), want: []netobs.Rule{netobs.RuleSAFailed}},
	{name: "no baseline: the baseline rules are off", noBase: true, tagRule: netobs.RuleUnknownPair,
		obs: flowObs("198.51.100.99", "192.0.2.20", 20000)},
	{name: "the node's own session is the tie rule's", tagRule: netobs.RuleUnknownPair,
		obs: func(t testing.TB) *netobs.Observation {
			o := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 22)
			o.Node.PlatformSession = &netobs.PlatformSession{InvocationID: "inv-1", Tie: "connection"}
			return o
		}},
}

// judge runs one case on a fresh detector and returns the rules raised.
func judge(t testing.TB, base []byte, c ruleCase) []netobs.Rule {
	t.Helper()
	if c.noBase {
		base = nil
	}
	alerts, err := dxDetector(t, base).Observe(dxID(1), c.obs(t))
	if err != nil {
		t.Fatal(err)
	}
	var got []netobs.Rule
	for _, a := range alerts {
		got = append(got, a.Rule)
		a.Capture = fmt.Sprintf("%064x", 9)
		if err := a.Validate(); err != nil {
			t.Errorf("%s: %s alert: %v", c.name, a.Rule, err)
		}
	}
	return got
}

func TestRules(t *testing.T) {
	base := dxBaseline(t)
	for _, c := range ruleCases {
		if got := judge(t, base, c); !slices.Equal(got, c.want) {
			t.Errorf("%s: raised %v, want %v", c.name, got, c.want)
		}
	}
}

// Every rule this version runs has a malicious sample and a near-miss.
func TestEveryRuleHasSamples(t *testing.T) {
	for _, r := range rules {
		bad, near := false, false
		for _, c := range ruleCases {
			if c.tagRule == r.rule {
				bad = bad || slices.Contains(c.want, r.rule)
				near = near || !slices.Contains(c.want, r.rule)
			}
		}
		if !bad || !near {
			t.Errorf("%s: sample %v, near-miss %v", r.rule, bad, near)
		}
	}
}

// The mutation test (P4-4-B4 acceptance): each rule's condition is swapped
// for hand-written mutants, and the rule cases must catch every one.
func TestMutants(t *testing.T) {
	base := dxBaseline(t)
	never := func(*Detector, *netobs.Observation) bool { return false }
	mutants := map[netobs.Rule][]func(*Detector, *netobs.Observation) bool{
		netobs.RuleUnknownPair: {never,
			func(d *Detector, o *netobs.Observation) bool { // one orientation only, midstream too
				p, ok := pairOf(o)
				return flowStart(o) && ok && !d.pairs[p]
			},
			func(d *Detector, o *netobs.Observation) bool { // UDP one way only
				p, ok := pairOf(o)
				if o.IP.L4 == "udp" {
					return flowStart(o) && ok && !d.pairs[p]
				}
				return unknownPair(d, o)
			},
			func(d *Detector, o *netobs.Observation) bool { // the reversed match on any port at the learned end
				p, ok := pairOf(o)
				if !flowStart(o) || !ok || o.Direction == netobs.DirectionClientServer || d.pairs[p] {
					return unknownPair(d, o)
				}
				for q := range d.pairs {
					if q.Client == p.Server && q.Server == p.Client && q.L4 == p.L4 {
						return false
					}
				}
				return true
			},
			func(d *Detector, o *netobs.Observation) bool { // the source port in the key
				p, ok := pairOf(o)
				return flowStart(o) && ok && (!d.pairs[p] || *o.IP.Sport != 51234)
			},
			func(d *Detector, o *netobs.Observation) bool { // ends judged too
				p, ok := pairOf(o)
				return o.Kind == netobs.KindFlow && ok && o.Direction == netobs.DirectionClientServer && !d.pairs[p]
			},
		},
		netobs.RuleNewService: {never,
			func(d *Detector, o *netobs.Observation) bool { // basis in the key
				p, ok := pairOf(o)
				return o.Kind == netobs.KindService && ok && (!d.services[serviceKey{p.Server, p.L4, p.Port, p.Protocol}] || o.Service.Basis != "content")
			},
		},
		netobs.RuleNewFunction: {never,
			func(d *Detector, o *netobs.Observation) bool { // any pair
				p, ok := pairOf(o)
				return o.Kind == netobs.KindFunction && ok && !writeClass(o.Node.FunctionClass) && !d.functions[functionKey(functionOf(p, o.Function))]
			},
			func(d *Detector, o *netobs.Observation) bool { // the code alone, not the objects
				p, ok := pairOf(o)
				if o.Kind != netobs.KindFunction || !ok || writeClass(o.Node.FunctionClass) || !d.pairs[p] {
					return false
				}
				for _, f := range d.base.Functions {
					if f.Pair == p && f.Code == o.Function.Code {
						return false
					}
				}
				return true
			},
			func(d *Detector, o *netobs.Observation) bool { // writes judged too
				p, ok := pairOf(o)
				return o.Kind == netobs.KindFunction && ok && d.pairs[p] && !d.functions[functionKey(functionOf(p, o.Function))]
			},
		},
		netobs.RuleUnauthorizedWrite: {never,
			func(d *Detector, o *netobs.Observation) bool { // control only
				return o.Kind == netobs.KindFunction && o.Node.FunctionClass == netobs.ClassControl &&
					!d.writers[netobs.Writer{Client: endpoint(o.Node.SrcAsset, o.IP.Src), Server: endpoint(o.Node.DstAsset, o.IP.Dst), Class: o.Node.FunctionClass}]
			},
			func(d *Detector, o *netobs.Observation) bool { // the client alone, any class
				if o.Kind != netobs.KindFunction || !writeClass(o.Node.FunctionClass) {
					return false
				}
				for w := range d.writers {
					if w.Client == endpoint(o.Node.SrcAsset, o.IP.Src) {
						return false
					}
				}
				return true
			},
		},
		netobs.RuleUnresolvedAddress: {never,
			func(d *Detector, o *netobs.Observation) bool { // the source end only
				return flowStart(o) && o.Node.SrcAsset == netobs.AssetUnresolved && o.IP.L4 == "tcp" && !d.addresses[addrKey{o.IP.Src, "addr:" + o.IP.Src}]
			},
			func(d *Detector, o *netobs.Observation) bool { // any unresolved end, known or not
				return flowStart(o) && (o.Node.SrcAsset == netobs.AssetUnresolved || o.Node.DstAsset == netobs.AssetUnresolved)
			},
		},
		netobs.RuleSAFailed: {never,
			func(_ *Detector, o *netobs.Observation) bool { // any SA in use
				return o.Kind == netobs.KindFunction && o.Function.SA != netobs.SANone && o.Function.SA != ""
			},
			func(_ *Detector, o *netobs.Observation) bool { // error from the master only
				return o.Kind == netobs.KindFunction && o.Function.SA == netobs.SAFailed && o.Function.SAErrorFrom == "master"
			},
		},
	}
	for i := range rules {
		ms := mutants[rules[i].rule]
		if len(ms) < 2 {
			t.Errorf("%s: %d mutants", rules[i].rule, len(ms))
		}
		orig := rules[i].applies
		for j, m := range ms {
			rules[i].applies = m
			caught := false
			for _, c := range ruleCases {
				if got := judge(t, base, c); !slices.Equal(got, c.want) {
					caught = true
					break
				}
			}
			if !caught {
				t.Errorf("%s mutant %d survives", rules[i].rule, j)
			}
		}
		rules[i].applies = orig
	}
}

// Coalescing (C13 §7.3): the first hit of a key alerts at once with hits
// 1; the rest are counted, and the window's end gives one summary with the
// hits, the distinct sources, the first 32 related and the first 4 cites.
// Keys are rule × destination asset, and every unresolved destination
// shares one bucket.
func TestCoalescing(t *testing.T) {
	d := dxDetector(t, dxBaseline(t))
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	seq := uint64(0)
	feed := func(o *netobs.Observation, at time.Time) []netobs.Alert {
		t.Helper()
		seq++
		out, err := d.Observe(dxID(seq), dxAt(t, o, at))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// 40 unknown clients in 198.51.100.0/24 poll the relay in one window.
	for i := 0; i < 40; i++ {
		o := lxObs(t, netobs.KindFlow, fmt.Sprintf("198.51.100.%d", 100+i%35), "192.0.2.20", 20000)
		o.Citation.CaptureID = fmt.Sprintf("ring:%s:%d", lxRun, i+1)
		out := feed(o, t0.Add(time.Duration(i)*time.Second))
		if i == 0 && (len(out) != 2 || out[0].Hits != 1 || out[1].Hits != 1) {
			t.Fatalf("first hit: %+v", out)
		}
		if i > 0 && len(out) != 0 {
			t.Fatalf("hit %d raised %d alerts in the window", i, len(out))
		}
	}
	// Two unresolved destinations share the bucket: one alert, then counts.
	if out := feed(lxObs(t, netobs.KindFlow, "192.0.2.10", "203.0.113.1", 20000), t0.Add(41*time.Second)); len(out) != 2 {
		t.Fatalf("first unresolved destination: %d alerts", len(out))
	}
	if out := feed(lxObs(t, netobs.KindFlow, "192.0.2.10", "203.0.113.2", 20000), t0.Add(42*time.Second)); len(out) != 0 {
		t.Fatalf("second unresolved destination: %d alerts", len(out))
	}
	// A hit at the window's end closes the relay's windows first.
	out := feed(lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000), t0.Add(60*time.Second))
	if len(out) != 2 {
		t.Fatalf("window end: %d alerts, want the two summaries", len(out))
	}
	for _, a := range out {
		if a.AssetID != lxRelay || a.Hits != 40 || a.Sources != 32 || len(a.Related) != 32 || a.RelatedTotal != 40 || len(a.Cites) != 4 {
			t.Errorf("summary %s: hits %d sources %d related %d/%d cites %d", a.Rule, a.Hits, a.Sources, len(a.Related), a.RelatedTotal, len(a.Cites))
		}
		if a.WindowStartUTC != "2026-11-09T08:00:00Z" || a.AtUTC != "2026-11-09T08:00:39Z" {
			t.Errorf("summary %s: window %s at %s", a.Rule, a.WindowStartUTC, a.AtUTC)
		}
		if a.Related[0].Seq != 1 || a.Cites[3].CaptureID != "ring:"+lxRun+":4" {
			t.Errorf("summary %s: related from %d, cite 4 %s", a.Rule, a.Related[0].Seq, a.Cites[3].CaptureID)
		}
	}
	// The unresolved bucket's windows close later, with hits 2.
	out = feed(lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000), t0.Add(101*time.Second))
	if len(out) != 2 || out[0].AssetID != netobs.AssetUnresolved || out[0].Hits != 2 || out[0].Sources != 1 {
		t.Fatalf("unresolved bucket: %+v", out)
	}
	if k := KeyOf(&out[0]); k != (Key{netobs.RuleUnknownPair, netobs.AssetUnresolved}) {
		t.Fatalf("key %+v", k)
	}
}

// A window with one hit ends with no summary, and a late observation
// doesn't move the clock back.
func TestWindowOneHit(t *testing.T) {
	d := dxDetector(t, dxBaseline(t))
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	steps := []struct {
		o    *netobs.Observation
		at   time.Duration
		want int
	}{
		{lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000), 0, 1},
		{lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000), 70 * time.Second, 0},
		{lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000), 10 * time.Second, 1}, // late: a new window, opened at its own time
		{lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000), 71 * time.Second, 1}, // closes it with no summary, and opens the next
		{lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000), 72 * time.Second, 0},
	}
	for i, s := range steps {
		out, err := d.Observe(dxID(uint64(i+1)), dxAt(t, s.o, t0.Add(s.at)))
		if err != nil || len(out) != s.want {
			t.Fatalf("step %d: %d alerts, err %v; want %d", i, len(out), err, s.want)
		}
		for _, a := range out {
			if a.Hits != 1 || a.WindowStartUTC != a.AtUTC {
				t.Fatalf("step %d: a summary, hits %d", i, a.Hits)
			}
		}
	}
	if d.clockUTC != "2026-11-09T08:01:12Z" {
		t.Fatalf("clock %s", d.clockUTC)
	}
}

// D4-71 condition 2's second half: an entry the full draft refused alerts
// as new once the baseline is acknowledged, which fails closed.
func TestOverflowEntryAlertsAsNew(t *testing.T) {
	l, seq, _ := fill(t)
	// A session on a new port, proven by its end, whose pair the full
	// draft refuses.
	o := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 65535)
	for i, x := range []*netobs.Observation{o, lxEnd(t, "192.0.2.10", "192.0.2.20", 65535, false)} {
		if err := l.Observe(seq+uint64(i), x); err != nil {
			t.Fatal(err)
		}
	}
	if l.period.Overflow != 1 {
		t.Fatalf("overflow %d", l.period.Overflow)
	}
	draft, err := l.Freeze("2026-11-08T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDetector(DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: draft})
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Observe(dxID(1), o)
	if err != nil || len(out) != 1 || out[0].Rule != netobs.RuleUnknownPair {
		t.Fatalf("the refused pair raised %v, %v", out, err)
	}
	held := lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 1)
	if out, err := d.Observe(dxID(2), held); err != nil || len(out) != 1 || out[0].Rule != netobs.RuleUnauthorizedWrite {
		t.Fatalf("a held pair raised %v, %v", out, err)
	}
}

// The words fit ExplainMax at their longest, and carry no device text.
func TestExplainFits(t *testing.T) {
	base := dxBaseline(t)
	d := dxDetector(t, base)
	d.version = 1<<63 - 1
	long := strings.Repeat("p", 64)
	for _, r := range rules {
		o := lxObs(t, netobs.KindFunction, "2001:db8::1:2:3:4", "2001:db8::5:6:7:8", 65535)
		o.IP.Sport = ptr(65535)
		o.Protocol, o.Direction = long, netobs.DirectionMidstream
		o.Service = &netobs.Service{Basis: "content"}
		o.Function = &netobs.Function{Code: 65535, Sub: ptr(65535), Objects: make([]string, 16), SA: netobs.SAFailed, SAErrorFrom: "outstation"}
		o.Node.FunctionClass = netobs.ClassSessionSetup
		o.Node.SrcAsset, o.Node.DstAsset = netobs.AssetUnresolved, netobs.AssetUnresolved
		bv, text := r.explain(d, o)
		if len(bv) > netobs.ExplainMax || len(text) > netobs.ExplainMax || bv == "" || text == "" {
			t.Errorf("%s: %d and %d bytes", r.rule, len(bv), len(text))
		}
	}
}

func TestDetectorRefuses(t *testing.T) {
	d := dxDetector(t, dxBaseline(t))
	other := lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000)
	other.SensorID = lxRun
	for i, o := range []*netobs.Observation{nil, {}, other} {
		if _, err := d.Observe(dxID(uint64(i+1)), o); err == nil {
			t.Errorf("observation %d taken", i)
		}
		if d.Through() != uint64(i+1) {
			t.Errorf("observation %d: through %d", i, d.Through())
		}
	}
	if out, err := d.Observe(dxID(2), lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000)); err != nil || out != nil {
		t.Errorf("a seq taken already: %v, %v", out, err)
	}
	draft := accept(t, dxBaseline(t))
	for name, cfg := range map[string]DetectorConfig{
		"no sensor":      {Baseline: draft},
		"another sensor": {SensorID: lxRun, Baseline: draft},
		"not canonical":  {SensorID: lxSensor, Baseline: append([]byte(" "), draft...)},
		"no params":      {SensorID: lxSensor},
		"a short window": {SensorID: lxSensor, Params: netobs.BaselineParams{TieGraceS: 30, CoalesceWindowS: 59}},
		"not a baseline": {SensorID: lxSensor, Baseline: []byte(`{}`)},
		"another table": {SensorID: lxSensor, Baseline: func() []byte {
			b, _ := netobs.DecodeBaseline(draft)
			b.FunctionTable = "fc-classes/2"
			out, _ := b.Encode()
			return out
		}()},
	} {
		if _, err := NewDetector(cfg); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dxStream is a recorded observation stream on the test clock: 5 s apart,
// with every ninth 20 s late, over keys that repeat inside the 60 s
// windows and keys that don't.
func dxStream(t testing.TB, n int) []*netobs.Observation {
	t.Helper()
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	var out []*netobs.Observation
	for i := range n {
		var o *netobs.Observation
		switch i % 6 {
		case 0:
			o = lxObs(t, netobs.KindFlow, "192.0.2.20", "192.0.2.10", 20000) // unknown-pair against the master
		case 1:
			o = lxObs(t, netobs.KindFlow, fmt.Sprintf("198.51.100.%d", 100+i%4), "192.0.2.20", 20000) // and unresolved-address
		case 2:
			o = fnObs(2, []string{"g34v1"}, netobs.SANone, "")(t) // unauthorized-write
		case 3:
			o = lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000) // known: nothing
		case 4:
			o = fnObs(5, []string{"g12v1"}, netobs.SAFailed, "master")(t) // sa-failed
		case 5:
			o = lxObs(t, netobs.KindFlow, "192.0.2.10", fmt.Sprintf("203.0.113.%d", i%3), 20000) // the unresolved bucket
		}
		o.Citation.CaptureID = fmt.Sprintf("ring:%s:%d", lxRun, i+1)
		at := t0.Add(time.Duration(i) * 5 * time.Second)
		if i%9 == 8 {
			at = at.Add(-20 * time.Second)
		}
		out = append(out, dxAt(t, o, at))
	}
	return out
}

// alertStream is the test's alert stream: records by seq, each the health
// body the node would commit, and the time the store stamped it with: the
// later of the test clock and the stream's last stamp.
type alertStream struct {
	recs   [][]byte
	alerts []netobs.Alert
	stamps []time.Time
}

func (s *alertStream) commit(t testing.TB, a netobs.Alert, now time.Time) {
	t.Helper()
	a.Capture = fmt.Sprintf("%x", sha256Of(mustJSON(t, a.Cites))) // the node's capture, deterministic here
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.stamps); n > 0 && now.Before(s.stamps[n-1]) {
		now = s.stamps[n-1]
	}
	s.recs, s.alerts, s.stamps = append(s.recs, mustJSON(t, h)), append(s.alerts, a), append(s.stamps, now)
}

func (s *alertStream) after(seq uint64) []Committed {
	var out []Committed
	for i := int(seq); i < len(s.alerts); i++ {
		out = append(out, Committed{Seq: uint64(i + 1), Alert: s.alerts[i]})
	}
	return out
}

// Acceptance: restore equals uninterrupted. The run is checkpointed every
// 4 observations; it is cut at every checkpoint and crashed at every
// observation up to the next, after committing each prefix of that
// observation's alerts, so the crash falls between an alert's commit and
// the next checkpoint. Restored from the checkpoint and the alerts after
// its last_alert_seq, and fed the observations after its through again,
// it gives the uninterrupted run's alert records byte for byte, and the
// same checkpoints. With a backward clock step after the checkpoint, the
// alerts committed after it carry earlier stamps than the checkpoint, and
// the restore, which goes by seq, is unchanged.
func TestDetectorRestoreAtEveryCut(t *testing.T) {
	base := dxBaseline(t)
	restoreAtEveryCut(t, DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base}, dxStream(t, 60), 4, 4, true)
}

// restoreAtEveryCut runs obs uninterrupted, checkpointing every every
// observations, then cuts at each checkpoint and crashes at each of the
// span observations after it, after each prefix of that observation's
// alerts, with and without a backward clock step, and checks the restored
// run against the uninterrupted one byte for byte.
func restoreAtEveryCut(t *testing.T, cfg DetectorConfig, obs []*netobs.Observation, every, span int, needHazard bool) {
	t.Helper()
	t0 := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	clock := func(i int, step bool, ckpt int) time.Time { // the node's clock at observation i
		now := t0.Add(time.Duration(i) * time.Second)
		if step && i > ckpt {
			now = now.Add(-time.Hour)
		}
		return now
	}

	var whole alertStream
	perObs := make([]int, len(obs)) // alerts each observation raised
	marks := map[int][]byte{}       // checkpoint after observation i (1-based)
	d, err := NewDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range obs {
		out, err := d.Observe(dxID(uint64(i+1)), o)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out {
			whole.commit(t, a, clock(i+1, false, 0))
		}
		perObs[i] = len(out)
		if (i+1)%every == 0 {
			marks[i+1] = must(d.Checkpoint(uint64(len(whole.alerts))))
		}
	}
	summaries := 0
	for _, a := range whole.alerts {
		if a.Hits > 1 {
			summaries++
		}
	}
	if len(whole.alerts) < 20 || summaries < 5 {
		t.Fatalf("the stream raised %d alerts, %d summaries: too few to test", len(whole.alerts), summaries)
	}

	hazard := false
	for _, step := range []bool{false, true} {
		for k := every; k < len(obs); k += every {
			cp, err := netobs.DecodeDetectorCheckpoint(marks[k])
			if err != nil {
				t.Fatal(err)
			}
			for j := k + 1; j <= min(k+span, len(obs)); j++ {
				for m := 0; m <= perObs[j-1]; m++ {
					// The crashed run committed every alert of the
					// observations before j, and m of j's.
					n := m
					for i := 0; i < j-1; i++ {
						n += perObs[i]
					}
					var s alertStream
					for i := range n {
						s.commit(t, whole.alerts[i], clock(seqObs(perObs, i+1), step, k))
					}
					if step && int(cp.LastAlertSeq) < n && s.stamps[cp.LastAlertSeq].Before(clock(k, false, 0)) {
						hazard = true
					}
					r, err := RestoreDetector(cfg, marks[k], s.after(cp.LastAlertSeq), uint64(j))
					if err != nil {
						t.Fatalf("cut %d crash %d/%d: %v", k, j, m, err)
					}
					for i := int(r.Through()); i < len(obs); i++ {
						out, err := r.Observe(dxID(uint64(i+1)), obs[i])
						if err != nil {
							t.Fatal(err)
						}
						for _, a := range out {
							s.commit(t, a, clock(i+1, step, k))
						}
						if (i+1)%every == 0 && i+1 > j && !bytesEqual(must(r.Checkpoint(uint64(len(s.alerts)))), marks[i+1]) {
							t.Fatalf("cut %d crash %d/%d: checkpoint at %d differs", k, j, m, i+1)
						}
					}
					if len(s.recs) != len(whole.recs) || r.Mismatches() != 0 {
						t.Fatalf("cut %d crash %d/%d step %v: %d records, want %d; mismatches %d", k, j, m, step, len(s.recs), len(whole.recs), r.Mismatches())
					}
					for i := range s.recs {
						if !bytesEqual(s.recs[i], whole.recs[i]) {
							t.Fatalf("cut %d crash %d/%d: record %d differs", k, j, m, i+1)
						}
					}
				}
			}
		}
	}
	if needHazard && !hazard {
		t.Fatal("no cut put an alert committed after its checkpoint before the checkpoint's time: the clock step isn't exercised")
	}
}

// seqObs is the observation (1-based) whose processing raised alert seq.
func seqObs(perObs []int, seq int) int {
	for i, n := range perObs {
		if seq <= n {
			return i + 1
		}
		seq -= n
	}
	return len(perObs)
}

// A restore holds back only an exact match (D1). A committed alert that
// differs from the one raised again in its place is not matched: the
// regenerated alert is returned, so it is committed, and the departure
// counts as one mismatch. The alerts after it match again. A committed
// alert the replay never reaches by the head is a mismatch too.
func TestDetectorRestoreMismatch(t *testing.T) {
	base := dxBaseline(t)
	obs := dxStream(t, 12)
	d := dxDetector(t, base)
	cp := must(d.Checkpoint(0))
	var raised []netobs.Alert
	for i, o := range obs {
		out, err := d.Observe(dxID(uint64(i+1)), o)
		if err != nil {
			t.Fatal(err)
		}
		raised = append(raised, out...)
	}
	for i := range raised {
		raised[i].Capture = fmt.Sprintf("%064x", i+1) // the node's
	}
	committed := []Committed{{1, raised[0]}, {2, raised[1]}}
	committed[1].Alert.Observation = "altered"
	r, err := RestoreDetector(DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base}, cp, committed, uint64(len(obs)))
	if err != nil {
		t.Fatal(err)
	}
	var again []netobs.Alert
	for i, o := range obs {
		out, err := r.Observe(dxID(uint64(i+1)), o)
		if err != nil {
			t.Fatal(err)
		}
		again = append(again, out...)
	}
	if len(again) != len(raised)-1 || again[0].Observation != raised[1].Observation || r.Mismatches() != 1 {
		t.Fatalf("raised again %d of %d, mismatches %d", len(again), len(raised), r.Mismatches())
	}
	// A committed alert past everything the replay raises by the head.
	extra := raised[len(raised)-1]
	extra.Hits = 99
	r, err = RestoreDetector(DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base}, cp,
		[]Committed{{1, raised[0]}, {2, extra}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := r.Observe(dxID(1), obs[0]); err != nil || len(out) != 0 || r.Mismatches() != 1 {
		t.Fatalf("at the head: %d alerts, %v, mismatches %d", len(out), err, r.Mismatches())
	}
}

// A restore refuses a checkpoint of another sensor or baseline, committed
// alerts at or below its last_alert_seq or out of order, and a checkpoint
// that doesn't restore to itself.
func TestDetectorRestoreRefuses(t *testing.T) {
	base := dxBaseline(t)
	d := dxDetector(t, base)
	if _, err := d.Observe(dxID(1), dxStream(t, 1)[0]); err != nil {
		t.Fatal(err)
	}
	cp := must(d.Checkpoint(5))
	a := netobs.Alert{}
	cfg := DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base}
	for name, c := range map[string]struct {
		cfg       DetectorConfig
		cp        []byte
		committed []Committed
	}{
		"no baseline":       {DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Params: netobs.BaselineParams{TieGraceS: 30, CoalesceWindowS: 60}}, cp, nil},
		"another baseline":  {DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: accept(t, base)}, cp, nil},
		"at last_alert_seq": {cfg, cp, []Committed{{5, a}}},
		"out of order":      {cfg, cp, []Committed{{7, a}, {6, a}}},
		"whitespace":        {cfg, append(slices.Clone(cp), ' '), nil},
		"truncated":         {cfg, cp[:len(cp)-1], nil},
	} {
		if _, err := RestoreDetector(c.cfg, c.cp, c.committed, 0); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
	if _, err := RestoreDetector(cfg, cp, nil, 0); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func sha256Of(b []byte) [32]byte { return sha256.Sum256(b) }

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// Completes TestLearnerUDPStart (D1 in D4-71): an undecoded UDP flow seen
// during learning raises no alert after acknowledgement, in either
// orientation, and a reply-first capture's reversed pair covers the real
// orientation too. Either way stays within the same two endpoints, with
// the learned port at its end: another port there, or a third host,
// alerts.
func TestUDPPairBothWays(t *testing.T) {
	l, _ := NewLearner(lxConfig())
	for i, o := range []*netobs.Observation{
		lxUDP(t, "192.0.2.10", 40000, "192.0.2.20", 123), // in order
		lxUDP(t, "192.0.2.20", 161, "192.0.2.10", 50000), // reply first: relay→master:50000 learned
	} {
		if err := l.Observe(uint64(i+1), o); err != nil {
			t.Fatal(err)
		}
	}
	d, err := NewDetector(DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: must(l.Freeze("2026-11-08T00:00:00Z"))})
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range []struct {
		name string
		o    *netobs.Observation
		want []netobs.Rule
	}{
		{"the learned flow again", lxUDP(t, "192.0.2.10", 40001, "192.0.2.20", 123), nil},
		{"its reply first", lxUDP(t, "192.0.2.20", 123, "192.0.2.10", 40000), nil},
		{"the reversed pair's real orientation", lxUDP(t, "192.0.2.10", 50000, "192.0.2.20", 161), nil},
		{"another port at the learned end", lxUDP(t, "192.0.2.10", 50001, "192.0.2.20", 161), []netobs.Rule{netobs.RuleUnknownPair}},
		{"another server port", lxUDP(t, "192.0.2.10", 40000, "192.0.2.20", 124), []netobs.Rule{netobs.RuleUnknownPair}},
		{"a third host", lxUDP(t, "198.51.100.50", 50000, "192.0.2.20", 161), []netobs.Rule{netobs.RuleUnknownPair, netobs.RuleUnresolvedAddress}},
	} {
		d.windows = map[Key]*netobs.DetectorWindow{} // judge each on its own
		out, err := d.Observe(dxID(uint64(i+1)), c.o)
		if err != nil {
			t.Fatal(err)
		}
		var got []netobs.Rule
		for _, a := range out {
			got = append(got, a.Rule)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: raised %v, want %v", c.name, got, c.want)
		}
	}
}

// Completes TestLearnerHoldsStarts (D1 in D4-71): a SYN-only probe during
// learning leaves its pair unknown, so a real session on it after
// acknowledgement alerts; a completed session's doesn't.
func TestSYNProbeAlertsAfterAcknowledgement(t *testing.T) {
	l, _ := NewLearner(lxConfig())
	for i, o := range []*netobs.Observation{
		lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 23),
		lxEnd(t, "192.0.2.10", "192.0.2.20", 23, true),
		lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000),
		lxEnd(t, "192.0.2.10", "192.0.2.20", 20000, false),
	} {
		if err := l.Observe(uint64(i+1), o); err != nil {
			t.Fatal(err)
		}
	}
	d, err := NewDetector(DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: must(l.Freeze("2026-11-08T00:00:00Z"))})
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Observe(dxID(1), lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 23))
	if err != nil || len(out) != 1 || out[0].Rule != netobs.RuleUnknownPair {
		t.Fatalf("the probed pair: %v, %v", out, err)
	}
	if out, err := d.Observe(dxID(2), lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)); err != nil || len(out) != 0 {
		t.Fatalf("the completed pair: %v, %v", out, err)
	}
}

// capAsset is a destination asset of the window-cap tests.
func capAsset(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

// capObs is a failed SA operate against asset i at at: sa-failed, which runs
// with no baseline, on its own key.
func capObs(t testing.TB, i int, at time.Time) *netobs.Observation {
	t.Helper()
	o := fnObs(5, []string{"g12v1"}, netobs.SAFailed, "master")(t)
	o.Node.DstAsset = capAsset(i)
	return dxAt(t, o, at)
}

func capDetector(t testing.TB) *Detector {
	t.Helper()
	return dxDetector(t, nil)
}

// With MaxDetectorWindows keys open, a new key alerts at once, and the
// window that started earliest closes early with its summary if it had
// repeats, or silently if not (D1 in D4-72). A key closed early opens a
// new window when it is hit again.
func TestWindowCap(t *testing.T) {
	d := capDetector(t)
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	seq := uint64(0)
	feed := func(i int, at time.Duration) []netobs.Alert {
		t.Helper()
		seq++
		out, err := d.Observe(dxID(seq), capObs(t, i, t0.Add(at)))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for i := range netobs.MaxDetectorWindows {
		if out := feed(i, time.Duration(i)*time.Millisecond); len(out) != 1 || out[0].Hits != 1 {
			t.Fatalf("key %d: %+v", i, out)
		}
	}
	if out := feed(0, 100*time.Millisecond); len(out) != 0 {
		t.Fatalf("a repeat in the window: %+v", out)
	}
	out := feed(netobs.MaxDetectorWindows, 101*time.Millisecond)
	if len(out) != 2 || out[0].AssetID != capAsset(0) || out[0].Hits != 2 || out[1].AssetID != capAsset(netobs.MaxDetectorWindows) || out[1].Hits != 1 {
		t.Fatalf("full table, new key: %+v", out)
	}
	if len(d.windows) != netobs.MaxDetectorWindows || d.EarlyCloses() != 1 {
		t.Fatalf("%d windows open, %d early closes", len(d.windows), d.EarlyCloses())
	}
	// Key 1 had no repeat, so it closes with no record.
	if out := feed(netobs.MaxDetectorWindows+1, 102*time.Millisecond); len(out) != 1 || out[0].AssetID != capAsset(netobs.MaxDetectorWindows+1) {
		t.Fatalf("full table, second new key: %+v", out)
	}
	if _, open := d.windows[Key{netobs.RuleSAFailed, capAsset(1)}]; open {
		t.Fatal("key 1 still open")
	}
	out = feed(1, 103*time.Millisecond)
	if len(out) != 1 || out[0].AssetID != capAsset(1) || out[0].Hits != 1 || out[0].WindowStartUTC != "2026-11-09T08:00:00.103Z" {
		t.Fatalf("a key closed early, hit again: %+v", out)
	}
	if _, open := d.windows[Key{netobs.RuleSAFailed, capAsset(2)}]; open {
		t.Fatal("key 2, the earliest, still open")
	}
	// Each early close is counted, with or without a summary (D3's C1 on
	// #569); a window that closes in time is not.
	if d.EarlyCloses() != 3 {
		t.Fatalf("%d early closes, want 3", d.EarlyCloses())
	}
	if out := feed(1, 104*time.Millisecond+60*time.Second); len(out) == 0 || d.EarlyCloses() != 3 {
		t.Fatalf("windows closing in time: %d alerts, %d early closes", len(out), d.EarlyCloses())
	}
}

// capStream is a stream past the cap: failed SA operates 250 ms apart,
// one in three to one of two hot assets and the rest cycling over 110, so
// more than MaxDetectorWindows keys are open within a 60 s window.
func capStream(t testing.TB, n int) []*netobs.Observation {
	t.Helper()
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	var out []*netobs.Observation
	for i := range n {
		a := 1000 + (i/3)%2
		if i%3 != 0 {
			a = i % 110
		}
		o := capObs(t, a, t0.Add(time.Duration(i)*250*time.Millisecond))
		o.Citation.CaptureID = fmt.Sprintf("ring:%s:%d", lxRun, i+1)
		out = append(out, o)
	}
	return out
}

// Past the cap, every hit is counted once across the alerts: each window
// gives a first alert, and a summary of all its hits if it had repeats.
// Some windows close early, and the state never passes the cap.
func TestWindowCapCountsEachHitOnce(t *testing.T) {
	d := capDetector(t)
	obs := capStream(t, 600)
	var all []netobs.Alert
	early := 0
	for i, o := range obs {
		out, err := d.Observe(dxID(uint64(i+1)), o)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out {
			if a.Hits > 1 && mustTime(a.WindowStartUTC).Add(60*time.Second).After(mustTime(o.FirstUTC)) {
				early++
			}
		}
		all = append(all, out...)
		if len(d.windows) > netobs.MaxDetectorWindows {
			t.Fatalf("observation %d: %d windows open", i+1, len(d.windows))
		}
	}
	// A flow raises nothing with no baseline, and closes every window.
	end := dxAt(t, lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000), time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC))
	out, err := d.Observe(dxID(uint64(len(obs)+1)), end)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, out...)
	firsts, summaries, hits := 0, 0, int64(0)
	for _, a := range all {
		if a.Hits == 1 {
			firsts++
			continue
		}
		summaries++
		hits += a.Hits
	}
	if got := hits + int64(firsts-summaries); got != int64(len(obs)) || early == 0 || d.EarlyCloses() < int64(early) || len(d.windows) != 0 {
		t.Fatalf("hits counted %d, want %d; %d summaries early; %d windows left", got, len(obs), early, len(d.windows))
	}
}

// Restore at the cap gives the uninterrupted run's records byte for byte.
func TestDetectorRestoreAtCap(t *testing.T) {
	cfg := DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName,
		Params: netobs.BaselineParams{TieGraceS: netobs.DefaultTieGraceS, CoalesceWindowS: 60}}
	restoreAtEveryCut(t, cfg, capStream(t, 600), 50, 2, false)
}

// A checkpoint taken mid-restore, with committed alerts still pending,
// names the seq before the first of them, so a second restore from it
// holds them back too: the run matches the uninterrupted one, with no
// duplicate (D6's D4 on #569).
func TestCheckpointMidRestore(t *testing.T) {
	const every = 4
	base := dxBaseline(t)
	cfg := DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base}
	obs := dxStream(t, 60)
	now := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	var whole alertStream
	marks := map[int][]byte{}
	d := dxDetector(t, base)
	for i, o := range obs {
		out, err := d.Observe(dxID(uint64(i+1)), o)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out {
			whole.commit(t, a, now)
		}
		if (i+1)%every == 0 {
			marks[i+1] = must(d.Checkpoint(uint64(len(whole.alerts))))
		}
	}
	tested := 0
	for k := every; k+2*every <= len(obs); k += every {
		// The crash came after observation j, with every alert through it
		// committed.
		j := k + 2*every
		var s alertStream
		for _, a := range whole.alerts {
			s.commit(t, a, now)
		}
		cp := mustV(netobs.DecodeDetectorCheckpoint(marks[k]))
		committedThrough := 0
		r1 := mustV(RestoreDetector(cfg, marks[k], nil, 0))
		for i := k; i < j; i++ { // count the alerts through j on a scratch restore
			out, _ := r1.Observe(dxID(uint64(i+1)), obs[i])
			committedThrough += len(out)
		}
		s.recs, s.alerts, s.stamps = s.recs[:int(cp.LastAlertSeq)+committedThrough], s.alerts[:int(cp.LastAlertSeq)+committedThrough], s.stamps[:int(cp.LastAlertSeq)+committedThrough]
		r := mustV(RestoreDetector(cfg, marks[k], s.after(cp.LastAlertSeq), uint64(j)))
		// Replay until some committed alerts were held back and some wait.
		i := k
		for ; i < j && (len(r.pending) == len(s.after(cp.LastAlertSeq)) || len(r.pending) == 0); i++ {
			if out := mustV(r.Observe(dxID(uint64(i+1)), obs[i])); len(out) != 0 {
				t.Fatalf("cut %d: a committed alert raised again: %+v", k, out)
			}
		}
		if len(r.pending) == 0 {
			continue
		}
		tested++
		mid := mustV(r.Checkpoint(uint64(len(s.alerts))))
		midCP := mustV(netobs.DecodeDetectorCheckpoint(mid))
		if midCP.LastAlertSeq != r.pending[0].Seq-1 {
			t.Fatalf("cut %d: mid-restore checkpoint names %d, want %d", k, midCP.LastAlertSeq, r.pending[0].Seq-1)
		}
		r2 := mustV(RestoreDetector(cfg, mid, s.after(midCP.LastAlertSeq), uint64(j)))
		for i := int(r2.Through()); i < len(obs); i++ {
			for _, a := range mustV(r2.Observe(dxID(uint64(i+1)), obs[i])) {
				s.commit(t, a, now)
			}
		}
		if len(s.recs) != len(whole.recs) || r2.Mismatches() != 0 {
			t.Fatalf("cut %d: %d records, want %d; mismatches %d", k, len(s.recs), len(whole.recs), r2.Mismatches())
		}
		for n := range s.recs {
			if !bytesEqual(s.recs[n], whole.recs[n]) {
				t.Fatalf("cut %d: record %d differs", k, n+1)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no cut left committed alerts pending mid-restore")
	}
}

// An observation that arrives late, with an earlier first_utc, doesn't move
// the capture clock back, so windows close where they would have, and a
// late hit doesn't move a window's at_utc back from its latest hit (D6's D6
// and D16 on #569).
func TestLateObservations(t *testing.T) {
	d := capDetector(t)
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	seq := uint64(0)
	feed := func(i int, at time.Duration) []netobs.Alert {
		t.Helper()
		seq++
		return mustV(d.Observe(dxID(seq), capObs(t, i, t0.Add(at))))
	}
	feed(0, 0)
	feed(0, 30*time.Second)
	if out := feed(0, 10*time.Second); len(out) != 0 { // late: a third hit
		t.Fatalf("a late hit: %+v", out)
	}
	feed(1, 59*time.Second)
	if out := feed(1, 20*time.Second); len(out) != 0 { // late: key 1's second hit
		t.Fatalf("a late hit on key 1: %+v", out)
	}
	cp := mustV(netobs.DecodeDetectorCheckpoint(mustV(d.Checkpoint(0))))
	if cp.ClockUTC != "2026-11-09T08:00:59Z" {
		t.Fatalf("clock %s after a late observation, want the latest", cp.ClockUTC)
	}
	if w := cp.Windows[0]; w.AssetID != capAsset(0) || w.Hits != 3 || w.AtUTC != "2026-11-09T08:00:30Z" {
		t.Fatalf("window 0: hits %d at %s, want 3 at the latest hit", w.Hits, w.AtUTC)
	}
	// Key 0's window closes at its start plus 60 s on the clock, and its
	// summary is at the latest hit.
	out := feed(2, 60*time.Second)
	if len(out) != 2 || out[0].AssetID != capAsset(0) || out[0].Hits != 3 || out[0].AtUTC != "2026-11-09T08:00:30Z" {
		t.Fatalf("at the window's end: %+v", out)
	}
}

// mustV is v, or a panic on err.
func mustV[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
