package netdetect

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// The detector's side of C13 0.3 §15 (P4-4-C13-ABS): the null VID, stacked
// tags, objects_unread and blindness. Constructed fixtures, desk only.

// spoofDetector is a detector for the node of dxNodeAddrs, on VLAN 10 and
// on the untagged segment when untagged.
func spoofDetector(t *testing.T, untagged bool) *Detector {
	t.Helper()
	c := owCfg(nil)
	c.NodeUntagged = untagged
	d, err := NewDetector(c)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// stacked is a 0.2 flow start from the node's address, sent from a MAC
// not the node's, with outer VID outer (nil untagged) and inner VIDs.
func stacked(t *testing.T, outer *int, inner ...int) *netobs.Observation {
	o := nodeFlow("192.0.2.20", 23, "02:00:00:00:00:01", outer, false)(t)
	o.Schema, o.L2.InnerVLANs = netobs.Identifier02, inner
	if len(inner) == 0 {
		o.L2.InnerVLANs = nil
	}
	if err := o.ValidateStored(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return o
}

func spoofed(t *testing.T, d *Detector, o *netobs.Observation) bool {
	t.Helper()
	out, err := d.Observe(dxID(d.Through()+1), o)
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(out, func(a netobs.Alert) bool { return a.Rule == netobs.RuleNodeAddressSpoofed })
}

// withSpoofRule runs f with nodeAddressSpoofed's condition replaced by m.
func withSpoofRule(m func(*Detector, *netobs.Observation) bool, f func()) {
	i := slices.IndexFunc(rules, func(r rule) bool { return r.rule == netobs.RuleNodeAddressSpoofed })
	orig := rules[i].applies
	rules[i].applies = m
	defer func() { rules[i].applies = orig }()
	f()
}

// §15.9 (D6's point 1): a channel record with vlan 0 goes through
// DecodeFromSensorIn, which reads the null VID as untagged, and the
// detector raises node-address-spoofed for the node's address on the
// untagged segment from a foreign MAC. Control: the pointer left at 0, as
// before §15, raises nothing (the fail-open D6 measured at bca57ee2).
func TestVLAN0SpoofThroughDecoder(t *testing.T) {
	stored := nodeFlow("192.0.2.20", 23, "02:00:00:00:00:01", nil, false)(t)
	ch := *stored
	ch.Node, ch.Schema, ch.MadeUTC = nil, netobs.Identifier03, stored.LastUTC
	ch.Coverage.ConfigDigest = "sha256:" + strings.Repeat("0f", 32)
	ch.Coverage.Settings.PRPWindowMS = netobs.DefaultPRPWindowMS
	b, err := json.Marshal(&ch)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["l2"].(map[string]any)["vlan"] = 0
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	r, err := netobs.DecodeFromSensorIn(b, netobs.Identifier03)
	if err != nil {
		t.Fatal(err)
	}
	o := r.Observation
	o.Node = stored.Node
	if !spoofed(t, spoofDetector(t, true), o) {
		t.Error("vlan 0 through the decoder: no node-address-spoofed")
	}
	o.L2.VLAN = ptr(0)
	if spoofed(t, spoofDetector(t, true), o) {
		t.Error("control: the pointer left at 0 raised node-address-spoofed")
	}
}

// §15.4, §15.9 (D1's 6955432193 item 1; D6's B1, D3's B1 on #741): the
// spoofing check reads the outer VID and every inner VID, an outer nil and
// an inner 0 each as the untagged segment, and an inner VID only adds a
// match. Each case has its control, a mutant of the rule run in its place.
func TestDoubleTagSpoof(t *testing.T) {
	ignoreInner := func(d *Detector, o *netobs.Observation) bool {
		c := *o
		c.L2.InnerVLANs = nil
		return nodeAddressSpoofed(d, &c)
	}
	ignoreOuterWhenStacked := func(d *Detector, o *netobs.Observation) bool {
		if len(o.L2.InnerVLANs) == 0 {
			return nodeAddressSpoofed(d, o)
		}
		c := *o
		c.L2.VLAN, c.L2.InnerVLANs = ptr(o.L2.InnerVLANs[0]), o.L2.InnerVLANs[1:]
		return nodeAddressSpoofed(d, &c)
	}
	innerZeroNoSegment := func(d *Detector, o *netobs.Observation) bool {
		c := *o
		c.L2.InnerVLANs = slices.DeleteFunc(slices.Clone(o.L2.InnerVLANs), func(v int) bool { return v == 0 })
		return nodeAddressSpoofed(d, &c)
	}
	innermost := func(d *Detector, o *netobs.Observation) bool {
		if len(o.L2.InnerVLANs) == 0 {
			return nodeAddressSpoofed(d, o)
		}
		c := *o
		c.L2.VLAN, c.L2.InnerVLANs = ptr(o.L2.InnerVLANs[len(o.L2.InnerVLANs)-1]), nil
		return nodeAddressSpoofed(d, &c)
	}
	for _, c := range []struct {
		name     string
		untagged bool
		o        func() *netobs.Observation
		mutant   func(*Detector, *netobs.Observation) bool
	}{
		{"outer not the node's, inner the node's", false, func() *netobs.Observation { return stacked(t, ptr(30), 10) }, ignoreInner},
		{"outer nil, inner not the node's, node untagged", true, func() *netobs.Observation { return stacked(t, nil, 30) }, ignoreOuterWhenStacked},
		{"inner 0 under a tagged outer not the node's, node untagged", true, func() *netobs.Observation { return stacked(t, ptr(30), 0) }, innerZeroNoSegment},
		{"outer the node's, inner VIDs added", false, func() *netobs.Observation { return stacked(t, ptr(10), 30, 40) }, innermost},
	} {
		if !spoofed(t, spoofDetector(t, c.untagged), c.o()) {
			t.Errorf("%s: no node-address-spoofed", c.name)
		}
		withSpoofRule(c.mutant, func() {
			if spoofed(t, spoofDetector(t, c.untagged), c.o()) {
				t.Errorf("control, %s: the mutant still raised", c.name)
			}
		})
	}
	// An inner VID only adds: the outer VID that raises still raises with
	// any inner VIDs, and a frame whose tags are none of the node's raises
	// nothing.
	if !spoofed(t, spoofDetector(t, false), stacked(t, ptr(10))) {
		t.Error("outer the node's, no inner: no node-address-spoofed")
	}
	if spoofed(t, spoofDetector(t, false), stacked(t, ptr(30), 40, 0)) {
		t.Error("no tag on the node's segments, node not untagged: raised")
	}
}

// §15.4, §15.9 check (2) (D3's B1 and N1 on #741): a frame carrying the
// node's VID only as an inner tag leaves the detector's endpoint record and
// the learner's address entry on the outer VID. Detector.covers reads no
// frame's VID: it reads the record see writes and the coverage statement.
// The controls are code mutants of see's caller (track) and of the
// learner's address entry, each reading the innermost VID; they are run by
// hand and recorded in the PR.
func TestInnerVIDOnlyAdds(t *testing.T) {
	o := stacked(t, ptr(30), 10)
	o.Node.PlatformSession = nil
	d := spoofDetector(t, false)
	if _, err := d.Observe(dxID(1), o); err != nil {
		t.Fatal(err)
	}
	a, _ := parseAddr(owRelay.Addr) // an enrolled endpoint, so the record keeps it
	if e := d.seen[a]; e == nil || !slices.Equal(e.VLANs, []int{30}) {
		t.Errorf("the detector's record: %+v, want VLAN 30 only", e)
	}
	l, err := NewLearner(lxConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Observe(1, o); err != nil {
		t.Fatal(err)
	}
	for _, x := range l.document().Addresses {
		if !slices.Equal(x.VLANs, []int{30}) {
			t.Errorf("the learner's address %s: VLANs %v, want 30 only", x.IP, x.VLANs)
		}
	}
}

// §15.9 (D6's N1 on #741): the spoofing alert's explanation, with an outer
// VID of 4094 and three inner VIDs of 4094, names the inner VIDs and the
// tag that matched, and fits ExplainMax with IPv6 ends; so does one whose
// match is an inner tag.
func TestExplainSpoofStackedFits(t *testing.T) {
	d := dxDetector(t, nil)
	for _, c := range []struct {
		own   int
		outer int
		match string
	}{{4094, 4094, "the outer tag"}, {4094, 4093, "inner tag 1, VLAN 4094"}} {
		d.own.vlans = map[int]bool{c.own: true}
		o := lxObs(t, netobs.KindFlow, "2001:db8::1:2:3:4", "2001:db8::5:6:7:8", 65535)
		o.IP.Sport = ptr(65535)
		o.L2.VLAN, o.L2.InnerVLANs = ptr(c.outer), []int{4094, 4094, 4094}
		bv, text := explainNodeAddressSpoofed(d, o)
		if len(bv) > netobs.ExplainMax || len(text) > netobs.ExplainMax {
			t.Errorf("outer %d: %d and %d bytes, above %d", c.outer, len(bv), len(text), netobs.ExplainMax)
		}
		if !strings.Contains(text, "inner VIDs 4094 4094 4094") || !strings.Contains(text, "matched by "+c.match) {
			t.Errorf("outer %d: %q names neither the inner VIDs nor the match %q", c.outer, text, c.match)
		}
	}
}

// §15.3, §15.9: a DNP3 function whose headers were not shown read to the
// end takes its code's most restrictive row: function 2 of g50v1 is write,
// not time-sync, with objects_unread true or absent. Function 1 stays
// read. Control: objects_unread false gives time-sync, and Modbus is not
// read for it.
func TestClassifyObjectsUnread(t *testing.T) {
	fn := func(code int, unread *bool, objects ...string) *netobs.Function {
		return &netobs.Function{Code: code, Objects: objects, ObjectsUnread: unread}
	}
	for _, c := range []struct {
		name  string
		proto string
		f     *netobs.Function
		class string
	}{
		{"2 g50v1, unread", "dnp3", fn(2, ptr(true), "g50v1"), netobs.ClassWrite},
		{"2 g50v1, absent", "dnp3", fn(2, nil, "g50v1"), netobs.ClassWrite},
		{"2 g80v1, unread", "dnp3", fn(2, ptr(true), "g80v1"), netobs.ClassWrite},
		{"1 g60v1, unread", "dnp3", fn(1, ptr(true), "g60v1"), netobs.ClassRead},
		{"control, 2 g50v1, read", "dnp3", fn(2, ptr(false), "g50v1"), netobs.ClassTimeSync},
		{"control, Modbus 3", "modbus", &netobs.Function{Code: 3, Objects: []string{}, Unit: ptr(1)}, netobs.ClassRead},
	} {
		if r := ClassifyFunction(c.proto, c.f); r.Class != c.class {
			t.Errorf("%s: %s, want %s", c.name, r.Class, c.class)
		}
	}
}

// §15.3: the learner does not learn a function whose headers were not read
// to the end, and new-function judges it as not in the baseline even where
// the same code and objects are. Control: the same function read to the
// end is learned, and is quiet once acknowledged.
func TestObjectsUnreadNotLearned(t *testing.T) {
	read := func(unread bool) *netobs.Observation {
		o := dxFn(t, lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 20000), 1, []string{"g60v1"}, netobs.SAUnknown, "")
		o.Function.ObjectsUnread = ptr(unread)
		return o
	}
	for _, unread := range []bool{true, false} {
		l, err := NewLearner(lxConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Observe(1, read(unread)); err != nil {
			t.Fatal(err)
		}
		if got := len(l.document().Functions); got != map[bool]int{true: 0, false: 1}[unread] {
			t.Errorf("unread %v: %d functions learned", unread, got)
		}
	}
	// The baseline holds 1 [g60v1] on the pair (dxBaseline's poll).
	base := accept(t, dxBaseline(t))
	for _, c := range []struct {
		unread bool
		want   bool
	}{{true, true}, {false, false}} {
		d := dxDetector(t, base)
		o := read(c.unread)
		got := newFunction(d, o)
		if got != c.want {
			t.Errorf("unread %v: new-function %v, want %v", c.unread, got, c.want)
		}
	}
}

// §15.6, §15.9 (D6's point 8): a record stating blindness drops a due
// session unjudged, and the detector counts it. Control: the same session
// under a coverage statement that sees the endpoint alerts and counts
// nothing.
func TestBlindnessCounted(t *testing.T) {
	for _, c := range []struct {
		name    string
		blind   func(o *netobs.Observation)
		unseen  int
		counted int64
	}{
		{"interface-bound", func(o *netobs.Observation) { o.Coverage.Degraded = []string{"interface-bound"} }, 0, 1},
		{"no VLAN seen", func(o *netobs.Observation) { o.Coverage.VLANsSeen, o.Coverage.UntaggedSeen = []int{}, false }, 0, 1},
		{"control, seeing", func(o *netobs.Observation) {}, 1, 0},
	} {
		r := newOwRun(t, nil)
		r.obs(owQuiet(t), 0)
		must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
		o := owQuiet(t)
		c.blind(o)
		r.obs(o, 50)
		if got := len(r.unseen()); got != c.unseen || r.d.Uncovered() != c.counted {
			t.Errorf("%s: %d unseen, %d uncovered, want %d and %d", c.name, got, r.d.Uncovered(), c.unseen, c.counted)
		}
	}
}
