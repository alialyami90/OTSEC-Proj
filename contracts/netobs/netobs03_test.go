package netobs

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// C13 0.3 fixtures. Every value is illustrative: no sensor produced them
// and no device was contacted.

// fxEnd03 is a 0.3 channel flow end, not a first sight: a TCP end with
// every count of CH-52 to CH-55 and no incomplete, or a UDP end with the
// four counts of CH-52.
func fxEnd03(l4 string) *Observation {
	o := fxObservation02()
	o.Schema = Identifier03
	o.Kind, o.Function, o.Frames, o.FirstSight, o.Seq = KindFlow, nil, nil, false, "43"
	o.Flow = &Flow{Phase: "end", Packets: 3, Bytes: 222, End: "fin",
		OrigPayload: ptr(int64(40)), RespPayload: ptr(int64(900)), OrigPkts: ptr(int64(2)), RespPkts: ptr(int64(1))}
	if l4 == "udp" {
		o.IP.L4, o.Direction, o.Flow.End = "udp", DirectionNone, "idle"
		return o
	}
	o.Flow.SynOnly = ptr(false)
	o.Flow.ToDeviceOverlapOctets, o.Flow.RexmitInconsistent, o.Flow.PasswordLines = ptr(int64(0)), ptr(int64(0)), ptr(int64(1))
	return o
}

// asStored is o as the node stores it.
func asStored(o *Observation) *Observation {
	o.Node = &Node{SrcAsset: fxMaster, DstAsset: fxAsset, ResolvedBy: "ip", EvidenceClass: "simulated"}
	return o
}

// clear03 removes every field 0.3 adds to an end; at 0.1 also 0.2's.
func clear03(o *Observation, schema string) *Observation {
	o.Schema = schema
	f := o.Flow
	f.OrigPayload, f.RespPayload, f.OrigPkts, f.RespPkts = nil, nil, nil, nil
	f.ToDeviceOverlapOctets, f.Incomplete, f.RexmitInconsistent, f.PasswordLines = nil, nil, nil, nil
	if schema == Identifier {
		o.MadeUTC, o.Coverage = "", fxCoverage()
	}
	return o
}

func fxHeartbeat03() *Heartbeat {
	h := fxHeartbeat02()
	h.Schema = Identifier03
	h.FrameStage = &FrameStage{OverlapTableFull: ptr(uint64(0))}
	h.Agent.OverlapJoinRefused, h.Agent.OverlapUnjoined = ptr(uint64(0)), ptr(uint64(0))
	return h
}

// fxMismatch is a 0.3 own-session-mismatch alert, raised before any
// baseline is acknowledged.
func fxMismatch() *Alert {
	a := fxAlert()
	a.Schema, a.Rule, a.Baseline, a.BaselineVersion = Identifier03, RuleOwnSessionMismatch, "", 0
	a.KeyText = "own-session-mismatch for " + fxAsset
	a.BaselineValue = "the run's profile"
	a.Observation = "comparison M3 M6b: 412 octets to the relay above the run's bound"
	return a
}

// in03 decodes o's JSON on a 0.3 connection.
func in03(t *testing.T, v any) error {
	t.Helper()
	_, err := DecodeFromSensorIn(mustJSON(t, v), Identifier03)
	return err
}

// CH-52 to CH-55 on the 0.3 channel: placement, ranges, and what is
// required (N-4, N-5 and N-7's contract legs, D4's own).
func TestFlowEnd03Channel(t *testing.T) {
	for _, l4 := range []string{"tcp", "udp"} {
		if err := in03(t, fxEnd03(l4)); err != nil {
			t.Errorf("a 0.3 %s end: %v", l4, err)
		}
	}
	max := int64(math.MaxInt64)
	top := fxEnd03("tcp")
	for _, x := range top.Flow.counts03() {
		*x.v = max
	}
	if err := in03(t, top); err != nil {
		t.Errorf("every count at 2^63 - 1: %v", err)
	}
	start := fxEnd03("tcp")
	clear03(start, Identifier03).Flow = &Flow{Phase: "start", Packets: 1, Bytes: 60}
	if err := in03(t, start); err != nil {
		t.Errorf("a 0.3 start with no count: %v", err)
	}

	ok := []struct {
		name string
		mut  func(f *Flow)
	}{
		{"incomplete with no count", func(f *Flow) { f.ToDeviceOverlapOctets, f.PasswordLines, f.Incomplete = nil, nil, ptr(true) }},
		{"incomplete with a count", func(f *Flow) { f.PasswordLines, f.Incomplete = nil, ptr(true) }},
		{"no password_lines", func(f *Flow) { f.PasswordLines = nil }},
		{"syn-only with no payload", func(f *Flow) { f.SynOnly, f.OrigPayload, f.RespPayload = ptr(true), ptr(int64(0)), ptr(int64(0)) }},
	}
	for _, tc := range ok {
		o := fxEnd03("tcp")
		tc.mut(o.Flow)
		if err := in03(t, o); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	bad := []struct {
		name  string
		l4    string
		mut   func(f *Flow)
		code  Code
		field string
	}{
		{"tcp without orig_payload", "tcp", func(f *Flow) { f.OrigPayload = nil }, CodeMissing, "flow.orig_payload"},
		{"tcp without resp_payload", "tcp", func(f *Flow) { f.RespPayload = nil }, CodeMissing, "flow.resp_payload"},
		{"tcp without orig_pkts", "tcp", func(f *Flow) { f.OrigPkts = nil }, CodeMissing, "flow.orig_pkts"},
		{"tcp without resp_pkts", "tcp", func(f *Flow) { f.RespPkts = nil }, CodeMissing, "flow.resp_pkts"},
		{"udp without orig_payload", "udp", func(f *Flow) { f.OrigPayload = nil }, CodeMissing, "flow.orig_payload"},
		{"udp without resp_pkts", "udp", func(f *Flow) { f.RespPkts = nil }, CodeMissing, "flow.resp_pkts"},
		{"tcp without rexmit_inconsistent", "tcp", func(f *Flow) { f.RexmitInconsistent = nil }, CodeMissing, "flow.rexmit_inconsistent"},
		{"tcp with neither count nor incomplete", "tcp", func(f *Flow) { f.ToDeviceOverlapOctets, f.PasswordLines = nil, nil }, CodeMissing, "flow.to_device_overlap_octets"},
		{"incomplete false", "tcp", func(f *Flow) { f.Incomplete = ptr(false) }, CodeForm, "flow.incomplete"},
		{"password_lines beside incomplete", "tcp", func(f *Flow) { f.Incomplete = ptr(true) }, CodeConflict, "flow.password_lines"},
		{"syn-only with orig_payload", "tcp", func(f *Flow) { f.SynOnly, f.RespPayload, f.OrigPayload = ptr(true), ptr(int64(0)), ptr(int64(1)) }, CodeConflict, "flow.orig_payload"},
		{"syn-only with resp_payload", "tcp", func(f *Flow) { f.SynOnly, f.OrigPayload, f.RespPayload = ptr(true), ptr(int64(0)), ptr(int64(1)) }, CodeConflict, "flow.resp_payload"},
		{"udp with the overlap count", "udp", func(f *Flow) { f.ToDeviceOverlapOctets = ptr(int64(0)) }, CodeConflict, "flow.to_device_overlap_octets"},
		{"udp with incomplete", "udp", func(f *Flow) { f.Incomplete = ptr(true) }, CodeConflict, "flow.incomplete"},
		{"udp with rexmit_inconsistent", "udp", func(f *Flow) { f.RexmitInconsistent = ptr(int64(0)) }, CodeConflict, "flow.rexmit_inconsistent"},
		{"udp with password_lines", "udp", func(f *Flow) { f.PasswordLines = ptr(int64(0)) }, CodeConflict, "flow.password_lines"},
	}
	for _, x := range fxEnd03("tcp").Flow.counts03() {
		name := x.name
		bad = append(bad, struct {
			name  string
			l4    string
			mut   func(f *Flow)
			code  Code
			field string
		}{name + " -1", "tcp", func(f *Flow) {
			for _, y := range f.counts03() {
				if y.name == name {
					*y.v = -1
				}
			}
		}, CodeRange, name})
	}
	for _, tc := range bad {
		o := fxEnd03(tc.l4)
		tc.mut(o.Flow)
		if err := in03(t, o); !refusedAt(err, tc.code, tc.field) {
			t.Errorf("%s: got %v, want %s at %s", tc.name, err, tc.code, tc.field)
		}
	}

	// Never on a start: each count, and incomplete.
	for _, set := range []func(f *Flow){
		func(f *Flow) { f.OrigPayload = ptr(int64(0)) }, func(f *Flow) { f.RespPkts = ptr(int64(0)) },
		func(f *Flow) { f.ToDeviceOverlapOctets = ptr(int64(0)) }, func(f *Flow) { f.Incomplete = ptr(true) },
		func(f *Flow) { f.RexmitInconsistent = ptr(int64(0)) }, func(f *Flow) { f.PasswordLines = ptr(int64(0)) },
	} {
		o := fxEnd03("tcp")
		clear03(o, Identifier03).Flow = &Flow{Phase: "start", Packets: 1, Bytes: 60}
		set(o.Flow)
		if err := in03(t, o); !hasCode(err, CodeConflict) || !strings.Contains(err.Error(), "only on the end phase") {
			t.Errorf("a start with a 0.3 field: %v", err)
		}
	}

	// 2^63 is past the range: the decode refuses it.
	b := encodeWith(t, fxEnd03("tcp"), func(m map[string]any) {
		m["flow"].(map[string]any)["orig_payload"] = json.Number("9223372036854775808")
	})
	if _, err := DecodeFromSensorIn(b, Identifier03); !hasCode(err, CodeDecode) {
		t.Errorf("orig_payload 2^63: %v", err)
	}
}

// Each 0.3 field is refused below 0.3, on the channel and in a stored
// record; optional in a stored record of any minor; and a later minor's
// stored record is read forward (C13 0.3 §1.1; N-4's and N-12's legs).
func TestFlowEnd03Minors(t *testing.T) {
	for _, x := range []string{"orig_payload", "resp_payload", "orig_pkts", "resp_pkts",
		"to_device_overlap_octets", "incomplete", "rexmit_inconsistent", "password_lines"} {
		o := clear03(fxEnd03("tcp"), Identifier02)
		if x == "incomplete" {
			o.Flow.Incomplete = ptr(true)
		} else {
			reflect.ValueOf(o.Flow).Elem().FieldByIndex(fieldIndex(t, x)).Set(reflect.ValueOf(ptr(int64(0))))
		}
		if _, err := DecodeFromSensorIn(mustJSON(t, o), Identifier02); !refusedAt(err, CodeDecode, "flow."+x) {
			t.Errorf("%s on the 0.2 channel: %v", x, err)
		}
		if _, err := DecodeStored(mustJSON(t, asStored(o))); !refusedAt(err, CodeDecode, "flow."+x) {
			t.Errorf("%s in a stored 0.2 record: %v", x, err)
		}
		o.Node, o.Schema, o.MadeUTC, o.Coverage = nil, Identifier, "", fxCoverage()
		if _, err := DecodeChannel(mustJSON(t, o)); !refusedAt(err, CodeDecode, "flow."+x) {
			t.Errorf("%s on the 0.1 channel: %v", x, err)
		}
	}
	if _, err := DecodeFromSensorIn(mustJSON(t, clear03(fxEnd03("tcp"), Identifier02)), Identifier02); err != nil {
		t.Errorf("a 0.2 channel end without them: %v", err)
	}
	for _, s := range []string{Identifier, Identifier02, Identifier03} {
		for _, l4 := range []string{"tcp", "udp"} {
			if _, err := DecodeStored(mustJSON(t, asStored(clear03(fxEnd03(l4), s)))); err != nil {
				t.Errorf("a stored %s %s end without them: %v", s, l4, err)
			}
		}
	}
	got, err := DecodeStored(mustJSON(t, asStored(fxEnd03("tcp"))))
	if err != nil || got.Flow.OrigPayload == nil || *got.Flow.PasswordLines != 1 {
		t.Errorf("a stored 0.3 end: %+v, %v", got, err)
	}
	later := asStored(fxEnd03("tcp"))
	later.Schema = "otsec.netobs/0.4"
	b := encodeWith(t, later, func(m map[string]any) { m["flow"].(map[string]any)["added_in_04"] = 1 })
	if _, err := DecodeStored(b); err != nil {
		t.Errorf("a stored 0.4 end with an added field: %v", err)
	}
	b = encodeWith(t, asStored(fxEnd03("tcp")), func(m map[string]any) { m["flow"].(map[string]any)["added_in_04"] = 1 })
	if _, err := DecodeStored(b); !hasCode(err, CodeDecode) {
		t.Errorf("a stored 0.3 end with an unknown field: %v", err)
	}
}

// fieldIndex finds the Flow field whose JSON name is name.
func fieldIndex(t *testing.T, name string) []int {
	t.Helper()
	ft := reflect.TypeFor[Flow]()
	for i := range ft.NumField() {
		if tag, _, _ := strings.Cut(ft.Field(i).Tag.Get("json"), ","); tag == name {
			return []int{i}
		}
	}
	t.Fatalf("no field %s", name)
	return nil
}

// The type's half of N-8's leg (2): absent, 0 and false stay apart through
// a decode into Observation and an encode back, which is what the node's
// tie path does. D5's leg runs the same through Link.record.
func TestEnd03AbsentZeroFalseKept(t *testing.T) {
	keys := []string{"orig_payload", "resp_payload", "orig_pkts", "resp_pkts", "to_device_overlap_octets", "rexmit_inconsistent", "password_lines"}
	// Each case edits the record as JSON, so the input does not come from
	// the type under test.
	cases := []func(f map[string]any){
		func(f map[string]any) {}, // every count present, none incomplete
		func(f map[string]any) { // every count 0
			for _, k := range keys {
				f[k] = 0
			}
		},
		func(f map[string]any) {
			delete(f, "to_device_overlap_octets")
			delete(f, "password_lines")
			f["incomplete"] = true
		},
		func(f map[string]any) { f["incomplete"] = false }, // refused by the reader, but kept by the type
		func(f map[string]any) { // every count absent
			for _, k := range keys {
				delete(f, k)
			}
		},
	}
	for i, mut := range cases {
		in := encodeWith(t, asStored(fxEnd03("tcp")), func(m map[string]any) { mut(m["flow"].(map[string]any)) })
		var back Observation
		if err := json.Unmarshal(in, &back); err != nil {
			t.Fatal(err)
		}
		out := mustJSON(t, &back)
		var a, b map[string]any
		_ = json.Unmarshal(in, &a)
		_ = json.Unmarshal(out, &b)
		if !reflect.DeepEqual(a["flow"], b["flow"]) {
			t.Errorf("case %d: flow %v re-encoded as %v", i, a["flow"], b["flow"])
		}
	}
}

// CH-36 for 0.3: a hello of either known minor opens a connection, and a
// frame of another minor than the connection's is refused as schema. The
// node's two messages keep 0.2's identifier (link.go, NodeHello.Validate).
func TestChannel03Minor(t *testing.T) {
	h3 := fxSensorHello()
	h3.Schema = Identifier03
	for _, h := range []*SensorHello{fxSensorHello(), h3} {
		m, err := DecodeFromSensor(mustJSON(t, h))
		if err != nil || m.Hello == nil {
			t.Errorf("a %s hello: %v", h.Schema, err)
		}
	}
	for _, s := range []string{Identifier, "otsec.netobs/0.4"} {
		h := fxSensorHello()
		h.Schema = s
		if _, err := DecodeFromSensor(mustJSON(t, h)); !hasCode(err, CodeSchema) {
			t.Errorf("a %s hello: %v", s, err)
		}
		if err := h.Validate(); !hasCode(err, CodeSchema) {
			t.Errorf("a %s hello's Validate: %v", s, err)
		}
	}
	k3 := fxTick()
	k3.Schema = Identifier03
	cases := []struct {
		name string
		v    any
		conn string
		ok   bool
	}{
		{"0.3 end on 0.3", fxEnd03("tcp"), Identifier03, true},
		{"0.3 heartbeat on 0.3", fxHeartbeat03(), Identifier03, true},
		{"0.3 tick on 0.3", k3, Identifier03, true},
		{"0.2 end on 0.2", clear03(fxEnd03("tcp"), Identifier02), Identifier02, true},
		{"0.2 heartbeat on 0.2", fxHeartbeat02(), Identifier02, true},
		{"0.2 tick on 0.2", fxTick(), Identifier02, true},
		{"0.3 end on 0.2", fxEnd03("tcp"), Identifier02, false},
		{"0.3 heartbeat on 0.2", fxHeartbeat03(), Identifier02, false},
		{"0.2 end on 0.3", clear03(fxEnd03("tcp"), Identifier02), Identifier03, false},
		{"0.2 tick on 0.3", fxTick(), Identifier03, false},
		{"0.2 hello on 0.3", fxSensorHello(), Identifier03, false},
	}
	for _, tc := range cases {
		_, err := DecodeFromSensorIn(mustJSON(t, tc.v), tc.conn)
		if tc.ok != (err == nil) || (!tc.ok && !hasCode(err, CodeSchema)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	nh := fxNodeHello()
	nh.Schema = Identifier03
	if m, err := DecodeFromNode(mustJSON(t, nh)); err == nil || m.Close != CloseNodeHello {
		t.Errorf("a node-hello at 0.3: %+v, %v", m, err)
	}
}

// CH-53's three counts in the heartbeat: required at 0.3, refused below,
// never falling within a run, and never in counters (N-9's contract leg).
func TestHeartbeat03(t *testing.T) {
	if err := in03(t, fxHeartbeat03()); err != nil {
		t.Fatalf("a 0.3 heartbeat: %v", err)
	}
	bad := []struct {
		name  string
		mut   func(h *Heartbeat)
		field string
	}{
		{"no frame_stage", func(h *Heartbeat) { h.FrameStage = nil }, "frame_stage"},
		{"no overlap_table_full", func(h *Heartbeat) { h.FrameStage.OverlapTableFull = nil }, "frame_stage.overlap_table_full"},
		{"no overlap_join_refused", func(h *Heartbeat) { h.Agent.OverlapJoinRefused = nil }, "agent.overlap_join_refused"},
		{"no overlap_unjoined", func(h *Heartbeat) { h.Agent.OverlapUnjoined = nil }, "agent.overlap_unjoined"},
	}
	for _, tc := range bad {
		h := fxHeartbeat03()
		tc.mut(h)
		if err := in03(t, h); !refusedAt(err, CodeMissing, tc.field) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	for _, tc := range []struct {
		name  string
		mut   func(h *Heartbeat)
		field string
	}{
		{"frame_stage", func(h *Heartbeat) { h.FrameStage = &FrameStage{OverlapTableFull: ptr(uint64(0))} }, "frame_stage"},
		{"overlap_join_refused", func(h *Heartbeat) { h.Agent.OverlapJoinRefused = ptr(uint64(0)) }, "agent.overlap_join_refused"},
		{"overlap_unjoined", func(h *Heartbeat) { h.Agent.OverlapUnjoined = ptr(uint64(0)) }, "agent.overlap_unjoined"},
	} {
		h := fxHeartbeat02()
		tc.mut(h)
		if _, err := DecodeFromSensorIn(mustJSON(t, h), Identifier02); !refusedAt(err, CodeDecode, tc.field) {
			t.Errorf("%s at 0.2: %v", tc.name, err)
		}
	}
	// Follows: each count may stay or rise, and never fall by one.
	prev := fxHeartbeat03()
	*prev.FrameStage.OverlapTableFull, *prev.Agent.OverlapJoinRefused, *prev.Agent.OverlapUnjoined = 5, 5, 5
	same := fxHeartbeat03()
	same.Seq = "45"
	*same.FrameStage.OverlapTableFull, *same.Agent.OverlapJoinRefused, *same.Agent.OverlapUnjoined = 5, 5, 5
	if err := same.Follows(prev); err != nil {
		t.Errorf("the counts unchanged: %v", err)
	}
	for _, tc := range []struct {
		field string
		v     func(h *Heartbeat) *uint64
	}{
		{"frame_stage.overlap_table_full", func(h *Heartbeat) *uint64 { return h.FrameStage.OverlapTableFull }},
		{"agent.overlap_join_refused", func(h *Heartbeat) *uint64 { return h.Agent.OverlapJoinRefused }},
		{"agent.overlap_unjoined", func(h *Heartbeat) *uint64 { return h.Agent.OverlapUnjoined }},
	} {
		next := fxHeartbeat03()
		next.Seq = "45"
		*next.FrameStage.OverlapTableFull, *next.Agent.OverlapJoinRefused, *next.Agent.OverlapUnjoined = 5, 5, 5
		*tc.v(next) = 4
		if err := next.Follows(prev); !refusedAt(err, CodeOrder, tc.field) {
			t.Errorf("%s fell by one: %v", tc.field, err)
		}
	}
	// None of the three is a counter.
	ct := reflect.TypeFor[Counters]()
	for i := range ct.NumField() {
		tag, _, _ := strings.Cut(ct.Field(i).Tag.Get("json"), ",")
		if slices.Contains([]string{"overlap_table_full", "overlap_join_refused", "overlap_unjoined"}, tag) {
			t.Errorf("%s is in counters", tag)
		}
	}
	// A count of 0 is present, not left out; a 0.2 heartbeat built with
	// this type carries none of the three keys.
	if b := string(mustJSON(t, fxHeartbeat03())); !strings.Contains(b, `"overlap_table_full":0`) || !strings.Contains(b, `"overlap_unjoined":0`) {
		t.Errorf("a 0 count left out: %s", b)
	}
	if b := string(mustJSON(t, fxHeartbeat02())); strings.Contains(b, "overlap_") || strings.Contains(b, "frame_stage") {
		t.Errorf("a 0.2 heartbeat with a 0.3 key: %s", b)
	}
}

// CH-51: the rule token, baseline-free with no params, new in 0.3 (N-1's
// contract leg).
func TestMismatchRule(t *testing.T) {
	r := RuleOwnSessionMismatch
	if r != "own-session-mismatch" || !slices.Contains(Rules, r) || !slices.Contains(BaselineFree, r) || RuleParams(r) != nil {
		t.Fatalf("own-session-mismatch: in Rules %v, baseline-free %v, params %v", slices.Contains(Rules, r), slices.Contains(BaselineFree, r), RuleParams(r))
	}
	a := fxMismatch()
	if err := a.Validate(); err != nil {
		t.Fatalf("a 0.3 alert with no baseline: %v", err)
	}
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	back, err := AlertFromHealth(h)
	if err != nil || back.Rule != r || back.Observation != a.Observation {
		t.Errorf("read from its health body: %+v, %v", back, err)
	}
	for _, s := range []string{Identifier, Identifier02} {
		a := fxMismatch()
		a.Schema = s
		if err := a.Validate(); !refusedAt(err, CodeForm, "rule") {
			t.Errorf("at %s: %v", s, err)
		}
		h.Details["schema"] = s
		if _, err := AlertFromHealth(h); !refusedAt(err, CodeForm, "rule") {
			t.Errorf("at %s, from its health body: %v", s, err)
		}
	}
	later := fxMismatch()
	later.Schema = "otsec.netobs/0.4"
	if err := later.Validate(); err != nil {
		t.Errorf("at 0.4: %v", err)
	}
	withParam := fxMismatch()
	withParam.Params = []Param{{Name: "tie_grace_s", Value: "30"}}
	if err := withParam.Validate(); !refusedAt(err, CodeConflict, "params") {
		t.Errorf("with a param: %v", err)
	}
	notHead := fxMismatch()
	notHead.Observation = "comparison M3 M3: twice"
	if err := notHead.Validate(); !refusedAt(err, CodeForm, "observation") {
		t.Errorf("a head that breaks the grammar: %v", err)
	}
}

// longestHead is the grammar's longest head: every item of every part.
const longestHead = "comparison M1 M2 M3 M4 M5 M6a M6b unjudged M2:incomplete M3:incomplete M5:incomplete M6a:incomplete M6b:incomplete M6b:no-profile reason prp-table-full prp-mismatched no-profile"

// CH-51's head grammar, matched over the whole observation (N-2's legs (1)
// and (2), D4's own).
func TestMismatchHead(t *testing.T) {
	var accept []string
	var partStrings [][]string // each part's accepted forms
	for _, p := range mismatchParts {
		var forms []string
		if p.items == nil {
			forms = []string{p.word}
		}
		for _, it := range p.items {
			forms = append(forms, p.word+" "+it)
		}
		if len(p.items) > 1 {
			forms = append(forms, p.word+" "+strings.Join(p.items, " "))
		}
		partStrings = append(partStrings, forms)
		accept = append(accept, forms...)
	}
	for i := range partStrings {
		for j := i + 1; j < len(partStrings); j++ {
			for _, a := range partStrings[i] {
				for _, b := range partStrings[j] {
					accept = append(accept, a+" "+b)
				}
			}
		}
	}
	accept = append(accept, longestHead,
		"comparison M5 unjudged M6b:no-profile", "unjudged M5:incomplete", // D6's pair
		"comparison M3 M6b", "unjudged M5:incomplete M6b:incomplete", "comparison M5 unjudged M6b:incomplete",
		"comparison M2 reason prp-table-full", "comparison M1 M3 M5 M6a M6b unjudged M3:incomplete M5:incomplete M6a:incomplete M6b:incomplete M6b:no-profile no-profile")
	for _, h := range accept {
		for _, s := range []string{h, h + ": free text", h + ": ", h + ": a: b: c"} {
			if !validMismatchObservation(s) {
				t.Errorf("refused %q", s)
			}
		}
	}
	refuse := []string{
		"", ": free text", "free text", "comparison", "comparison M7", "comparison M6b M3", "comparison M3 M3",
		"comparison M3x", "comparison M3:", "unjudged M1:incomplete", "unjudged M5:no-profile", "unjudged M4:incomplete",
		"unjudged M3:incomplete comparison M3", "reason prp-table-full unjudged M3:incomplete",
		"no-profile reason prp-table-full", "comparison M3 comparison M5", "no-profile no-profile",
		"comparisonM3", "comparison  M3", " comparison M3", "comparison M3 ", "unjudged", "reason", "reason prp-late",
		"reason prp-mismatched prp-table-full", "no-profile M3", "comparison M3:free text", "comparison M3 :free",
		"comparison M3:incomplete", "Comparison M3", "comparison m3", "comparison M3\tunjudged M5:incomplete",
	}
	for _, s := range refuse {
		if validMismatchObservation(s) {
			t.Errorf("accepted %q", s)
		}
	}
	// The longest head is 177 octets (CH-51), so ": " and 77 octets of free
	// text fit ExplainMax, and 78 do not.
	if len(longestHead) != 177 {
		t.Errorf("longest head %d octets, the text says 177", len(longestHead))
	}
	a := fxMismatch()
	a.Observation = longestHead + ": " + strings.Repeat("x", 77)
	if err := a.Validate(); err != nil || len(a.Observation) != ExplainMax {
		t.Errorf("the longest head with 77 octets of free text, %d octets: %v", len(a.Observation), err)
	}
	a.Observation += "x"
	if err := a.Validate(); !refusedAt(err, CodeRange, "observation") {
		t.Errorf("one octet past ExplainMax: %v", err)
	}
}

// C13 0.3 §1.2: 0.3 code writes otsec.netcheckpoint/0.3, reads 0.2 and 0.1
// strictly, and a window is judged as an alert of the checkpoint's minor,
// so a 0.2 checkpoint holds no own-session-mismatch window.
func TestCheckpoint02Read(t *testing.T) {
	if CheckpointIdentifier != "otsec.netcheckpoint/0.3" || CheckpointIdentifier02 != "otsec.netcheckpoint/0.2" {
		t.Fatalf("identifiers %s %s", CheckpointIdentifier, CheckpointIdentifier02)
	}
	k := fxDetectorCheckpoint()
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeDetectorCheckpoint(b); err != nil || got.Schema != "otsec.netcheckpoint/0.3" {
		t.Fatalf("a 0.3 checkpoint: %v", err)
	}
	cv := fxCoverage02()
	k.Coverage, k.Windows[0].Coverage = &cv, cv
	k.Schema = CheckpointIdentifier02
	if b, err = k.Encode(); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDetectorCheckpoint(b); err != nil {
		t.Errorf("a 0.2 detector checkpoint: %v", err)
	}
	if _, err := DecodeDetectorCheckpoint(append(b[:len(b)-1], []byte(`,"added":1}`)...)); !hasCode(err, CodeDecode) {
		t.Errorf("a 0.2 detector checkpoint with an unknown field: %v", err)
	}
	l := fxLearnerCheckpoint(t)
	l.Schema = CheckpointIdentifier02
	if b, err = l.Encode(); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLearnerCheckpoint(b); err != nil {
		t.Errorf("a 0.2 learner checkpoint: %v", err)
	}

	m := fxMismatch()
	w := DetectorWindow{Rule: m.Rule, AssetID: m.AssetID, KeyText: m.KeyText, BaselineValue: m.BaselineValue,
		Observation: m.Observation, AtUTC: m.AtUTC, WindowStartUTC: m.WindowStartUTC, Hits: m.Hits,
		Sources: []string{"192.0.2.10", "198.51.100.7"}, Related: []uint64{7, 9, 12}, Cites: m.Cites, Coverage: cv}
	for _, tc := range []struct {
		schema string
		ok     bool
	}{{CheckpointIdentifier, true}, {CheckpointIdentifier02, false}} {
		k := fxDetectorCheckpoint()
		k.Schema, k.Coverage, k.Windows[0].Coverage = tc.schema, &cv, cv
		k.Windows = append([]DetectorWindow{w}, k.Windows...) // sorted by rule
		if err := k.Validate(); tc.ok != (err == nil) {
			t.Errorf("an own-session-mismatch window in %s: %v", tc.schema, err)
		}
	}
}
