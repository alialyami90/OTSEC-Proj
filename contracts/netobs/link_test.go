package netobs

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// C13 0.2 fixtures. Every value is illustrative: no sensor produced them.
const fxDigest = "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

func fxCoverage02() Coverage {
	cv := fxCoverage()
	cv.ConfigDigest, cv.Settings.PRPWindowMS = fxDigest, DefaultPRPWindowMS
	return cv
}

func fxObservation02() *Observation {
	o := fxFunction()
	o.Schema, o.MadeUTC, o.Coverage = Identifier02, "2026-11-07T10:00:00.200000Z", fxCoverage02()
	return o
}

func fxAgent() *Agent {
	z := func() *uint64 { return ptr(uint64(0)) }
	return &Agent{Closes: AgentCloses{Handshake: z(), NodeHello: z(), NodeHelloTimeout: z(), Binding: z(), Ack: z(),
		Type: z(), Idle: z(), FrameTooLarge: z(), Superseded: z(), RunComplete: z(), Shutdown: z()},
		TakenAhead: z(), SyncLate: z(), EntriesUnreadable: z()}
}

func fxHeartbeat02() *Heartbeat {
	h := fxHeartbeat()
	h.Schema, h.Coverage = Identifier02, fxCoverage02()
	for _, x := range []**uint64{&h.Counters.DropsHolder, &h.Counters.FramesOverlong, &h.Counters.FramesOutgoing,
		&h.Counters.PRPMismatched, &h.Counters.PRPTableFull, &h.Counters.PRPTagDiffers, &h.Counters.PRPWrongLAN,
		&h.Counters.EngineLinesRefused} {
		*x = ptr(uint64(0))
	}
	h.Interfaces = []InterfaceCount{{Name: "eth1", Carrier: "up", Packets: h.Counters.Packets}}
	h.Agent, h.EgressCheck = fxAgent(), "ok"
	return h
}

func fxSensorHello() *SensorHello {
	return &SensorHello{Schema: Identifier02, Type: TypeSensorHello, SensorID: fxSensor, Generation: "2",
		RunCounter: "5", RunID: fxRun, Current: ptr(true), FirstSeq: "101", NewestSeq: "120", DropsChannel: "0",
		Lost: []Span{}, PinnedBy: "signature", ConfigDigest: fxDigest, BufferBytes: "2147483648",
		SensorUTC: "2026-11-07T10:00:00Z"}
}

func fxPrior() *Prior {
	return &Prior{RunsSkipped: "0", RecordsLost: "0", Lost: []Span{}, PreviousEnd: "clean", StartedBy: "agent"}
}

func fxTick() *Tick {
	return &Tick{Schema: Identifier02, Type: TypeTick, SensorID: fxSensor, RunID: fxRun, SensorUTC: "2026-11-07T10:00:10Z",
		NewestSeq: "125", SentSeq: "122", DropsChannel: "0", Lost: []Span{}, BufferedRecords: "4", BufferedBytes: "4096"}
}

func fxNodeHello() *NodeHello {
	return &NodeHello{Schema: Identifier02, Type: TypeNodeHello, SensorID: fxSensor, Generation: "2",
		Taken: &Taken{RunCounter: "5", RunID: fxRun, Seq: "100"}}
}

func fxAck() *Ack {
	return &Ack{Schema: Identifier02, Type: TypeAck, RunCounter: "5", RunID: fxRun, Seq: "110"}
}

func span(from, to string) Span {
	return Span{FromUTC: "2026-11-07T09:" + from + "Z", ToUTC: "2026-11-07T09:" + to + "Z"}
}

// fromSensor decodes v's JSON, with mut applied to its decoded map first.
func encodeWith(t *testing.T, v any, mut func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustJSON(t, v), &m); err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		mut(m)
	}
	return mustJSON(t, m)
}

func hasCode(err error, code Code) bool { return slices.Contains(Codes(err), code) }

// CH-5, CH-7, CH-8, CH-21, CH-28, CH-31, CH-43: the four kinds from a
// sensor decode strictly, each 0.2 field required.
func TestDecodeFromSensor(t *testing.T) {
	for _, v := range []any{fxSensorHello(), fxTick(), fxHeartbeat02(), fxObservation02()} {
		m, err := DecodeFromSensor(mustJSON(t, v))
		if err != nil {
			t.Fatalf("%T: %v", v, err)
		}
		set := 0
		for _, p := range []bool{m.Hello != nil, m.Tick != nil, m.Heartbeat != nil, m.Observation != nil} {
			if p {
				set++
			}
		}
		if set != 1 || m.Type == "" {
			t.Errorf("%T: %d set, type %q", v, set, m.Type)
		}
	}
	h := fxSensorHello()
	h.Prior = fxPrior()
	if _, err := DecodeFromSensor(mustJSON(t, h)); err != nil {
		t.Errorf("hello with prior: %v", err)
	}
	cases := []struct {
		name string
		v    any
		mut  func(m map[string]any)
		code Code
	}{
		{"an alert", fxObservation02(), func(m map[string]any) { m["type"] = "alert" }, CodeType},
		{"a node message", fxObservation02(), func(m map[string]any) { m["type"] = TypeAck }, CodeType},
		{"a 0.1 observation", fxObservation02(), func(m map[string]any) { m["schema"] = Identifier }, CodeSchema},
		{"a 0.1 hello", fxSensorHello(), func(m map[string]any) { m["schema"] = Identifier }, CodeSchema},
		{"an unknown key", fxTick(), func(m map[string]any) { m["extra"] = "1" }, CodeDecode},
		{"no made_utc", fxObservation02(), func(m map[string]any) { delete(m, "made_utc") }, CodeMissing},
		{"made_utc not UTC", fxObservation02(), func(m map[string]any) { m["made_utc"] = "2026-11-07T10:00:00+00:00" }, CodeForm},
		{"no config_digest", fxObservation02(), func(m map[string]any) { delete(m["coverage"].(map[string]any), "config_digest") }, CodeMissing},
		{"a bad config_digest", fxHeartbeat02(), func(m map[string]any) { m["coverage"].(map[string]any)["config_digest"] = "sha256:ABC" }, CodeForm},
		{"no prp_window_ms", fxHeartbeat02(), func(m map[string]any) {
			delete(m["coverage"].(map[string]any)["settings"].(map[string]any), "prp_window_ms")
		}, CodeMissing},
		{"prp_window_ms 9", fxObservation02(), func(m map[string]any) {
			m["coverage"].(map[string]any)["settings"].(map[string]any)["prp_window_ms"] = 9
		}, CodeRange},
		{"prp_window_ms 2001", fxObservation02(), func(m map[string]any) {
			m["coverage"].(map[string]any)["settings"].(map[string]any)["prp_window_ms"] = 2001
		}, CodeRange},
		{"no drops_holder", fxHeartbeat02(), func(m map[string]any) { delete(m["counters"].(map[string]any), "drops_holder") }, CodeMissing},
		{"no engine_lines_refused", fxHeartbeat02(), func(m map[string]any) { delete(m["counters"].(map[string]any), "engine_lines_refused") }, CodeMissing},
		{"no interfaces", fxHeartbeat02(), func(m map[string]any) { delete(m, "interfaces") }, CodeMissing},
		{"no agent", fxHeartbeat02(), func(m map[string]any) { delete(m, "agent") }, CodeMissing},
		{"an agent key missing", fxHeartbeat02(), func(m map[string]any) {
			delete(m["agent"].(map[string]any)["closes"].(map[string]any), "superseded")
		}, CodeMissing},
		{"an unknown agent key", fxHeartbeat02(), func(m map[string]any) { m["agent"].(map[string]any)["closes"].(map[string]any)["other"] = 0 }, CodeDecode},
		{"egress_check unknown", fxHeartbeat02(), func(m map[string]any) { m["egress_check"] = "unknown" }, CodeForm},
		{"a carrier outside its set", fxHeartbeat02(), func(m map[string]any) { m["interfaces"].([]any)[0].(map[string]any)["carrier"] = "dormant" }, CodeForm},
		{"an interface not in the coverage", fxHeartbeat02(), func(m map[string]any) { m["interfaces"].([]any)[0].(map[string]any)["name"] = "eth2" }, CodeConflict},
		{"packets not summing", fxHeartbeat02(), func(m map[string]any) { m["interfaces"].([]any)[0].(map[string]any)["packets"] = 999 }, CodeConflict},
		{"a node object", fxObservation02(), func(m map[string]any) { m["node"] = map[string]any{} }, CodeConflict},
	}
	for _, tc := range cases {
		_, err := DecodeFromSensor(encodeWith(t, tc.v, tc.mut))
		if !hasCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	// egress_check is optional at 0.2 (CH-27).
	hb := fxHeartbeat02()
	hb.EgressCheck = ""
	if _, err := DecodeFromSensor(mustJSON(t, hb)); err != nil {
		t.Errorf("no egress_check: %v", err)
	}
	// prp_window_ms at its two ends.
	for _, ms := range []int{MinPRPWindowMS, MaxPRPWindowMS} {
		o := fxObservation02()
		o.Coverage.Settings.PRPWindowMS = ms
		if _, err := DecodeFromSensor(mustJSON(t, o)); err != nil {
			t.Errorf("prp_window_ms %d: %v", ms, err)
		}
	}
	// Two interfaces whose packets sum to the total.
	hb = fxHeartbeat02()
	hb.Coverage.Interfaces = append(hb.Coverage.Interfaces, Interface{Name: "eth2", Attachment: "tap", LAN: "b"})
	hb.Interfaces = []InterfaceCount{{Name: "eth2", Carrier: "down", Packets: 400}, {Name: "eth1", Carrier: "unknown", Packets: 600}}
	if _, err := DecodeFromSensor(mustJSON(t, hb)); err != nil {
		t.Errorf("two interfaces: %v", err)
	}
	hb.Interfaces = hb.Interfaces[:1]
	if _, err := DecodeFromSensor(mustJSON(t, hb)); !hasCode(err, CodeConflict) {
		t.Errorf("one interface of two: %v", err)
	}
}

// The 0.1 channel, main's intake reader, stays strict: a field new in 0.2
// is refused in a 0.1 record (D4-103 ruling 2).
func TestChannel01RefusesNewFields(t *testing.T) {
	o := fxFunction()
	o.MadeUTC = "2026-11-07T10:00:00Z"
	if _, err := DecodeChannel(mustJSON(t, o)); !hasCode(err, CodeDecode) {
		t.Errorf("0.1 observation with made_utc: %v", err)
	}
	o = fxFunction()
	o.Coverage.ConfigDigest = fxDigest
	if _, err := DecodeChannel(mustJSON(t, o)); !hasCode(err, CodeDecode) {
		t.Errorf("0.1 observation with config_digest: %v", err)
	}
	hb := fxHeartbeat()
	hb.Agent = fxAgent()
	if _, err := DecodeChannel(mustJSON(t, hb)); !hasCode(err, CodeDecode) {
		t.Errorf("0.1 heartbeat with agent: %v", err)
	}
	hb = fxHeartbeat()
	hb.Counters.FramesOutgoing = ptr(uint64(0))
	if _, err := DecodeChannel(mustJSON(t, hb)); !hasCode(err, CodeDecode) {
		t.Errorf("0.1 heartbeat with frames_outgoing: %v", err)
	}
	for _, v := range []any{fxFunction(), fxFlow(), fxHeartbeat()} {
		if _, err := DecodeChannel(mustJSON(t, v)); err != nil {
			t.Errorf("0.1 %T: %v", v, err)
		}
	}
	// And a 0.2 record never passes the 0.1 reader.
	if _, err := DecodeChannel(mustJSON(t, fxObservation02())); !hasCode(err, CodeSchema) {
		t.Errorf("0.2 observation on the 0.1 channel: %v", err)
	}
}

// CH-5, CH-2: the agent's reading of a frame from the node, and its close.
func TestDecodeFromNode(t *testing.T) {
	for _, v := range []any{fxNodeHello(), fxAck()} {
		if m, err := DecodeFromNode(mustJSON(t, v)); err != nil || m.Close != "" {
			t.Errorf("%T: %v %q", v, err, m.Close)
		}
	}
	nh := fxNodeHello()
	nh.Taken = nil
	if _, err := DecodeFromNode(mustJSON(t, nh)); err != nil {
		t.Errorf("node-hello without taken: %v", err)
	}
	nh.Taken = &Taken{RunCounter: "5", RunID: fxRun, Seq: "0"}
	if _, err := DecodeFromNode(mustJSON(t, nh)); err != nil {
		t.Errorf("taken seq 0: %v", err)
	}
	cases := []struct {
		name  string
		v     any
		mut   func(m map[string]any)
		close string
	}{
		{"a sensor type", fxAck(), func(m map[string]any) { m["type"] = TypeTick }, CloseType},
		{"an unknown key", fxAck(), func(m map[string]any) { m["x"] = 1 }, CloseType},
		{"an unknown key in taken", fxNodeHello(), func(m map[string]any) { m["taken"].(map[string]any)["x"] = 1 }, CloseType},
		{"a leading zero", fxAck(), func(m map[string]any) { m["seq"] = "0110" }, CloseAck},
		{"above 2^64 - 1", fxAck(), func(m map[string]any) { m["seq"] = "18446744073709551616" }, CloseAck},
		{"a run_counter of 0", fxAck(), func(m map[string]any) { m["run_counter"] = "0" }, CloseAck},
		{"a number, not a string", fxAck(), func(m map[string]any) { m["seq"] = 110 }, CloseAck},
		{"a 0.1 schema", fxNodeHello(), func(m map[string]any) { m["schema"] = Identifier }, CloseNodeHello},
		{"a generation of 0", fxNodeHello(), func(m map[string]any) { m["generation"] = "0" }, CloseNodeHello},
		{"no sensor_id", fxNodeHello(), func(m map[string]any) { delete(m, "sensor_id") }, CloseNodeHello},
	}
	for _, tc := range cases {
		m, err := DecodeFromNode(encodeWith(t, tc.v, tc.mut))
		if err == nil || m.Close != tc.close {
			t.Errorf("%s: close %q, err %v; want %s", tc.name, m.Close, err, tc.close)
		}
	}
	m, err := DecodeFromNode([]byte("{"))
	if err == nil || m.Close != CloseType {
		t.Errorf("not JSON: %q %v", m.Close, err)
	}
	// MaxNodeMessage: at the bound read, one byte over closes.
	b := encodeWith(t, fxAck(), nil)
	over := append([]byte(strings.Repeat(" ", MaxNodeMessage+1-len(b))), b...)
	if m, _ := DecodeFromNode(over); m.Close != CloseFrameTooLarge {
		t.Errorf("%d bytes: close %q", len(over), m.Close)
	}
	exact := append([]byte(strings.Repeat(" ", MaxNodeMessage-len(b))), b...)
	if _, err := DecodeFromNode(exact); err != nil {
		t.Errorf("%d bytes: %v", len(exact), err)
	}
}

// CH-13 row 1: the hello's form and range.
func TestSensorHelloForm(t *testing.T) {
	if err := fxSensorHello().Validate(); err != nil {
		t.Fatal(err)
	}
	ok := []func(h *SensorHello){
		func(h *SensorHello) { h.NewestSeq = "100" }, // first_seq - 1: nothing to send
		func(h *SensorHello) { h.BufferBytes = fmt.Sprint(MinBufferBytes) },
		func(h *SensorHello) { h.BufferBytes = fmt.Sprint(uint64(MaxBufferBytes)) },
		func(h *SensorHello) { h.Lost = []Span{span("00:00", "00:00"), span("00:01", "00:02")} },
		func(h *SensorHello) { h.PinnedBy = "console" },
	}
	for i, mut := range ok {
		h := fxSensorHello()
		mut(h)
		if err := h.Validate(); err != nil {
			t.Errorf("ok %d: %v", i, err)
		}
	}
	bad := []struct {
		name string
		mut  func(h *SensorHello)
		code Code
	}{
		{"newest_seq below first_seq - 1", func(h *SensorHello) { h.NewestSeq = "99" }, CodeRange},
		{"buffer_bytes below 16 MiB", func(h *SensorHello) { h.BufferBytes = fmt.Sprint(MinBufferBytes - 1) }, CodeRange},
		{"buffer_bytes above 64 GiB", func(h *SensorHello) { h.BufferBytes = fmt.Sprint(uint64(MaxBufferBytes) + 1) }, CodeRange},
		{"no current", func(h *SensorHello) { h.Current = nil }, CodeMissing},
		{"no lost", func(h *SensorHello) { h.Lost = nil }, CodeMissing},
		{"first_seq 0", func(h *SensorHello) { h.FirstSeq = "0" }, CodeForm},
		{"a span from after to", func(h *SensorHello) { h.Lost = []Span{span("00:02", "00:01")} }, CodeOrder},
		{"spans touching", func(h *SensorHello) { h.Lost = []Span{span("00:00", "00:01"), span("00:01", "00:02")} }, CodeOrder},
		{"spans newest first", func(h *SensorHello) { h.Lost = []Span{span("00:05", "00:06"), span("00:01", "00:02")} }, CodeOrder},
		{"nine spans", func(h *SensorHello) {
			for i := range 9 {
				h.Lost = append(h.Lost, span(fmt.Sprintf("%02d:00", i), fmt.Sprintf("%02d:30", i)))
			}
		}, CodeRange},
		{"a span not UTC", func(h *SensorHello) { h.Lost = []Span{{FromUTC: "2026-11-07T09:00:00", ToUTC: "2026-11-07T09:00:00Z"}} }, CodeForm},
		{"pinned_by other", func(h *SensorHello) { h.PinnedBy = "pin" }, CodeForm},
		{"a bad digest", func(h *SensorHello) { h.ConfigDigest = fxDigest[7:] }, CodeForm},
		{"previous_end other", func(h *SensorHello) { h.Prior = fxPrior(); h.Prior.PreviousEnd = "crash" }, CodeForm},
		{"started_by other", func(h *SensorHello) { h.Prior = fxPrior(); h.Prior.StartedBy = "node" }, CodeForm},
		{"prior without lost", func(h *SensorHello) { h.Prior = fxPrior(); h.Prior.Lost = nil }, CodeMissing},
	}
	for _, tc := range bad {
		h := fxSensorHello()
		tc.mut(h)
		if err := h.Validate(); !hasCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	// Eight spans are the bound.
	h := fxSensorHello()
	for i := range MaxLostSpans {
		h.Lost = append(h.Lost, span(fmt.Sprintf("%02d:00", i), fmt.Sprintf("%02d:30", i)))
	}
	if err := h.Validate(); err != nil {
		t.Errorf("eight spans: %v", err)
	}
}

// fxHelloState holds run 5 of fxSensorHello, taken to 100, with D 0.
func fxHelloState() HelloState {
	return HelloState{SensorID: fxSensor, Generation: 2, Began: 1, PinnedBy: "signature", ConfigDigest: fxDigest,
		Position: &Position{Generation: 2, RunCounter: 5, RunID: fxRun, Taken: 100}}
}

// CH-13: every row, in order, with its boundaries (H-1, H-2).
func TestJudgeHello(t *testing.T) {
	newRun := func(h *SensorHello) { h.RunCounter, h.RunID, h.Prior = "6", fxInv(9), fxPrior() }
	cases := []struct {
		name   string
		state  func(s *HelloState)
		hello  func(h *SensorHello)
		close  string
		accept string
	}{
		{"a resume", nil, nil, "", HelloResume},
		{"another sensor_id", nil, func(h *SensorHello) { h.SensorID = fxAsset }, CloseBinding, ""},
		{"another generation", nil, func(h *SensorHello) { h.Generation = "3" }, CloseBinding, ""},
		{"a counter below", nil, func(h *SensorHello) { h.RunCounter = "4" }, CloseRunRegressed, ""},
		{"a fork", nil, func(h *SensorHello) { h.RunID = fxInv(9) }, CloseRunForked, ""},
		{"a resume with prior", nil, func(h *SensorHello) { h.Prior = fxPrior() }, CloseHello, ""},
		{"drops_channel below D", func(s *HelloState) { s.Position.D = 3 }, func(h *SensorHello) { h.DropsChannel = "2" }, CloseHello, ""},
		{"drops_channel at D", func(s *HelloState) { s.Position.D = 3 }, func(h *SensorHello) { h.DropsChannel = "3" }, "", HelloResume},
		{"5a: newest below T", nil, func(h *SensorHello) { h.FirstSeq, h.NewestSeq = "99", "99" }, CloseRunRegressed, ""},
		{"5a: newest at T", nil, func(h *SensorHello) { h.FirstSeq, h.NewestSeq = "101", "100" }, "", HelloResume},
		{"5b: a renewed resume", func(s *HelloState) { s.Generation = 3 }, func(h *SensorHello) { h.Generation = "3" }, "", HelloResumeRenewed},
		{"a position of a later generation", func(s *HelloState) { s.Position.Generation = 3 }, nil, CloseHello, ""},
		{"a new run", nil, newRun, "", HelloNewRun},
		{"a new run without prior", nil, func(h *SensorHello) { h.RunCounter, h.RunID = "6", fxInv(9) }, CloseHello, ""},
		{"no position: run 1 is new", func(s *HelloState) { s.Position = nil }, func(h *SensorHello) {
			h.RunCounter, h.Prior = "1", fxPrior()
		}, "", HelloNewRun},
		{"a position read as none", func(s *HelloState) { s.Began = 3; s.Generation = 3 }, func(h *SensorHello) {
			h.Generation, h.RunCounter, h.Prior = "3", "1", fxPrior()
			h.Prior.RunsSkipped = "0"
		}, "", HelloNewRun},
		{"a position at Began reads", func(s *HelloState) { s.Began = 2 }, nil, "", HelloResume},
		{"pinned_by changed", nil, func(h *SensorHello) { h.PinnedBy = "console" }, CloseBinding, ""},
		{"pinned_by first seen", func(s *HelloState) { s.PinnedBy = "" }, func(h *SensorHello) { h.PinnedBy = "console" }, "", HelloResume},
		{"a new span with no rise", nil, func(h *SensorHello) { h.Lost = []Span{span("00:00", "00:10")} }, CloseHello, ""},
		{"a new span with a rise", nil, func(h *SensorHello) { h.Lost, h.DropsChannel = []Span{span("00:00", "00:10")}, "1" }, "", HelloResume},
		{"a held span again", func(s *HelloState) { s.Spans, s.Ds, s.Position.D = []Span{span("00:00", "00:10")}, 4, 4 }, func(h *SensorHello) {
			h.Lost, h.DropsChannel = []Span{span("00:00", "00:10")}, "4"
		}, "", HelloResume},
		{"a held span widened, D at Ds", func(s *HelloState) { s.Spans, s.Ds, s.Position.D = []Span{span("00:00", "00:10")}, 4, 4 }, func(h *SensorHello) {
			h.Lost, h.DropsChannel = []Span{span("00:00", "00:11")}, "4"
		}, CloseHello, ""},
		{"a new run's span with no rise", nil, func(h *SensorHello) { newRun(h); h.Lost = []Span{span("00:00", "00:10")} }, CloseHello, ""},
		{"prior.lost with no records lost", nil, func(h *SensorHello) { newRun(h); h.Prior.Lost = []Span{span("00:00", "00:10")} }, CloseHello, ""},
		{"prior.lost with records lost", nil, func(h *SensorHello) {
			newRun(h)
			h.Prior.Lost, h.Prior.RecordsLost = []Span{span("00:00", "00:10")}, "1"
		}, "", HelloNewRun},
	}
	for _, tc := range cases {
		s, h := fxHelloState(), fxSensorHello()
		if tc.state != nil {
			tc.state(&s)
		}
		if tc.hello != nil {
			tc.hello(h)
		}
		if err := h.Validate(); err != nil {
			t.Fatalf("%s: the hello is not valid: %v", tc.name, err)
		}
		v := JudgeHello(s, h)
		if v.Close != tc.close || v.Accept != tc.accept {
			t.Errorf("%s: close %q accept %q, want %q %q", tc.name, v.Close, v.Accept, tc.close, tc.accept)
		}
	}
	// The raises, which never close.
	s, h := fxHelloState(), fxSensorHello()
	if v := JudgeHello(s, h); v.DigestMismatch || v.BufferSmall || v.RunsUndeclared || v.SpansWidened {
		t.Errorf("a clean hello raised: %+v", v)
	}
	s.ConfigDigest = "sha256:" + hash(nil)
	if v := JudgeHello(s, h); !v.DigestMismatch || v.Close != "" {
		t.Errorf("digest: %+v", v)
	}
	s = fxHelloState()
	h.BufferBytes = fmt.Sprint(SiteBufferFloor - 1)
	if v := JudgeHello(s, h); !v.BufferSmall || v.Close != "" {
		t.Errorf("buffer below the floor: %+v", v)
	}
	h.BufferBytes = fmt.Sprint(SiteBufferFloor)
	if v := JudgeHello(s, h); v.BufferSmall {
		t.Errorf("buffer at the floor: %+v", v)
	}
	h = fxSensorHello()
	newRun(h)
	h.RunCounter, h.Prior.RunsSkipped = "8", "2" // 8 - 5 - 1
	if v := JudgeHello(s, h); v.RunsUndeclared || v.Accept != HelloNewRun {
		t.Errorf("runs_skipped agreeing: %+v", v)
	}
	for _, n := range []string{"1", "3"} {
		h.Prior.RunsSkipped = n
		if v := JudgeHello(s, h); !v.RunsUndeclared || v.Close != "" {
			t.Errorf("runs_skipped %s for 2: %+v", n, v)
		}
	}
	h = fxSensorHello()
	h.Lost, h.DropsChannel = []Span{span("00:00", "00:10")}, "1"
	if v := JudgeHello(s, h); !v.SpansWidened {
		t.Errorf("a new span: %+v", v)
	}
}

// CH-8: a tick's checks and its rate rule (T-5, S-2's tick leg).
func TestJudgeTick(t *testing.T) {
	state := func() TickState {
		return TickState{Hello: fxSensorHello(), Last: fxTick(), Since: 10 * time.Second}
	}
	cases := []struct {
		name  string
		state func(s *TickState)
		tick  func(k *Tick)
		close bool
		early bool
	}{
		{"a tick", nil, nil, false, false},
		{"the same values", nil, nil, false, false},
		{"another sensor_id", nil, func(k *Tick) { k.SensorID = fxAsset }, true, false},
		{"another run", nil, func(k *Tick) { k.RunID = fxInv(9) }, true, false},
		{"newest_seq falls", nil, func(k *Tick) { k.NewestSeq = "124" }, true, false},
		{"drops_channel falls", func(s *TickState) { s.Last.DropsChannel = "2" }, func(k *Tick) { k.DropsChannel = "1" }, true, false},
		{"sent_seq falls", nil, func(k *Tick) { k.SentSeq = "121" }, true, false},
		{"sent_seq above newest", nil, func(k *Tick) { k.SentSeq = "126" }, true, false},
		{"sent_seq at newest", nil, func(k *Tick) { k.SentSeq = "125" }, false, false},
		{"the first tick: newest below the hello's", func(s *TickState) { s.Last = nil }, func(k *Tick) { k.NewestSeq, k.SentSeq = "119", "100" }, true, false},
		{"the first tick: never early", func(s *TickState) { s.Last, s.Since = nil, 0 }, nil, false, false},
		{"early", func(s *TickState) { s.Since = TickMinSpacing - time.Nanosecond }, nil, false, true},
		{"at the spacing", func(s *TickState) { s.Since = TickMinSpacing }, nil, false, false},
		{"a new span with no rise", nil, func(k *Tick) { k.Lost = []Span{span("00:00", "00:10")} }, true, false},
		{"a new span with a rise", nil, func(k *Tick) { k.Lost, k.DropsChannel = []Span{span("00:00", "00:10")}, "1" }, false, false},
		{"a span inside a held one", func(s *TickState) { s.Spans, s.Ds = []Span{span("00:00", "00:10")}, 1; s.Last.DropsChannel = "1" }, func(k *Tick) {
			k.Lost, k.DropsChannel = []Span{span("00:02", "00:08")}, "1"
		}, false, false},
	}
	for _, tc := range cases {
		s, k := state(), fxTick()
		if tc.state != nil {
			tc.state(&s)
		}
		if tc.tick != nil {
			tc.tick(k)
		}
		v := JudgeTick(s, k)
		if (v.Close == CloseTick) != tc.close || v.Early != tc.early || (v.Close != "" && v.Close != CloseTick) {
			t.Errorf("%s: %+v, want close %v early %v", tc.name, v, tc.close, tc.early)
		}
	}
	s, k := state(), fxTick()
	k.SensorID = fxAsset
	if v := JudgeTick(s, k); !v.SensorID {
		t.Errorf("another sensor_id is not flagged: %+v", v)
	}
	k = fxTick()
	k.RunID = fxInv(9)
	if v := JudgeTick(s, k); v.SensorID {
		t.Errorf("another run is flagged as sensor-id: %+v", v)
	}
}

// CH-9 at the agent (A-1).
func TestAckValid(t *testing.T) {
	last := uint64(105)
	s := AckState{RunCounter: 5, RunID: fxRun, LastAck: &last, FirstSeq: 101, SentSeq: 110}
	cases := []struct {
		name string
		s    func(s *AckState)
		a    func(a *Ack)
		ok   bool
	}{
		{"at the highest sent", nil, nil, true},
		{"above the highest sent", nil, func(a *Ack) { a.Seq = "111" }, false},
		{"another run_id", nil, func(a *Ack) { a.RunID = fxInv(9) }, false},
		{"another counter", nil, func(a *Ack) { a.RunCounter = "6" }, false},
		{"below the last", nil, func(a *Ack) { a.Seq = "104" }, false},
		{"equal to the last", nil, func(a *Ack) { a.Seq = "105" }, true},
		{"first_seq - 1 with nothing sent", func(s *AckState) { s.LastAck, s.SentSeq = nil, 0 }, func(a *Ack) { a.Seq = "100" }, true},
		{"first_seq with nothing sent", func(s *AckState) { s.LastAck, s.SentSeq = nil, 0 }, func(a *Ack) { a.Seq = "101" }, false},
	}
	for _, tc := range cases {
		st, a := s, fxAck()
		if tc.s != nil {
			tc.s(&st)
		}
		if tc.a != nil {
			tc.a(a)
		}
		if AckValid(st, a) != tc.ok {
			t.Errorf("%s: got %v", tc.name, !tc.ok)
		}
	}
}

// CH-14's table (S-1).
func TestPlaceRecord(t *testing.T) {
	h := fxSensorHello()
	cases := []struct {
		name         string
		l, p         uint64
		sensor, run  string
		seq          uint64
		place        string
		wantL, wantG uint64
	}{
		{"the next", 100, 100, fxSensor, fxRun, 101, PlaceRead, 101, 0},
		{"a jump", 100, 100, fxSensor, fxRun, 104, PlaceRead, 104, 3},
		{"another run", 100, 100, fxSensor, fxInv(9), 101, PlaceRun, 100, 0},
		{"at L", 100, 90, fxSensor, fxRun, 100, PlaceSeq, 100, 0},
		{"just above P", 90, 100, fxSensor, fxRun, 101, PlaceRead, 101, 0},
		{"at P", 90, 100, fxSensor, fxRun, 100, PlaceDuplicate, 100, 0},
		{"a duplicate jump", 90, 100, fxSensor, fxRun, 95, PlaceDuplicate, 95, 0},
		{"above P after a jump", 90, 100, fxSensor, fxRun, 103, PlaceRead, 103, 2},
		{"another sensor_id takes its seq", 100, 100, fxAsset, fxRun, 101, PlaceSensorID, 101, 0},
		{"another sensor_id after a jump", 100, 100, fxAsset, fxRun, 103, PlaceSensorID, 103, 2},
		{"another sensor_id at L", 100, 100, fxAsset, fxRun, 100, PlaceSensorID, 100, 0},
	}
	for _, tc := range cases {
		got := PlaceRecord(h, tc.l, tc.p, tc.sensor, tc.run, tc.seq)
		if got != (Placement{Place: tc.place, L: tc.wantL, Gap: tc.wantG}) {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
}

// CH-26, CH-31, CH-43: the new counts never fall within a run (K-1).
func TestFollows02(t *testing.T) {
	prev := fxHeartbeat02()
	prev.Counters.FramesOutgoing = ptr(uint64(3))
	prev.Agent.Closes.Ack = ptr(uint64(2))
	next := fxHeartbeat02()
	next.Seq = "45"
	next.Counters.FramesOutgoing = ptr(uint64(3))
	next.Agent.Closes.Ack = ptr(uint64(2))
	if err := next.Follows(prev); err != nil {
		t.Fatalf("equal counts: %v", err)
	}
	cases := []struct {
		name  string
		mut   func(h *Heartbeat)
		field string
	}{
		{"frames_outgoing falls", func(h *Heartbeat) { h.Counters.FramesOutgoing = ptr(uint64(2)) }, "counters.frames_outgoing"},
		{"prp_wrong_lan falls", func(h *Heartbeat) { prev.Counters.PRPWrongLAN = ptr(uint64(1)) }, "counters.prp_wrong_lan"},
		{"an interface falls", func(h *Heartbeat) { prev.Interfaces[0].Packets++ }, "interfaces.eth1.packets"},
		{"an agent close falls", func(h *Heartbeat) { h.Agent.Closes.Ack = ptr(uint64(1)) }, "agent.closes.ack"},
		{"sync_late falls", func(h *Heartbeat) { prev.Agent.SyncLate = ptr(uint64(9)) }, "agent.sync_late"},
	}
	for _, tc := range cases {
		saved := *prev
		savedAgent, savedIfs, savedCounters := *prev.Agent, slices.Clone(prev.Interfaces), prev.Counters
		h := *next
		agent := *next.Agent
		h.Agent = &agent
		tc.mut(&h)
		if err := h.Follows(prev); !refusedAt(err, CodeOrder, tc.field) {
			t.Errorf("%s: %v", tc.name, err)
		}
		*prev = saved
		*prev.Agent, prev.Interfaces, prev.Counters = savedAgent, savedIfs, savedCounters
	}
}

// CH-21, CH-23, CH-39, CH-40, CH-41: the stored observation's new fields,
// and a 0.1 stored record without them (R-2).
func TestStored02(t *testing.T) {
	s := fxStored()
	s.Schema, s.MadeUTC, s.Coverage = Identifier02, "2026-11-07T10:00:00.2Z", fxCoverage02()
	s.Node.Late, s.Node.Backlog, s.Node.Skewed = true, true, true
	for i := range MaxLostSpans {
		s.Node.Lost = append(s.Node.Lost, span(fmt.Sprintf("%02d:00", i), fmt.Sprintf("%02d:30", i)))
	}
	got, err := DecodeStored(mustJSON(t, s))
	if err != nil {
		t.Fatalf("stored 0.2: %v", err)
	}
	if !got.Node.Late || !got.Node.Backlog || !got.Node.Skewed || len(got.Node.Lost) != MaxLostSpans || got.MadeUTC == "" {
		t.Errorf("read back: %+v", got.Node)
	}
	// Each new field is optional in a stored 0.2 record.
	bare := fxStored()
	bare.Schema = Identifier02
	if _, err := DecodeStored(mustJSON(t, bare)); err != nil {
		t.Errorf("stored 0.2 without the new fields: %v", err)
	}
	if _, err := DecodeStored(mustJSON(t, fxStored())); err != nil {
		t.Errorf("stored 0.1: %v", err)
	}
	bad := []struct {
		name string
		mut  func(o *Observation)
		code Code
	}{
		{"nine lost windows", func(o *Observation) { o.Node.Lost = append(o.Node.Lost, span("09:00", "09:30")) }, CodeRange},
		{"a window from after to", func(o *Observation) { o.Node.Lost[0] = span("00:30", "00:00") }, CodeOrder},
		{"made_utc not UTC", func(o *Observation) { o.MadeUTC = "yesterday" }, CodeForm},
	}
	for _, tc := range bad {
		o := *s
		n := *s.Node
		n.Lost = slices.Clone(s.Node.Lost)
		o.Node = &n
		tc.mut(&o)
		if _, err := DecodeStored(mustJSON(t, &o)); !hasCode(err, tc.code) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// At 0.1 each new field is refused.
	for name, mut := range map[string]func(o *Observation){
		"made_utc":      func(o *Observation) { o.MadeUTC = "2026-11-07T10:00:00Z" },
		"late":          func(o *Observation) { o.Node.Late = true },
		"backlog":       func(o *Observation) { o.Node.Backlog = true },
		"skewed":        func(o *Observation) { o.Node.Skewed = true },
		"lost":          func(o *Observation) { o.Node.Lost = []Span{span("00:00", "00:01")} },
		"config_digest": func(o *Observation) { o.Coverage.ConfigDigest = fxDigest },
		"prp_window_ms": func(o *Observation) { o.Coverage.Settings.PRPWindowMS = 400 },
	} {
		o := fxStored()
		mut(o)
		if _, err := DecodeStored(mustJSON(t, o)); !hasCode(err, CodeDecode) {
			t.Errorf("0.1 with %s: %v", name, err)
		}
	}
}

// CH-47: the aggregate keys and the assets they name (T-9).
func TestAlertAggregate(t *testing.T) {
	agg := func() *Alert {
		a := fxUnseen()
		a.Schema, a.AssetID, a.Assets, a.AssetsTotal = Identifier02, AggregateClockSkew, []string{fxAsset, fxMaster}, 50
		return a
	}
	if err := agg().Validate(); err != nil {
		t.Fatal(err)
	}
	outside := agg()
	outside.Rule = RuleOwnSessionOutsideRecord
	outside.Sources, outside.Related, outside.RelatedTotal = 1, fxAlert().Related[:1], 1
	outside.Hits, outside.Capture = 1, hash(nil)
	outside.Cites = fxAlert().Cites[:1]
	if err := outside.Validate(); err != nil {
		t.Errorf("own-session-outside-record: %v", err)
	}
	eight := agg()
	eight.Assets = nil
	for i := range MaxAggregateAssets {
		eight.Assets = append(eight.Assets, fxInv(100+i))
	}
	eight.AssetsTotal = MaxAggregateAssets
	if err := eight.Validate(); err != nil {
		t.Errorf("eight assets: %v", err)
	}
	cases := []struct {
		name  string
		mut   func(a *Alert)
		code  Code
		field string
	}{
		{"under another rule", func(a *Alert) {
			b := fxAlert()
			b.Schema, b.AssetID, b.Assets, b.AssetsTotal = Identifier02, AggregateHoldTimeout, []string{fxAsset}, 1
			*a = *b
		}, CodeConflict, "asset_id"},
		{"without assets", func(a *Alert) { a.Assets, a.AssetsTotal = nil, 0 }, CodeConflict, "assets"},
		{"assets under an asset ID", func(a *Alert) { a.AssetID = fxAsset }, CodeConflict, "assets"},
		{"total under an asset ID", func(a *Alert) { a.AssetID, a.Assets = fxAsset, nil }, CodeConflict, "assets"},
		{"nine assets", func(a *Alert) {
			a.Assets, a.AssetsTotal = nil, 9
			for i := range MaxAggregateAssets + 1 {
				a.Assets = append(a.Assets, fxInv(200+i))
			}
		}, CodeConflict, "assets"},
		{"a total below the list", func(a *Alert) { a.AssetsTotal = 1 }, CodeConflict, "assets_total"},
		{"a repeat", func(a *Alert) { a.Assets = []string{fxAsset, fxAsset}; a.AssetsTotal = 2 }, CodeOrder, "assets"},
		{"not an asset ID", func(a *Alert) { a.Assets = []string{AssetUnresolved} }, CodeForm, "assets[0]"},
	}
	for _, tc := range cases {
		a := agg()
		tc.mut(a)
		if err := a.Validate(); !refusedAt(err, tc.code, tc.field) {
			t.Errorf("%s: %v, want %s at %s", tc.name, err, tc.code, tc.field)
		}
	}
	// The total at the list's length passes; the health body round-trips.
	a := agg()
	a.AssetsTotal = 2
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	if h.Details["assets"] != fxAsset+" "+fxMaster || h.Details["assets_total"] != "2" {
		t.Errorf("details: %q %q", h.Details["assets"], h.Details["assets_total"])
	}
	back, err := AlertFromHealth(h)
	if err != nil || !slices.Equal(back.Assets, a.Assets) || back.AssetsTotal != 2 {
		t.Errorf("read back: %v %+v", err, back)
	}
	delete(h.Details, "assets_total")
	if _, err := AlertFromHealth(h); !hasCode(err, CodeConflict) {
		t.Errorf("assets without assets_total: %v", err)
	}
}

// CH-35: the alert's two coverage details, optional from 0.2 and refused
// at 0.1.
func TestAlertCoverage02(t *testing.T) {
	a := fxAlert()
	a.Schema, a.Coverage = Identifier02, fxCoverage02()
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	back, err := AlertFromHealth(h)
	if err != nil || back.Coverage.ConfigDigest != fxDigest || back.Coverage.Settings.PRPWindowMS != DefaultPRPWindowMS {
		t.Fatalf("read back: %v %+v", err, back.Coverage)
	}
	// Optional: an alert from a 0.1 observation's coverage.
	b := fxAlert()
	b.Schema = Identifier02
	if _, err := b.Health(); err != nil {
		t.Errorf("0.2 alert without them: %v", err)
	}
	h.Details["schema"] = Identifier
	if _, err := AlertFromHealth(h); !hasCode(err, CodeDecode) {
		t.Errorf("0.1 alert with them: %v", err)
	}
	for k, v := range map[string]string{"coverage.config_digest": "", "coverage.settings.prp_window_ms": "0"} {
		h, _ := a.Health()
		h.Details[k] = v
		if _, err := AlertFromHealth(h); err == nil {
			t.Errorf("%s = %q accepted", k, v)
		}
	}
}

// CH-35's table, "Read": the decoders read a 0.1 checkpoint strictly,
// its coverage without the two new fields; 0.3 code writes 0.3.
func TestCheckpoint01Read(t *testing.T) {
	if CheckpointIdentifier != "otsec.netcheckpoint/0.3" {
		t.Fatalf("CheckpointIdentifier %s", CheckpointIdentifier)
	}
	k := fxDetectorCheckpoint()
	k.Schema = CheckpointIdentifier01
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDetectorCheckpoint(b); err != nil {
		t.Errorf("a 0.1 detector checkpoint: %v", err)
	}
	cv := fxCoverage02()
	k.Coverage = &cv
	if _, err := k.Encode(); !hasCode(err, CodeDecode) {
		t.Errorf("a 0.1 checkpoint with 0.2 coverage: %v", err)
	}
	k.Windows[0].Coverage = cv
	k.Schema = CheckpointIdentifier
	if _, err := k.Encode(); err != nil {
		t.Errorf("a 0.2 checkpoint with 0.2 coverage: %v", err)
	}
	k = fxDetectorCheckpoint()
	k.Schema = CheckpointIdentifier01
	k.Windows[0].Coverage = cv
	if _, err := k.Encode(); err == nil {
		t.Error("a 0.1 checkpoint with a 0.2 window coverage: accepted")
	}
	l := fxLearnerCheckpoint(t)
	l.Schema = CheckpointIdentifier01
	b, err = l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLearnerCheckpoint(b); err != nil {
		t.Errorf("a 0.1 learner checkpoint: %v", err)
	}
	for _, s := range []string{"otsec.netcheckpoint/0.4", "otsec.netcheckpoint/0.0", Identifier02} {
		k := fxDetectorCheckpoint()
		k.Schema = s
		if err := k.Validate(); !hasCode(err, CodeSchema) {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// CH-11, CH-5: the closed sets (M-1, M-8).
func TestClosedSets(t *testing.T) {
	if !slices.Equal(NodeTypes, []string{"node-hello", "ack"}) ||
		!slices.Equal(SensorTypes, []string{"sensor-hello", "tick", "heartbeat", "observation"}) {
		t.Errorf("types: %v %v", NodeTypes, SensorTypes)
	}
	if !slices.Equal(NodeCloseReasons, []string{"hello", "hello-timeout", "binding", "run-regressed", "run-forked", "run",
		"tick", "idle", "frame-too-large", "store", "position-not-saved", "second-connection", "enrolment", "shutdown", "state-unread"}) {
		t.Errorf("node reasons: %v", NodeCloseReasons)
	}
	if !slices.Equal(AgentCloseReasons, []string{"handshake", "node-hello", "node-hello-timeout", "binding", "ack", "type",
		"idle", "frame-too-large", "superseded", "run-complete", "shutdown"}) {
		t.Errorf("agent reasons: %v", AgentCloseReasons)
	}
	var names []string
	for _, x := range fxAgent().counts() {
		names = append(names, x.name)
	}
	if len(names) != 14 {
		t.Errorf("agent counts: %v", names)
	}
}
