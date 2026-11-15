package contract

// C13 otsec.netobs/0.2, the channel's four messages and its pure checks
// (P4-4-CC deliverable 2, D4-103): D6's contract tests of the rows of
// docs/phase4/D4-c13-0.2-proposal.md §15 whose "Where" names Contract,
// against DecodeFromSensor, DecodeFromNode, JudgeHello, JudgeTick, AckValid
// and PlaceRecord. Rows: M-1, M-2, M-3, M-8, H-1, H-2, H-4, H-7, G-4, S-1,
// S-2, S-5, S-9, A-1, T-1 (the messages), T-5, R-1 and R-6, each for its
// contract legs. The legs that need the node's intake, the dialer, the
// detector or the rig are owed (the brief's "Owed" table) and are named in
// the PR, not here.
//
// Every message is written here from the text (§3, §4, CH-40), not from
// contracts/netobs's tests or helpers. Ground truth: GT-HAND, from the
// approved text. Evidence class: desk.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

const (
	v2Sensor  = "5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70"
	v2Other   = "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	v2Run     = "0d1e2f30-4a5b-4c6d-8e7f-a0b1c2d3e4f5"
	v2RunB    = "6f5e4d3c-2b1a-4098-8765-43210fedcba9"
	v2Digest  = "sha256:2af06c7358938493051accf442b6f5930dde8a1838c87c7f0428564d8ae7e726"
	v2DigestB = "sha256:00000000000000000000000000000000000000000000000000000000000000ff"
	v2Max64   = "18446744073709551615" // 2^64 - 1
	v2Over64  = "18446744073709551616" // 2^64
)

type v2Msg = map[string]any

// v2Set sets the value at a dotted path, and v2Del deletes it.
func v2Set(m v2Msg, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		m = m[p].(map[string]any)
	}
	m[parts[len(parts)-1]] = v
}

func v2Del(m v2Msg, path string) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		m = m[p].(map[string]any)
	}
	delete(m, parts[len(parts)-1])
}

func v2JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// v2DupKey puts key again at the front of a JSON object, so the document
// holds it twice.
func v2DupKey(b []byte, key string, v any) []byte {
	val, _ := json.Marshal(v)
	return []byte(fmt.Sprintf(`{%q:%s,%s`, key, val, b[1:]))
}

func v2Span(from, to string) map[string]any { return map[string]any{"from_utc": from, "to_utc": to} }

// CH-6.
func v2NodeHello() v2Msg {
	return v2Msg{"schema": "otsec.netobs/0.2", "type": "node-hello", "sensor_id": v2Sensor, "generation": "2",
		"taken": map[string]any{"run_counter": "5", "run_id": v2Run, "seq": "10"}}
}

// CH-9.
func v2Ack() v2Msg {
	return v2Msg{"schema": "otsec.netobs/0.2", "type": "ack", "run_counter": "5", "run_id": v2Run, "seq": "10"}
}

// CH-7: a resume of run 5 at generation 2, the node having taken 10.
func v2SensorHello() v2Msg {
	return v2Msg{"schema": "otsec.netobs/0.2", "type": "sensor-hello", "sensor_id": v2Sensor, "generation": "2",
		"run_counter": "5", "run_id": v2Run, "current": true, "first_seq": "11", "newest_seq": "20",
		"drops_channel": "3", "lost": []any{}, "pinned_by": "signature", "config_digest": v2Digest,
		"buffer_bytes": "2147483648", "sensor_utc": "2026-11-15T10:00:00Z"}
}

func v2Prior(skipped string) map[string]any {
	return map[string]any{"runs_skipped": skipped, "records_lost": "0", "lost": []any{},
		"previous_end": "clean", "started_by": "agent"}
}

// CH-8.
func v2Tick() v2Msg {
	return v2Msg{"schema": "otsec.netobs/0.2", "type": "tick", "sensor_id": v2Sensor, "run_id": v2Run,
		"sensor_utc": "2026-11-15T10:00:01Z", "newest_seq": "20", "sent_seq": "15", "drops_channel": "3",
		"lost": []any{}, "buffered_records": "0", "buffered_bytes": "0"}
}

func v2Hello(t *testing.T, m v2Msg) *netobs.SensorHello {
	t.Helper()
	f, err := netobs.DecodeFromSensor(v2JSON(t, m))
	if err != nil || f.Hello == nil {
		t.Fatalf("a valid sensor-hello: %v", err)
	}
	return f.Hello
}

func v2TickOf(t *testing.T, m v2Msg) *netobs.Tick {
	t.Helper()
	f, err := netobs.DecodeFromSensor(v2JSON(t, m))
	if err != nil || f.Tick == nil {
		t.Fatalf("a valid tick: %v", err)
	}
	return f.Tick
}

// v2State is what the node holds for the base hello: live generation 2,
// the position begun at 1, run 5 saved under generation 2 with T 10 and D
// 3, signature kept as the generation's pinned_by.
func v2State() netobs.HelloState {
	return netobs.HelloState{SensorID: v2Sensor, Generation: 2, Began: 1,
		Position: &netobs.Position{Generation: 2, RunCounter: 5, RunID: v2Run, Taken: 10, D: 3},
		PinnedBy: "signature", ConfigDigest: v2Digest}
}

// M-1 (CH-5, CH-11): each direction's closed set.
func TestC13v02M1ClosedSets(t *testing.T) {
	sorted := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }
	if got := sorted(netobs.NodeTypes); !slices.Equal(got, []string{"ack", "node-hello"}) {
		t.Errorf("NodeTypes %v, CH-5 lists node-hello and ack", got)
	}
	if got := sorted(netobs.SensorTypes); !slices.Equal(got, []string{"heartbeat", "observation", "sensor-hello", "tick"}) {
		t.Errorf("SensorTypes %v, CH-5 lists sensor-hello, tick, heartbeat and observation", got)
	}
	// From the node: any other type closes the agent's connection (type).
	for _, typ := range []string{"tick", "sensor-hello", "heartbeat", "observation", "netobs.alert", "", "Ack", "NODE-HELLO"} {
		m := v2Ack()
		m["type"] = typ
		f, err := netobs.DecodeFromNode(v2JSON(t, m))
		if err == nil || f == nil || f.Close != netobs.CloseType || f.Hello != nil || f.Ack != nil {
			t.Errorf("type %q from the node: %+v, %v; want a close as type", typ, f, err)
		}
	}
	// From the sensor: an unknown type is one record refused (type); the
	// decoder hands back no message, so the node keeps the connection.
	alert := v2Msg{"schema": "otsec.netobs/0.2", "type": "netobs.alert", "rule": "node-address-spoofed",
		"asset_id": "3f2a1b0c-9d8e-4f7a-a6b5-c4d3e2f1a0b9"}
	for _, m := range []v2Msg{v2NodeHello(), v2Ack(), alert, {"schema": "otsec.netobs/0.2", "type": "Tick"}, {"schema": "otsec.netobs/0.2", "type": ""}} {
		f, err := netobs.DecodeFromSensor(v2JSON(t, m))
		if !slices.Equal(netobs.Codes(err), []netobs.Code{netobs.CodeType}) || f.Hello != nil || f.Tick != nil || f.Heartbeat != nil || f.Observation != nil {
			t.Errorf("type %q from the sensor: %v, want only %s", m["type"], err, netobs.CodeType)
		}
	}
}

// M-2 (CH-2): the node's frames are capped at 1 KiB, the sensor's at 64 KiB.
func TestC13v02M2FrameCaps(t *testing.T) {
	if netobs.MaxNodeMessage != 1024 || netobs.MaxChannelFrame != 64<<10 {
		t.Fatalf("MaxNodeMessage %d, MaxChannelFrame %d: CH-2 states 1 KiB and 64 KiB", netobs.MaxNodeMessage, netobs.MaxChannelFrame)
	}
	pad := func(b []byte, n int) []byte { // JSON whitespace before the closing brace
		return append(append(bytes.Clone(b[:len(b)-1]), bytes.Repeat([]byte(" "), n-len(b))...), '}')
	}
	node := v2JSON(t, v2NodeHello())
	if f, err := netobs.DecodeFromNode(pad(node, 1024)); err != nil || f.Hello == nil {
		t.Errorf("a node-hello of exactly 1 KiB: %v", err)
	}
	if f, err := netobs.DecodeFromNode(pad(node, 1025)); err == nil || f.Close != netobs.CloseFrameTooLarge {
		t.Errorf("a node frame of 1 KiB + 1: %+v, %v; want frame-too-large", f, err)
	}
	if f, _ := netobs.DecodeFromNode(bytes.Repeat([]byte("x"), 1025)); f.Close != netobs.CloseFrameTooLarge {
		t.Errorf("1 KiB + 1 of garbage: %q, want frame-too-large before any decode", f.Close)
	}
	tick := v2JSON(t, v2Tick())
	if f, err := netobs.DecodeFromSensor(pad(tick, 64<<10)); err != nil || f.Tick == nil {
		t.Errorf("a tick of exactly 64 KiB: %v", err)
	}
	// The node's close point is ReadFrame (CH-2: "a 4-byte big-endian
	// length, then one JSON document"): a length of 64 KiB is read, and 64
	// KiB + 1 is ErrFrameTooLarge (frame-too-large), with its whole body
	// there to be read.
	frame := func(body []byte) io.Reader {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
		return io.MultiReader(bytes.NewReader(hdr[:]), bytes.NewReader(body))
	}
	if b, err := netobs.ReadFrame(frame(pad(tick, 64<<10))); err != nil || len(b) != 64<<10 {
		t.Errorf("ReadFrame, a length of 64 KiB: %d bytes, %v", len(b), err)
	}
	if b, err := netobs.ReadFrame(frame(pad(tick, 64<<10+1))); !errors.Is(err, netobs.ErrFrameTooLarge) {
		t.Errorf("ReadFrame, a length of 64 KiB + 1: %d bytes, %v; want ErrFrameTooLarge", len(b), err)
	}
	var w bytes.Buffer
	if err := netobs.WriteFrame(&w, pad(tick, 64<<10+1)); err != netobs.ErrFrameTooLarge {
		t.Errorf("framing a sensor frame of 64 KiB + 1: %v", err)
	}
	// "The node's two messages are under 300 bytes" (CH-2), at their
	// largest numbers.
	big := v2NodeHello()
	big["generation"] = v2Max64
	v2Set(big, "taken.run_counter", v2Max64)
	v2Set(big, "taken.seq", v2Max64)
	ack := v2Ack()
	ack["run_counter"], ack["seq"] = v2Max64, v2Max64
	for name, m := range map[string]v2Msg{"node-hello": big, "ack": ack} {
		b := v2JSON(t, m)
		if f, err := netobs.DecodeFromNode(b); err != nil || f.Close != "" {
			t.Errorf("the largest %s: %v", name, err)
		}
		if len(b) >= 300 {
			t.Errorf("the largest %s is %d bytes, CH-2 says under 300", name, len(b))
		}
		t.Logf("the largest %s: %d bytes", name, len(b))
	}
}

// M-3 (CH-5, CH-6, CH-7, CH-10): strict decoding of each message, at each
// end, with its reason. At the agent: a field not listed, or a type outside
// the set, closes as type; any other strict-decode failure of a known type
// closes as that type (node-hello, ack). At the node: a sensor-hello or a
// tick that fails is reported as that type, so the node closes hello or
// tick (CH-8: "A tick that fails its strict decode also closes as tick").
func TestC13v02M3StrictDecode(t *testing.T) {
	type nodeCase struct {
		name string
		b    []byte
		want string // the agent's close reason
	}
	nh := func(f func(v2Msg)) []byte { m := v2NodeHello(); f(m); return v2JSON(t, m) }
	ak := func(f func(v2Msg)) []byte { m := v2Ack(); f(m); return v2JSON(t, m) }
	cases := []nodeCase{
		{"node-hello, a field not listed", nh(func(m v2Msg) { m["extra"] = "1" }), netobs.CloseType},
		{"node-hello, a field not listed in taken", nh(func(m v2Msg) { v2Set(m, "taken.extra", "1") }), netobs.CloseType},
		{"node-hello, a key in another case", nh(func(m v2Msg) { m["Generation"] = m["generation"]; delete(m, "generation") }), netobs.CloseType},
		{"node-hello, a duplicate key", v2DupKey(v2JSON(t, v2NodeHello()), "sensor_id", v2Sensor), netobs.CloseNodeHello},
		{"node-hello, missing sensor_id", nh(func(m v2Msg) { delete(m, "sensor_id") }), netobs.CloseNodeHello},
		{"node-hello, missing taken.seq", nh(func(m v2Msg) { v2Del(m, "taken.seq") }), netobs.CloseNodeHello},
		{"node-hello, a 0.1 schema", nh(func(m v2Msg) { m["schema"] = "otsec.netobs/0.1" }), netobs.CloseNodeHello},
		{"node-hello, generation 0", nh(func(m v2Msg) { m["generation"] = "0" }), netobs.CloseNodeHello},
		{"node-hello, generation with a leading zero", nh(func(m v2Msg) { m["generation"] = "02" }), netobs.CloseNodeHello},
		{"node-hello, generation above 2^64 - 1", nh(func(m v2Msg) { m["generation"] = v2Over64 }), netobs.CloseNodeHello},
		{"node-hello, generation a JSON number", nh(func(m v2Msg) { m["generation"] = 2 }), netobs.CloseNodeHello},
		{"node-hello, taken.seq with a leading zero", nh(func(m v2Msg) { v2Set(m, "taken.seq", "010") }), netobs.CloseNodeHello},
		{"node-hello, taken.seq 00", nh(func(m v2Msg) { v2Set(m, "taken.seq", "00") }), netobs.CloseNodeHello},
		{"node-hello, an upper-case sensor_id", nh(func(m v2Msg) { m["sensor_id"] = strings.ToUpper(v2Sensor) }), netobs.CloseNodeHello},
		{"ack, a field not listed", ak(func(m v2Msg) { m["taken"] = "1" }), netobs.CloseType},
		{"ack, a duplicate key", v2DupKey(v2JSON(t, v2Ack()), "seq", "10"), netobs.CloseAck},
		{"ack, missing run_id", ak(func(m v2Msg) { delete(m, "run_id") }), netobs.CloseAck},
		{"ack, a 0.1 schema", ak(func(m v2Msg) { m["schema"] = "otsec.netobs/0.1" }), netobs.CloseAck},
		{"ack, seq with a leading zero", ak(func(m v2Msg) { m["seq"] = "007" }), netobs.CloseAck},
		{"ack, run_counter 0", ak(func(m v2Msg) { m["run_counter"] = "0" }), netobs.CloseAck},
		{"ack, seq above 2^64 - 1", ak(func(m v2Msg) { m["seq"] = v2Over64 }), netobs.CloseAck},
		{"a duplicate type", v2DupKey(v2JSON(t, v2Ack()), "type", "node-hello"), netobs.CloseType},
		{"not an object", []byte(`["node-hello"]`), netobs.CloseType},
	}
	for _, c := range cases {
		f, err := netobs.DecodeFromNode(c.b)
		if err == nil || f == nil || f.Close != c.want {
			got := ""
			if f != nil {
				got = f.Close
			}
			t.Errorf("%s: close %q (%v), want %q", c.name, got, err, c.want)
		}
	}
	// The forms that pass: taken absent, taken.seq 0, and 2^64 - 1.
	for name, b := range map[string][]byte{
		"taken absent":        nh(func(m v2Msg) { delete(m, "taken") }),
		"taken.seq 0":         nh(func(m v2Msg) { v2Set(m, "taken.seq", "0") }),
		"generation 2^64 - 1": nh(func(m v2Msg) { m["generation"] = v2Max64 }),
		"ack of seq 0":        ak(func(m v2Msg) { m["seq"] = "0" }),
	} {
		if f, err := netobs.DecodeFromNode(b); err != nil || f.Close != "" {
			t.Errorf("%s: %v", name, err)
		}
	}

	// At the node.
	type sensorCase struct {
		name, typ string
		b         []byte
	}
	sh := func(f func(v2Msg)) []byte { m := v2SensorHello(); f(m); return v2JSON(t, m) }
	tk := func(f func(v2Msg)) []byte { m := v2Tick(); f(m); return v2JSON(t, m) }
	scases := []sensorCase{
		{"sensor-hello, a field not listed", "sensor-hello", sh(func(m v2Msg) { m["oldest_seq"] = "1" })},
		{"sensor-hello, a duplicate key", "sensor-hello", v2DupKey(v2JSON(t, v2SensorHello()), "run_counter", "5")},
		{"sensor-hello, missing current", "sensor-hello", sh(func(m v2Msg) { delete(m, "current") })},
		{"sensor-hello, missing lost", "sensor-hello", sh(func(m v2Msg) { delete(m, "lost") })},
		{"sensor-hello, a 0.1 schema", "sensor-hello", sh(func(m v2Msg) { m["schema"] = "otsec.netobs/0.1" })},
		{"sensor-hello, first_seq 0", "sensor-hello", sh(func(m v2Msg) { m["first_seq"] = "0" })},
		{"sensor-hello, newest_seq with a leading zero", "sensor-hello", sh(func(m v2Msg) { m["newest_seq"] = "020" })},
		{"sensor-hello, drops_channel above 2^64 - 1", "sensor-hello", sh(func(m v2Msg) { m["drops_channel"] = v2Over64 })},
		{"sensor-hello, run_counter a JSON number", "sensor-hello", sh(func(m v2Msg) { m["run_counter"] = 5 })},
		{"sensor-hello, prior.records_lost 01", "sensor-hello", sh(func(m v2Msg) { m["run_counter"] = "6"; m["prior"] = v2Prior("0"); v2Set(m, "prior.records_lost", "01") })},
		{"tick, a field not listed", "tick", tk(func(m v2Msg) { m["seq"] = "1" })},
		{"tick, a duplicate key", "tick", v2DupKey(v2JSON(t, v2Tick()), "sent_seq", "15")},
		{"tick, missing sent_seq", "tick", tk(func(m v2Msg) { delete(m, "sent_seq") })},
		{"tick, sent_seq with a leading zero", "tick", tk(func(m v2Msg) { m["sent_seq"] = "015" })},
		{"tick, buffered_bytes above 2^64 - 1", "tick", tk(func(m v2Msg) { m["buffered_bytes"] = v2Over64 })},
	}
	for _, c := range scases {
		f, err := netobs.DecodeFromSensor(c.b)
		if err == nil || f == nil || f.Type != c.typ {
			got := ""
			if f != nil {
				got = f.Type
			}
			t.Errorf("%s: type %q (%v), want a refusal reported as %s", c.name, got, err, c.typ)
		}
	}
	// The forms that pass.
	for name, b := range map[string][]byte{
		"a resume":                      sh(func(v2Msg) {}),
		"newest_seq first_seq - 1":      sh(func(m v2Msg) { m["newest_seq"] = "10" }),
		"drops_channel 2^64 - 1":        sh(func(m v2Msg) { m["drops_channel"] = v2Max64 }),
		"a new run":                     sh(func(m v2Msg) { m["run_counter"] = "6"; m["prior"] = v2Prior("0") }),
		"current false":                 sh(func(m v2Msg) { m["current"] = false }),
		"pinned_by console":             sh(func(m v2Msg) { m["pinned_by"] = "console" }),
		"a tick":                        tk(func(v2Msg) {}),
		"a tick with sent_seq 0":        tk(func(m v2Msg) { m["sent_seq"] = "0" }),
		"a tick with buffered 2^64 - 1": tk(func(m v2Msg) { m["buffered_records"], m["buffered_bytes"] = v2Max64, v2Max64 }),
		"started_by enrolment, unclean": sh(func(m v2Msg) {
			m["run_counter"] = "6"
			m["prior"] = v2Prior("0")
			v2Set(m, "prior.started_by", "enrolment")
			v2Set(m, "prior.previous_end", "unclean")
		}),
		"started_by capture": sh(func(m v2Msg) {
			m["run_counter"] = "6"
			m["prior"] = v2Prior("0")
			v2Set(m, "prior.started_by", "capture")
		}),
		"started_by engine, runs_skipped 3": sh(func(m v2Msg) {
			m["run_counter"] = "6"
			m["prior"] = v2Prior("3")
			v2Set(m, "prior.started_by", "engine")
		}),
	} {
		if _, err := netobs.DecodeFromSensor(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// CH-13 row 1's form and range checks on a sensor-hello, each a close as
// hello (H-1's first row; CH-7, CH-20, CH-33, CH-40, CH-42).
func TestC13v02H1Row1Form(t *testing.T) {
	sh := func(f func(v2Msg)) []byte { m := v2SensorHello(); f(m); return v2JSON(t, m) }
	newRun := func(m v2Msg) { m["run_counter"] = "6"; m["prior"] = v2Prior("0") }
	refused := map[string][]byte{
		"buffer_bytes 16 MiB - 1":      sh(func(m v2Msg) { m["buffer_bytes"] = fmt.Sprint(16<<20 - 1) }),
		"buffer_bytes 64 GiB + 1":      sh(func(m v2Msg) { m["buffer_bytes"] = fmt.Sprint(64<<30 + 1) }),
		"newest_seq first_seq - 2":     sh(func(m v2Msg) { m["newest_seq"] = "9" }),
		"pinned_by outside its set":    sh(func(m v2Msg) { m["pinned_by"] = "installer" }),
		"previous_end outside its set": sh(func(m v2Msg) { newRun(m); v2Set(m, "prior.previous_end", "crashed") }),
		"started_by outside its set":   sh(func(m v2Msg) { newRun(m); v2Set(m, "prior.started_by", "frame-stage") }),
		"config_digest upper-case hex": sh(func(m v2Msg) { m["config_digest"] = strings.ToUpper(v2Digest[:7]) + strings.ToUpper(v2Digest[7:]) }),
		"config_digest short":          sh(func(m v2Msg) { m["config_digest"] = v2Digest[:70] }),
		"a span from after to":         sh(func(m v2Msg) { m["lost"] = []any{v2Span("2026-11-15T09:00:01Z", "2026-11-15T09:00:00Z")} }),
		"a prior span from after to": sh(func(m v2Msg) {
			newRun(m)
			v2Set(m, "prior.lost", []any{v2Span("2026-11-15T09:00:01Z", "2026-11-15T09:00:00Z")})
		}),
		"spans out of order": sh(func(m v2Msg) {
			m["lost"] = []any{v2Span("2026-11-15T09:10:00Z", "2026-11-15T09:11:00Z"), v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:01:00Z")}
		}),
		"spans that overlap": sh(func(m v2Msg) {
			m["lost"] = []any{v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:02:00Z"), v2Span("2026-11-15T09:01:00Z", "2026-11-15T09:03:00Z")}
		}),
		// D4's reading of "disjoint": two spans that share an instant are
		// not disjoint (CH-40).
		"spans that touch": sh(func(m v2Msg) {
			m["lost"] = []any{v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:01:00Z"), v2Span("2026-11-15T09:01:00Z", "2026-11-15T09:02:00Z")}
		}),
		"nine spans": sh(func(m v2Msg) {
			var l []any
			for i := range 9 {
				l = append(l, v2Span(fmt.Sprintf("2026-11-15T09:%02d:00Z", 2*i), fmt.Sprintf("2026-11-15T09:%02d:30Z", 2*i)))
			}
			m["lost"] = l
		}),
		"a span not in UTC": sh(func(m v2Msg) { m["lost"] = []any{v2Span("2026-11-15T09:00:00+00:00", "2026-11-15T09:01:00Z")} }),
	}
	for name, b := range refused {
		f, err := netobs.DecodeFromSensor(b)
		if err == nil || f.Type != netobs.TypeSensorHello {
			t.Errorf("%s: %v, want the hello refused (the node closes hello)", name, err)
		}
	}
	accepted := map[string][]byte{
		"buffer_bytes 16 MiB": sh(func(m v2Msg) { m["buffer_bytes"] = fmt.Sprint(16 << 20) }),
		"buffer_bytes 64 GiB": sh(func(m v2Msg) { m["buffer_bytes"] = fmt.Sprint(64 << 30) }),
		"spans 1 ns apart": sh(func(m v2Msg) {
			m["lost"] = []any{v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:01:00Z"), v2Span("2026-11-15T09:01:00.000000001Z", "2026-11-15T09:02:00Z")}
		}),
		"eight spans": sh(func(m v2Msg) {
			var l []any
			for i := range 8 {
				l = append(l, v2Span(fmt.Sprintf("2026-11-15T09:%02d:00Z", 2*i), fmt.Sprintf("2026-11-15T09:%02d:30Z", 2*i)))
			}
			m["lost"] = l
		}),
		"a span of one instant": sh(func(m v2Msg) { m["lost"] = []any{v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:00:00Z")} }),
	}
	for name, b := range accepted {
		if _, err := netobs.DecodeFromSensor(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// H-1 (CH-13): every row in order, the first failure deciding; with H-7's
// and H-4's contract legs (rows 5b and 5a) and G-4's (row 7, CH-33). The
// order is CH-13 as amended by D1's ruling on finding A (option 2 with
// N1-b, D4-106): rows 1 to 4, then row 7, then row 5 with 5a first, or row
// 6, then rows 8 and 9.
func TestC13v02H1HelloRows(t *testing.T) {
	type tc struct {
		name   string
		hello  func(v2Msg)
		state  func(*netobs.HelloState)
		close  string
		accept string
	}
	cases := []tc{
		{"row 2: another sensor_id", func(m v2Msg) { m["sensor_id"] = v2Other }, nil, netobs.CloseBinding, ""},
		{"row 2: another generation", func(m v2Msg) { m["generation"] = "3" }, nil, netobs.CloseBinding, ""},
		{"row 2 before row 3", func(m v2Msg) { m["generation"] = "3"; m["run_counter"] = "4" }, nil, netobs.CloseBinding, ""},
		{"row 3: a lower run_counter", func(m v2Msg) { m["run_counter"] = "4" }, nil, netobs.CloseRunRegressed, ""},
		{"row 3 before row 7", func(m v2Msg) { m["run_counter"] = "4"; m["pinned_by"] = "console" }, nil, netobs.CloseRunRegressed, ""},
		{"row 4: equal run_counter, another run_id", func(m v2Msg) { m["run_id"] = v2RunB }, nil, netobs.CloseRunForked, ""},
		{"row 4 before row 7", func(m v2Msg) { m["run_id"] = v2RunB; m["pinned_by"] = "console" }, nil, netobs.CloseRunForked, ""},
		{"row 5: a resume", nil, nil, "", netobs.HelloResume},
		{"row 5: prior on a resume", func(m v2Msg) { m["prior"] = v2Prior("0") }, nil, netobs.CloseHello, ""},
		{"row 5a: drops_channel below D (N1-b)", func(m v2Msg) { m["drops_channel"] = "2" }, nil, netobs.CloseRunRegressed, ""},
		{"row 7 before row 5", func(m v2Msg) { m["drops_channel"] = "2"; m["pinned_by"] = "console" }, nil, netobs.CloseBinding, ""},
		{"row 5a: newest_seq below T", func(m v2Msg) { m["first_seq"] = "10"; m["newest_seq"] = "9" }, nil, netobs.CloseRunRegressed, ""},
		{"row 5a: newest_seq at T", func(m v2Msg) { m["first_seq"] = "11"; m["newest_seq"] = "10" }, nil, "", netobs.HelloResume},
		{"row 5b: a renew's resume", nil, func(s *netobs.HelloState) { s.Position.Generation = 1 }, "", netobs.HelloResumeRenewed},
		{"row 5b's resume, 5a still applies", func(m v2Msg) { m["first_seq"] = "10"; m["newest_seq"] = "9" }, func(s *netobs.HelloState) { s.Position.Generation = 1 }, netobs.CloseRunRegressed, ""},
		{"a position below Began reads as none: no prior", nil, func(s *netobs.HelloState) { s.Position.Generation = 1; s.Began = 2 }, netobs.CloseHello, ""},
		{"a position below Began reads as none: a new run", func(m v2Msg) { m["prior"] = v2Prior("4") }, func(s *netobs.HelloState) { s.Position.Generation = 1; s.Began = 2 }, "", netobs.HelloNewRun},
		{"no position: run 1 is a new run", func(m v2Msg) { m["run_counter"] = "1"; m["prior"] = v2Prior("0") }, func(s *netobs.HelloState) { s.Position = nil }, "", netobs.HelloNewRun},
		{"row 6: a new run", func(m v2Msg) { m["run_counter"] = "6"; m["prior"] = v2Prior("0") }, nil, "", netobs.HelloNewRun},
		{"row 6: a new run without prior", func(m v2Msg) { m["run_counter"] = "6" }, nil, netobs.CloseHello, ""},
		{"row 7 before row 6", func(m v2Msg) { m["run_counter"] = "6"; m["pinned_by"] = "console" }, nil, netobs.CloseBinding, ""},
		{"row 7: pinned_by changed in the generation", func(m v2Msg) { m["pinned_by"] = "console" }, nil, netobs.CloseBinding, ""},
		{"row 7: the first pinned_by of the generation", func(m v2Msg) { m["pinned_by"] = "console" }, func(s *netobs.HelloState) { s.PinnedBy = "" }, "", netobs.HelloResume},
		{"row 7 before row 8", func(m v2Msg) { m["pinned_by"] = "console"; m["config_digest"] = v2DigestB }, nil, netobs.CloseBinding, ""},
	}
	for _, c := range cases {
		m := v2SensorHello()
		if c.hello != nil {
			c.hello(m)
		}
		s := v2State()
		if c.state != nil {
			c.state(&s)
		}
		v := netobs.JudgeHello(s, v2Hello(t, m))
		if v.Close != c.close || v.Accept != c.accept {
			t.Errorf("%s: close %q accept %q, want close %q accept %q", c.name, v.Close, v.Accept, c.close, c.accept)
		}
	}
	// Rows 8 and 9 raise and never close.
	for _, c := range []struct {
		name           string
		hello          func(v2Msg)
		digest, buffer bool
	}{
		{"row 8: another digest", func(m v2Msg) { m["config_digest"] = v2DigestB }, true, false},
		{"row 9: buffer_bytes 256 MiB - 1", func(m v2Msg) { m["buffer_bytes"] = fmt.Sprint(256<<20 - 1) }, false, true},
		{"row 9: buffer_bytes 256 MiB", func(m v2Msg) { m["buffer_bytes"] = fmt.Sprint(256 << 20) }, false, false},
		{"rows 8 and 9 together", func(m v2Msg) { m["config_digest"] = v2DigestB; m["buffer_bytes"] = fmt.Sprint(16 << 20) }, true, true},
	} {
		m := v2SensorHello()
		c.hello(m)
		v := netobs.JudgeHello(v2State(), v2Hello(t, m))
		if v.Close != "" || v.Accept != netobs.HelloResume || v.DigestMismatch != c.digest || v.BufferSmall != c.buffer {
			t.Errorf("%s: %+v, want accepted with digest %v, buffer %v", c.name, v, c.digest, c.buffer)
		}
	}
}

// v2HeldState is v2State with span a held for run 5 at Ds 3 (CH-40). A
// resume that states a and the new span b with drops_channel 3, which is D,
// pays for nothing: b is new and 3 is not above Ds. So the span is unpaid
// and no 5a check is touched.
func v2HeldState() netobs.HelloState {
	s := v2State()
	s.Spans, s.Ds = []netobs.Span{{FromUTC: "2026-11-15T09:00:00Z", ToUTC: "2026-11-15T09:01:00Z"}}, 3
	return s
}

var (
	v2SpanA = v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:01:00Z")
	v2SpanB = v2Span("2026-11-15T09:05:00Z", "2026-11-15T09:06:00Z")
)

// v2Unpaid states an unpaid span: on a resume against v2HeldState, the new
// span b with drops_channel at D; on a new run (no span held, Ds 0), span b
// with drops_channel 0.
func v2Unpaid(m v2Msg) {
	if m["run_counter"] == "5" {
		m["lost"], m["drops_channel"] = []any{v2SpanA, v2SpanB}, "3"
		return
	}
	m["lost"], m["drops_channel"] = []any{v2SpanB}, "0"
}

// CH-13 as amended by D1's ruling on finding A (option 2, D4-106; it
// replaces this test's earlier reading, the text's order, which D1 did not
// take). Row 1 checks only the spans' form (CH-40: from_utc at or before
// to_utc, at most MaxLostSpans, disjoint, oldest first). CH-40's widening
// check needs the run's held spans and Ds, so it is applied at row 5 or 6
// and still closes as hello. Rows 2, 3, 4 and 7 decide before it, so an
// unpaid span cannot turn an audited close into hello (D6's B1, D3's
// judgement on #687). An unpaid span in a hello no earlier row closes still
// closes as hello.
func TestC13v02H1Row1SpansFirst(t *testing.T) {
	// Row 1's form decides before identity: a fork, or another generation,
	// whose span runs from after to is refused at its strict decode, which
	// the node closes as hello.
	for name, f := range map[string]func(v2Msg){
		"row 1's form before row 2": func(m v2Msg) { m["generation"] = "3" },
		"row 1's form before row 4": func(m v2Msg) { m["run_id"] = v2RunB },
	} {
		m := v2SensorHello()
		f(m)
		m["lost"] = []any{v2Span("2026-11-15T09:00:01Z", "2026-11-15T09:00:00Z")}
		if d, err := netobs.DecodeFromSensor(v2JSON(t, m)); err == nil || d.Type != netobs.TypeSensorHello {
			t.Errorf("%s: %v, want the hello refused (the node closes hello)", name, err)
		}
	}
	newRun := func(m v2Msg) { m["run_counter"], m["prior"] = "6", v2Prior("0") }
	for _, c := range []struct {
		name  string
		f     func(v2Msg)
		close string
	}{
		// Rows 2, 3, 4 and 7 before the widening check.
		{"row 2 before the widening check", func(m v2Msg) { v2Unpaid(m); m["generation"] = "3" }, netobs.CloseBinding},
		{"row 3 before the widening check", func(m v2Msg) { v2Unpaid(m); m["run_counter"] = "4" }, netobs.CloseRunRegressed},
		{"row 4 before the widening check", func(m v2Msg) { v2Unpaid(m); m["run_id"] = v2RunB }, netobs.CloseRunForked},
		{"row 7 before row 5's widening check", func(m v2Msg) { v2Unpaid(m); m["pinned_by"] = "console" }, netobs.CloseBinding},
		{"row 7 before row 6's widening check", func(m v2Msg) { newRun(m); v2Unpaid(m); m["pinned_by"] = "console" }, netobs.CloseBinding},
		// No earlier row closes: the unpaid span closes as hello.
		{"a resume with an unpaid span", v2Unpaid, netobs.CloseHello},
		{"a new run with an unpaid span", func(m v2Msg) { newRun(m); v2Unpaid(m) }, netobs.CloseHello},
		{"a new run with prior.lost and records_lost 0", func(m v2Msg) { newRun(m); v2Set(m, "prior.lost", []any{v2SpanA}) }, netobs.CloseHello},
	} {
		m := v2SensorHello()
		c.f(m)
		if v := netobs.JudgeHello(v2HeldState(), v2Hello(t, m)); v.Close != c.close {
			t.Errorf("%s: close %q, want %q (CH-13 as amended, CH-40)", c.name, v.Close, c.close)
		}
	}
}

// H-1 and H-4's contract legs under the amended order (D1's ruling on
// finding A, option 2 with N1-b, D4-106): every close that writes
// sensor.link_refused (C8-4) is decided before any of the sensor's
// declarations (prior, drops_channel, lost, prior.lost) is judged. Row 7
// runs after row 4 and before row 5 or 6; row 5 runs 5a first, and 5a is
// newest_seq below T or drops_channel below D (N1-b; CH-15 as amended, D3's
// condition 2). Each close here is one of C8-4's six reasons, so the node
// writes its record; the record itself is the node intake's leg (owed).
// v2LinkRefusedCloses are those six as C13 writes them, with hyphens; the
// record's reason_code is their underscore form (F1, D4-107), which the
// node maps from its typed verdicts, never from these strings.
var v2LinkRefusedCloses = []string{"peer-key", "expired", "binding", "run-regressed", "run-forked", "sensor-id"}

func TestC13v02H1OrderAudited(t *testing.T) {
	regressed := func(m v2Msg) { m["first_seq"], m["newest_seq"] = "10", "9" } // T is 10
	for _, c := range []struct {
		name  string
		f     func(v2Msg)
		state func(*netobs.HelloState)
		close string
	}{
		// 5a before row 5's declarations.
		{"5a before prior", func(m v2Msg) { regressed(m); m["prior"] = v2Prior("0") }, nil, netobs.CloseRunRegressed},
		{"5a: newest_seq below T, with a falling drops_channel", func(m v2Msg) { regressed(m); m["drops_channel"] = "2" }, nil, netobs.CloseRunRegressed},
		{"5a before the widening check", func(m v2Msg) { v2Unpaid(m); regressed(m) }, nil, netobs.CloseRunRegressed},
		// N1-b: drops_channel below D is 5a with newest_seq at T.
		{"N1-b: newest_seq at T, drops_channel below D", func(m v2Msg) { m["first_seq"], m["newest_seq"], m["drops_channel"] = "11", "10", "2" }, nil, netobs.CloseRunRegressed},
		{"N1-b, with prior", func(m v2Msg) { m["drops_channel"] = "2"; m["prior"] = v2Prior("0") }, nil, netobs.CloseRunRegressed},
		{"N1-b on a renew's resume (5b), with an unpaid span", func(m v2Msg) { v2Unpaid(m); m["drops_channel"] = "2" }, func(s *netobs.HelloState) { s.Position.Generation = 1 }, netobs.CloseRunRegressed},
		// Row 7 before row 5 (5a included) and row 6.
		{"row 7 before prior", func(m v2Msg) { m["pinned_by"] = "console"; m["prior"] = v2Prior("0") }, nil, netobs.CloseBinding},
		{"row 7 before an unpaid span", func(m v2Msg) { v2Unpaid(m); m["pinned_by"] = "console" }, nil, netobs.CloseBinding},
		{"row 7 before 5a's drops_channel", func(m v2Msg) { m["pinned_by"] = "console"; m["drops_channel"] = "2" }, nil, netobs.CloseBinding},
		{"row 7 before 5a's newest_seq", func(m v2Msg) { regressed(m); m["pinned_by"] = "console" }, nil, netobs.CloseBinding},
		{"row 7 before row 6's prior", func(m v2Msg) { m["run_counter"], m["pinned_by"] = "6", "console" }, nil, netobs.CloseBinding},
		// Row 4 before row 7: a fork is held whatever it declares (SL-16).
		{"row 4 before row 7, with prior and an unpaid span", func(m v2Msg) {
			v2Unpaid(m)
			m["run_id"], m["pinned_by"], m["prior"] = v2RunB, "console", v2Prior("0")
		}, nil, netobs.CloseRunForked},
	} {
		m := v2SensorHello()
		c.f(m)
		s := v2HeldState()
		if c.state != nil {
			c.state(&s)
		}
		v := netobs.JudgeHello(s, v2Hello(t, m))
		if v.Close != c.close {
			t.Errorf("%s: close %q, want %q (CH-13 as amended)", c.name, v.Close, c.close)
		}
		if !slices.Contains(v2LinkRefusedCloses, v.Close) {
			t.Errorf("%s: close %q is not one of C8-4's six, so no sensor.link_refused is written", c.name, v.Close)
		}
	}
}

// H-2 (CH-13, CH-16): runs_skipped that disagrees raises
// sensor-gap-undeclared (runs), and the hello is accepted.
func TestC13v02H2RunsSkipped(t *testing.T) {
	for _, c := range []struct {
		counter, skipped string
		position         bool
		raise            bool
	}{
		{"8", "2", true, false}, {"8", "1", true, true}, {"8", "3", true, true},
		{"6", "0", true, false}, {"6", "1", true, true},
		{"3", "2", false, false}, {"3", "1", false, true}, {"3", "3", false, true},
	} {
		m := v2SensorHello()
		m["run_counter"], m["prior"] = c.counter, v2Prior(c.skipped)
		s := v2State()
		if !c.position {
			s.Position = nil
		}
		v := netobs.JudgeHello(s, v2Hello(t, m))
		if v.Close != "" || v.Accept != netobs.HelloNewRun || v.RunsUndeclared != c.raise {
			t.Errorf("run %s, runs_skipped %s, position %v: %+v, want a new run with RunsUndeclared %v", c.counter, c.skipped, c.position, v, c.raise)
		}
	}
}

// T-5 (CH-8) and S-2, S-5's contract legs: a tick's checks and its rate
// rule. On the first tick the earlier values are the hello's.
func TestC13v02T5Ticks(t *testing.T) {
	hello := v2Hello(t, v2SensorHello())
	last := v2TickOf(t, v2Tick()) // newest 20, sent 15, drops 3
	type tc struct {
		name     string
		tick     func(v2Msg)
		last     bool
		since    time.Duration
		close    string
		sensorID bool
		early    bool
	}
	cases := []tc{
		{"the first tick", nil, false, 0, "", false, false},
		{"another sensor_id", func(m v2Msg) { m["sensor_id"] = v2Other }, true, 10 * time.Second, netobs.CloseTick, true, false},
		{"another run_id", func(m v2Msg) { m["run_id"] = v2RunB }, true, 10 * time.Second, netobs.CloseTick, false, false},
		{"2 s after the last: tick_early", nil, true, 2 * time.Second, "", false, true},
		{"4.999 s after the last: tick_early", nil, true, 5*time.Second - time.Millisecond, "", false, true},
		{"5 s after the last", nil, true, 5 * time.Second, "", false, false},
		{"newest_seq below the hello's", func(m v2Msg) { m["newest_seq"] = "19"; m["sent_seq"] = "15" }, false, 0, netobs.CloseTick, false, false},
		{"drops_channel below the hello's", func(m v2Msg) { m["drops_channel"] = "2" }, false, 0, netobs.CloseTick, false, false},
		{"newest_seq below the last tick's", func(m v2Msg) { m["newest_seq"] = "19" }, true, 10 * time.Second, netobs.CloseTick, false, false},
		{"sent_seq below the last tick's", func(m v2Msg) { m["sent_seq"] = "14" }, true, 10 * time.Second, netobs.CloseTick, false, false},
		{"drops_channel below the last tick's", func(m v2Msg) { m["drops_channel"] = "2" }, true, 10 * time.Second, netobs.CloseTick, false, false},
		{"sent_seq above newest_seq", func(m v2Msg) { m["sent_seq"] = "21" }, true, 10 * time.Second, netobs.CloseTick, false, false},
		// S-5: sent_seq counts a seq skipped as unreadable, up to newest_seq.
		{"sent_seq at newest_seq", func(m v2Msg) { m["sent_seq"] = "20" }, true, 10 * time.Second, "", false, false},
		{"all equal to the last", nil, true, 10 * time.Second, "", false, false},
	}
	for _, c := range cases {
		m := v2Tick()
		if c.tick != nil {
			c.tick(m)
		}
		s := netobs.TickState{Hello: hello, Since: c.since}
		if c.last {
			s.Last = last
		}
		v := netobs.JudgeTick(s, v2TickOf(t, m))
		if v.Close != c.close || v.SensorID != c.sensorID || v.Early != c.early {
			t.Errorf("%s: %+v, want close %q, sensor-id %v, early %v", c.name, v, c.close, c.sensorID, c.early)
		}
	}
}

// S-2 (CH-15): a falling drops_channel closes in a tick (above), and is
// refused as order in a heartbeat (Follows); the heartbeat leg is in
// c13_v02_records_d6_test.go. Here, the hello's: a resume whose
// drops_channel is below D closes as run-regressed (5a, N1-b; CH-15 as
// amended, D3's condition 2 on #687), at D it is accepted.
func TestC13v02S2HelloDrops(t *testing.T) {
	for drops, want := range map[string]string{"2": netobs.CloseRunRegressed, "3": "", "4": ""} {
		m := v2SensorHello()
		m["drops_channel"] = drops
		if v := netobs.JudgeHello(v2State(), v2Hello(t, m)); v.Close != want {
			t.Errorf("drops_channel %s against D 3: close %q, want %q", drops, v.Close, want)
		}
	}
}

// S-9 (CH-40): spans in ticks and hellos. A span from after to closes; a
// new or wider span with no rise above Ds closes; a valid new span is
// accepted and marked; a restated span needs no rise; a span ending after
// sensor_utc, even in 2100, is no fault.
func TestC13v02S9Spans(t *testing.T) {
	a := v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:01:00Z")
	aWider := v2Span("2026-11-15T09:00:00Z", "2026-11-15T09:01:30Z")
	aEarlier := v2Span("2026-11-15T08:59:30Z", "2026-11-15T09:01:00Z")
	b := v2Span("2026-11-15T09:05:00Z", "2026-11-15T09:06:00Z")
	held := []netobs.Span{{FromUTC: "2026-11-15T09:00:00Z", ToUTC: "2026-11-15T09:01:00Z"}}
	hello := v2Hello(t, v2SensorHello())
	type tc struct {
		name    string
		lost    []any
		drops   string
		lastD   string // the last tick's drops_channel, "" for the first tick
		close   string
		widened bool
	}
	for _, c := range []tc{
		{"the held span restated, no rise", []any{a}, "3", "", "", false},
		// D4's reading of "new or wider" (#687): a span inside a held one
		// states no new time, so it needs no rise.
		{"a span inside the held one, no rise", []any{v2Span("2026-11-15T09:00:10Z", "2026-11-15T09:00:50Z")}, "3", "", "", false},
		{"a new span, no rise above Ds", []any{a, b}, "3", "", netobs.CloseTick, false},
		{"a new span with a rise", []any{a, b}, "4", "", "", true},
		{"the span wider at its end, no rise", []any{aWider}, "3", "", netobs.CloseTick, false},
		{"the span wider at its start, no rise", []any{aEarlier}, "3", "", netobs.CloseTick, false},
		{"the span wider, with a rise", []any{aWider}, "4", "", "", true},
		// Ds and not D (CH-40): D rose to 5 since (a heartbeat or an
		// earlier tick), Ds stayed 3; the tick that declares the span
		// shows 5, above Ds.
		{"a rise above Ds, none above the last tick", []any{a, b}, "5", "5", "", true},
		{"no span stated", []any{}, "3", "", "", false},
	} {
		m := v2Tick()
		m["lost"], m["drops_channel"] = c.lost, c.drops
		s := netobs.TickState{Hello: hello, Spans: held, Ds: 3, Since: 10 * time.Second}
		if c.lastD != "" {
			l := v2Tick()
			l["drops_channel"] = c.lastD
			s.Last = v2TickOf(t, l)
		}
		v := netobs.JudgeTick(s, v2TickOf(t, m))
		if v.Close != c.close || v.SpansWidened != c.widened {
			t.Errorf("tick, %s: %+v, want close %q widened %v", c.name, v, c.close, c.widened)
		}
	}
	// A span from after to, in a tick: refused at decode, so it closes as
	// tick.
	m := v2Tick()
	m["lost"] = []any{v2Span("2026-11-15T09:01:00Z", "2026-11-15T09:00:00Z")}
	if f, err := netobs.DecodeFromSensor(v2JSON(t, m)); err == nil || f.Type != netobs.TypeTick {
		t.Errorf("a tick span from after to: %v, want it refused as a tick", err)
	}
	// A span that ends after sensor_utc is not a fault, and nor is one in
	// 2100 with sensor_utc there too (the cut is the node's, owed).
	for name, f := range map[string]func(v2Msg){
		"a span past sensor_utc": func(m v2Msg) {
			m["lost"] = []any{v2Span("2026-11-15T09:59:00Z", "2026-11-15T10:05:00Z")}
			m["drops_channel"] = "4"
		},
		"a span and sensor_utc in 2100": func(m v2Msg) {
			m["lost"] = []any{v2Span("2100-01-01T00:00:00Z", "2100-01-01T00:10:00Z")}
			m["sensor_utc"], m["drops_channel"] = "2100-01-01T00:20:00Z", "4"
		},
	} {
		m := v2Tick()
		f(m)
		v := netobs.JudgeTick(netobs.TickState{Hello: hello, Ds: 3}, v2TickOf(t, m))
		if v.Close != "" || !v.SpansWidened {
			t.Errorf("%s: %+v, want accepted and marked", name, v)
		}
	}
	// In a hello: a resume after a node restart restates the held spans
	// with an unchanged drops_channel: accepted. A new span with no rise
	// closes as hello. On a new run the run holds no span (Ds 0); prior.lost
	// needs prior.records_lost above 0.
	for _, c := range []struct {
		name    string
		f       func(v2Msg)
		close   string
		widened int // 0 not marked, 1 marked, -1 not asserted
	}{
		{"a resume restating the held span", func(m v2Msg) { m["lost"] = []any{a} }, "", 0},
		{"a resume with a new span, no rise", func(m v2Msg) { m["lost"] = []any{a, b} }, netobs.CloseHello, -1},
		{"a resume with a new span and a rise", func(m v2Msg) { m["lost"] = []any{a, b}; m["drops_channel"] = "4" }, "", 1},
		{"a new run's span with drops_channel 0", func(m v2Msg) {
			m["run_counter"], m["prior"], m["lost"], m["drops_channel"] = "6", v2Prior("0"), []any{b}, "0"
		}, netobs.CloseHello, -1},
		{"a new run's span with drops_channel 1", func(m v2Msg) {
			m["run_counter"], m["prior"], m["lost"], m["drops_channel"] = "6", v2Prior("0"), []any{b}, "1"
		}, "", 1},
		{"prior.lost with records_lost 0", func(m v2Msg) {
			m["run_counter"], m["prior"] = "6", v2Prior("0")
			v2Set(m, "prior.lost", []any{a})
		}, netobs.CloseHello, -1},
		{"prior.lost with records_lost 1", func(m v2Msg) {
			m["run_counter"], m["prior"] = "6", v2Prior("0")
			v2Set(m, "prior.lost", []any{a})
			v2Set(m, "prior.records_lost", "1")
		}, "", -1},
	} {
		m := v2SensorHello()
		c.f(m)
		s := v2State()
		s.Spans, s.Ds = held, 3
		v := netobs.JudgeHello(s, v2Hello(t, m))
		if v.Close != c.close || (c.widened >= 0 && v.SpansWidened != (c.widened == 1)) {
			t.Errorf("hello, %s: %+v, want close %q widened %v", c.name, v, c.close, c.widened)
		}
	}
}

// A-1 (CH-9, CH-43): the agent's check of an ack.
func TestC13v02A1Acks(t *testing.T) {
	ack := func(counter, run, seq string) *netobs.Ack {
		m := v2Ack()
		m["run_counter"], m["run_id"], m["seq"] = counter, run, seq
		f, err := netobs.DecodeFromNode(v2JSON(t, m))
		if err != nil {
			t.Fatal(err)
		}
		return f.Ack
	}
	u := func(n uint64) *uint64 { return &n }
	// Run 5, first_seq 11, sent up to 15, the last ack 12.
	s := netobs.AckState{RunCounter: 5, RunID: v2Run, FirstSeq: 11, SentSeq: 15, LastAck: u(12)}
	for _, c := range []struct {
		name string
		a    *netobs.Ack
		s    netobs.AckState
		ok   bool
	}{
		{"within the sent", ack("5", v2Run, "14"), s, true},
		{"the highest sent", ack("5", v2Run, "15"), s, true},
		{"above the highest sent and first_seq - 1", ack("5", v2Run, "16"), s, false},
		{"equal to the last ack", ack("5", v2Run, "12"), s, true},
		{"below the last ack", ack("5", v2Run, "11"), s, false},
		{"another run_counter", ack("6", v2Run, "14"), s, false},
		{"another run_id", ack("5", v2RunB, "14"), s, false},
		// A resume with nothing to send: first_seq - 1 is valid, before any
		// tick, and so is the node's keepalive of it.
		{"first_seq - 1 on a resume, nothing sent", ack("5", v2Run, "10"), netobs.AckState{RunCounter: 5, RunID: v2Run, FirstSeq: 11}, true},
		{"first_seq on a resume, nothing sent", ack("5", v2Run, "11"), netobs.AckState{RunCounter: 5, RunID: v2Run, FirstSeq: 11}, false},
		{"the first ack, 0 on a new run", ack("5", v2Run, "0"), netobs.AckState{RunCounter: 5, RunID: v2Run, FirstSeq: 1}, true},
		{"the first ack, 1 on a new run with nothing sent", ack("5", v2Run, "1"), netobs.AckState{RunCounter: 5, RunID: v2Run, FirstSeq: 1}, false},
		{"first_seq - 1 after a resend above it", ack("5", v2Run, "10"), netobs.AckState{RunCounter: 5, RunID: v2Run, FirstSeq: 11, SentSeq: 13}, true},
	} {
		if got := netobs.AckValid(c.s, c.a); got != c.ok {
			t.Errorf("%s: %v, want %v", c.name, got, c.ok)
		}
	}
}

// S-1 (CH-14): each row of a record's place in its run. L starts at
// first_seq - 1 (10), P is the saved T.
func TestC13v02S1PlaceRecord(t *testing.T) {
	h := v2Hello(t, v2SensorHello())
	for _, c := range []struct {
		name          string
		l, p          uint64
		sensor, run   string
		seq           uint64
		place         string
		wantL, wantGp uint64
	}{
		{"another run_id", 10, 10, v2Sensor, v2RunB, 11, netobs.PlaceRun, 10, 0},
		{"the next seq", 10, 10, v2Sensor, v2Run, 11, netobs.PlaceRead, 11, 0},
		{"at L", 11, 10, v2Sensor, v2Run, 11, netobs.PlaceSeq, 11, 0},
		{"below L", 14, 10, v2Sensor, v2Run, 12, netobs.PlaceSeq, 14, 0},
		{"a jump above P", 10, 10, v2Sensor, v2Run, 14, netobs.PlaceRead, 14, 3},
		{"above L, at P", 10, 15, v2Sensor, v2Run, 15, netobs.PlaceDuplicate, 15, 0},
		{"above L, below P", 10, 15, v2Sensor, v2Run, 12, netobs.PlaceDuplicate, 12, 0},
		{"P + 1 after duplicates", 10, 15, v2Sensor, v2Run, 16, netobs.PlaceRead, 16, 0},
		{"a jump past P", 10, 15, v2Sensor, v2Run, 18, netobs.PlaceRead, 18, 2},
		{"a jump past L above P", 13, 10, v2Sensor, v2Run, 16, netobs.PlaceRead, 16, 2},
		{"another sensor_id takes its seq", 10, 10, v2Other, v2Run, 11, netobs.PlaceSensorID, 11, 0},
	} {
		got := netobs.PlaceRecord(h, c.l, c.p, c.sensor, c.run, c.seq)
		if got.Place != c.place || got.L != c.wantL || got.Gap != c.wantGp {
			t.Errorf("%s: %+v, want %s, L %d, gap %d", c.name, got, c.place, c.wantL, c.wantGp)
		}
	}
	// A record under another sensor_id moves L, so the next one is no gap
	// (the control of S-1: refused before its seq, it would leave one).
	first := netobs.PlaceRecord(h, 10, 10, v2Other, v2Run, 11)
	if next := netobs.PlaceRecord(h, first.L, 10, v2Sensor, v2Run, 12); next.Place != netobs.PlaceRead || next.Gap != 0 {
		t.Errorf("after a sensor-id refusal at 11, seq 12: %+v, want read with no gap", next)
	}
}

// M-8 (CH-11): each end's closed set of close reasons, pinned by value,
// and each reason the contract's checks give is in its end's set.
func TestC13v02M8CloseSets(t *testing.T) {
	node := []string{"hello", "hello-timeout", "binding", "run-regressed", "run-forked", "run", "tick", "idle",
		"frame-too-large", "store", "position-not-saved", "second-connection", "enrolment", "shutdown", "state-unread"}
	agent := []string{"handshake", "node-hello", "node-hello-timeout", "binding", "ack", "type", "idle",
		"frame-too-large", "superseded", "run-complete", "shutdown"}
	sorted := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }
	if !slices.Equal(sorted(netobs.NodeCloseReasons), sorted(node)) {
		t.Errorf("NodeCloseReasons %v, CH-11 lists %v", netobs.NodeCloseReasons, node)
	}
	if !slices.Equal(sorted(netobs.AgentCloseReasons), sorted(agent)) {
		t.Errorf("AgentCloseReasons %v, CH-11 lists %v", netobs.AgentCloseReasons, agent)
	}
	if slices.Contains(netobs.NodeCloseReasons, "closed-before-hello") {
		t.Error("closed-before-hello is a count, not a node close reason (CH-11)")
	}
	// The reasons the pure checks give.
	h := v2Hello(t, v2SensorHello())
	nodeGot := []string{
		netobs.PlaceRecord(h, 10, 10, v2Sensor, v2RunB, 11).Place,
		netobs.JudgeTick(netobs.TickState{Hello: h}, v2TickOf(t, func() v2Msg { m := v2Tick(); m["run_id"] = v2RunB; return m }())).Close,
	}
	for _, f := range []func(v2Msg){
		func(m v2Msg) { m["sensor_id"] = v2Other }, func(m v2Msg) { m["run_counter"] = "4" },
		func(m v2Msg) { m["run_id"] = v2RunB }, func(m v2Msg) { m["prior"] = v2Prior("0") },
	} {
		m := v2SensorHello()
		f(m)
		nodeGot = append(nodeGot, netobs.JudgeHello(v2State(), v2Hello(t, m)).Close)
	}
	for _, r := range nodeGot {
		if !slices.Contains(node, r) {
			t.Errorf("a node check closed %q, not in CH-11's set", r)
		}
	}
	var agentGot []string
	for _, b := range [][]byte{
		[]byte(`{"schema":"otsec.netobs/0.2","type":"tick"}`),
		v2JSON(t, func() v2Msg { m := v2NodeHello(); delete(m, "generation"); return m }()),
		v2JSON(t, func() v2Msg { m := v2Ack(); delete(m, "seq"); return m }()),
		bytes.Repeat([]byte(" "), 1025),
	} {
		f, _ := netobs.DecodeFromNode(b)
		agentGot = append(agentGot, f.Close)
	}
	for _, r := range agentGot {
		if !slices.Contains(agent, r) {
			t.Errorf("an agent check closed %q, not in CH-11's set", r)
		}
	}
}

// R-1 and R-6 (CH-35, CH-36): 0.1 has no hello. A 0.1 peer's first frame,
// and a hello of a minor the node does not know, are refused (the node
// closes hello); a record of a minor the node does not know is one record
// refused (schema), the connection open. The minor the node does not know
// is this code's own + 1, so it moved from 0.3 to 0.4 with C13 0.3 (#689;
// brief P4-4-CC, "Later-minor legs move with the minor").
func TestC13v02R1R6Minors(t *testing.T) {
	for _, schema := range []string{"otsec.netobs/0.1", "otsec.netobs/0.4", "otsec.netobs/1.2"} {
		m := v2SensorHello()
		m["schema"] = schema
		f, err := netobs.DecodeFromSensor(v2JSON(t, m))
		if !slices.Contains(netobs.Codes(err), netobs.CodeSchema) || f.Type != netobs.TypeSensorHello {
			t.Errorf("a %s sensor-hello: %v, want schema", schema, err)
		}
		tk := v2Tick()
		tk["schema"] = schema
		if f, err := netobs.DecodeFromSensor(v2JSON(t, tk)); !slices.Contains(netobs.Codes(err), netobs.CodeSchema) || f.Type != netobs.TypeTick {
			t.Errorf("a %s tick: %v, want schema, reported as a tick", schema, err)
		}
		for _, typ := range []string{netobs.TypeHeartbeat, netobs.TypeObservation} {
			rec := v2Msg{"schema": schema, "type": typ}
			f, err := netobs.DecodeFromSensor(v2JSON(t, rec))
			if !slices.Equal(netobs.Codes(err), []netobs.Code{netobs.CodeSchema}) || f.Type != typ {
				t.Errorf("a %s %s: %v, want one record refused as schema", schema, typ, err)
			}
		}
	}
	// A 0.1 peer's own first frame: a 0.1 heartbeat, as main's channel
	// sends it, is not a hello.
	if f, _ := netobs.DecodeFromSensor([]byte(`{"schema":"otsec.netobs/0.1","type":"heartbeat"}`)); f.Hello != nil {
		t.Error("a 0.1 heartbeat read as a hello")
	}
}

// T-1 (CH-21), for the messages: sensor_utc in RFC 3339 UTC with Z and at
// most nine fractional digits; another form closes (hello, tick).
func TestC13v02T1MessageTimes(t *testing.T) {
	bad := []string{"2026-11-15T10:00:00+00:00", "2026-11-15T10:00:00z", "2026-11-15T10:00:00.1234567890Z",
		"2026-11-15 10:00:00Z", "2026-11-15T10:00Z", "2026-11-15T10:00:00", ""}
	good := []string{"2026-11-15T10:00:00Z", "2026-11-15T10:00:00.123456789Z", "2026-11-15T10:00:00.5Z"}
	for _, v := range bad {
		for typ, m := range map[string]v2Msg{netobs.TypeSensorHello: v2SensorHello(), netobs.TypeTick: v2Tick()} {
			m["sensor_utc"] = v
			if f, err := netobs.DecodeFromSensor(v2JSON(t, m)); err == nil || f.Type != typ {
				t.Errorf("%s sensor_utc %q: %v, want it refused as %s", typ, v, err, typ)
			}
		}
	}
	for _, v := range good {
		for typ, m := range map[string]v2Msg{netobs.TypeSensorHello: v2SensorHello(), netobs.TypeTick: v2Tick()} {
			m["sensor_utc"] = v
			if _, err := netobs.DecodeFromSensor(v2JSON(t, m)); err != nil {
				t.Errorf("%s sensor_utc %q: %v", typ, v, err)
			}
		}
	}
}
