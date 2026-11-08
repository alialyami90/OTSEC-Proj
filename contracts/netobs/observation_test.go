package netobs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

func TestValidRecords(t *testing.T) {
	for name, b := range map[string][]byte{
		"function":  mustJSON(t, fxFunction()),
		"flow":      mustJSON(t, fxFlow()),
		"heartbeat": mustJSON(t, fxHeartbeat()),
	} {
		r, err := DecodeChannel(b)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if (r.Heartbeat == nil) == (r.Observation == nil) {
			t.Errorf("%s: exactly one of heartbeat and observation", name)
		}
	}
	if err := fxStored().ValidateStored(); err != nil {
		t.Errorf("stored: %v", err)
	}
}

// TestObservationRules: each case breaks one rule of C13 and is refused
// with its code.
func TestObservationRules(t *testing.T) {
	cases := []struct {
		name string
		code Code
		mut  func(o *Observation)
	}{
		{"unknown minor", CodeSchema, func(o *Observation) { o.Schema = "otsec.netobs/0.2" }},
		{"sensor id upper case", CodeForm, func(o *Observation) { o.SensorID = strings.ToUpper(fxSensor) }},
		{"seq zero", CodeForm, func(o *Observation) { o.Seq = "0" }},
		{"seq leading zero", CodeForm, func(o *Observation) { o.Seq = "042" }},
		{"last before first", CodeOrder, func(o *Observation) { o.LastUTC = "2026-11-07T09:00:00Z" }},
		{"time with offset", CodeForm, func(o *Observation) { o.FirstUTC = "2026-11-07T10:00:00+01:00" }},
		{"ten fraction digits", CodeForm, func(o *Observation) { o.FirstUTC = "2026-11-07T10:00:00.0000000001Z" }},
		{"mac upper case", CodeForm, func(o *Observation) { o.L2.SrcMAC = "00:30:A7:00:00:01" }},
		{"vlan 4095", CodeRange, func(o *Observation) { o.L2.VLAN = ptr(4095) }},
		{"mapped address", CodeForm, func(o *Observation) { o.IP.Src = "::ffff:192.0.2.10" }},
		{"tcp without port", CodeMissing, func(o *Observation) { o.IP.Sport = nil }},
		{"tcp direction none", CodeConflict, func(o *Observation) { o.Direction = DirectionNone }},
		{"udp midstream", CodeConflict, func(o *Observation) { o.IP.L4 = "udp" }},
		{"protocol not a token", CodeForm, func(o *Observation) { o.Protocol = "dnp 3" }},
		{"unknown kind", CodeForm, func(o *Observation) { o.Kind = "alert" }},
		{"two bodies", CodeConflict, func(o *Observation) { o.Flow = &Flow{Phase: "start", Packets: 1, Bytes: 60} }},
		{"citation from another run", CodeConflict, func(o *Observation) {
			o.Citation.CaptureID = "ring:" + fxSensor + ":3"
		}},
		{"frames_total below listed", CodeConflict, func(o *Observation) { o.Citation.FramesTotal = 1 }},
		{"frames out of order", CodeOrder, func(o *Observation) { o.Citation.Frames[1].N = 17; o.Frames[1].N = 17 }},
		{"wire_len above an uncut frame", CodeConflict, func(o *Observation) { o.Citation.Frames[0].WireLen = 80 }},
		{"redaction outside the frame", CodeRange, func(o *Observation) { o.Citation.Frames[1].Redactions[0].Offset = 85 }},
		{"redaction reason", CodeForm, func(o *Observation) { o.Citation.Frames[1].Redactions[0].Reason = "secret" }},
		{"redactions overlap", CodeOrder, func(o *Observation) {
			r := o.Citation.Frames[1].Redactions
			o.Citation.Frames[1].Redactions = append(r, Redaction{Offset: 64, Length: 2, Reason: ReasonCredential})
		}},
		{"redactions above MaxRedactions", CodeRange, func(o *Observation) {
			var rs []Redaction
			for i := range MaxRedactions + 1 {
				rs = append(rs, Redaction{Offset: i * 2, Length: 1, Reason: ReasonCredential})
			}
			o.Citation.Frames[1].Redactions = rs
		}},
		{"slot-not-placed beside credential", CodeConflict, func(o *Observation) {
			r := o.Citation.Frames[1].Redactions
			o.Citation.Frames[1].Redactions = append(r, Redaction{Offset: 70, Length: 4, Reason: ReasonSlotNotPlaced})
		}},
		{"coverage settings out of bound", CodeRange, func(o *Observation) { o.Coverage.Settings.SAReplyTimeoutMS = 30001 }},
		{"pending table below bound", CodeRange, func(o *Observation) { o.Coverage.Settings.MaxPendingDNP3 = 255 }},
		{"degraded unknown", CodeForm, func(o *Observation) { o.Coverage.Degraded = []string{"lost"} }},
		{"vlans not ascending", CodeOrder, func(o *Observation) { o.Coverage.VLANsSeen = []int{20, 10} }},
		{"overflow before full", CodeConflict, func(o *Observation) { o.Coverage.VLANsOverflow = true }},
		{"hsr decoded", CodeForm, func(o *Observation) { o.Coverage.HSR = "decoded" }},
		{"lans not a subset", CodeForm, func(o *Observation) { o.Coverage.PRP.LANsSeen = []string{"b", "a"} }},
		{"dnp3 response code", CodeConflict, func(o *Observation) { o.Function.Code = 129 }},
		{"dnp3 with unit", CodeConflict, func(o *Observation) { o.Function.Unit = ptr(1) }},
		{"sa unknown", CodeForm, func(o *Observation) { o.Function.SA = "forged" }},
		{"sa_error_from without failed", CodeConflict, func(o *Observation) { o.Function.SAErrorFrom = "master" }},
		{"failed without sa_error_from", CodeForm, func(o *Observation) { o.Function.SA = SAFailed }},
		{"objects unsorted", CodeOrder, func(o *Observation) { o.Function.Objects = []string{"g80v1", "g12v1"} }},
		{"objects above MaxObjects", CodeRange, func(o *Observation) {
			o.Function.Objects = nil
			for i := range MaxObjects + 1 {
				o.Function.Objects = append(o.Function.Objects, "g"+string(rune('1'+i/10))+string(rune('0'+i%10))+"v1")
			}
		}},
		{"frames on a repeat", CodeConflict, func(o *Observation) { o.FirstSight = false }},
		{"frame missing", CodeConflict, func(o *Observation) { o.Frames = o.Frames[:1] }},
		{"frame hash", CodeHash, func(o *Observation) {
			b, _ := base64.StdEncoding.DecodeString(o.Frames[0].Data)
			b[0] ^= 1
			o.Frames[0].Data = base64.StdEncoding.EncodeToString(b)
		}},
		{"redaction not applied", CodeHash, func(o *Observation) {
			b := fxFrame(90, 60, 8)
			b[63] = 'p'
			o.Citation.Frames[1].SHA256 = hash(b)
			o.Frames[1].Data = base64.StdEncoding.EncodeToString(b)
		}},
		{"frame not base64", CodeForm, func(o *Observation) { o.Frames[0].Data = "!!" }},
		{"node from the sensor", CodeConflict, func(o *Observation) { o.Node = fxStored().Node }},
	}
	for _, tc := range cases {
		o := fxFunction()
		tc.mut(o)
		if got := Codes(o.Validate()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
	}
}

func TestModbusSub(t *testing.T) {
	modbus := func(code int, sub *int) *Observation {
		o := fxFunction()
		o.Protocol, o.IP.Dport = "modbus", ptr(502)
		o.Function = &Function{Code: code, Sub: sub, Objects: []string{}, Unit: ptr(1)}
		return o
	}
	for _, ok := range []*Observation{modbus(8, ptr(4)), modbus(8, ptr(65535)), modbus(43, ptr(14)), modbus(43, nil), modbus(8, nil), modbus(3, nil)} {
		if err := ok.Validate(); err != nil {
			t.Errorf("code %d sub %v: %v", ok.Function.Code, ok.Function.Sub, err)
		}
	}
	for _, bad := range []*Observation{modbus(43, ptr(256)), modbus(3, ptr(0)), modbus(8, ptr(-1))} {
		if err := bad.Validate(); err == nil {
			t.Errorf("code %d sub %v accepted", bad.Function.Code, *bad.Function.Sub)
		}
	}
	nounit := modbus(3, nil)
	nounit.Function.Unit = nil
	if !slices.Contains(Codes(nounit.Validate()), CodeRange) {
		t.Error("Modbus without unit accepted")
	}
	d := fxFunction()
	d.Function.Sub = ptr(1)
	if !slices.Contains(Codes(d.Validate()), CodeConflict) {
		t.Error("DNP3 with sub accepted")
	}
}

// TestStrictDecode: the channel decoder refuses what C13 §1 calls strict,
// and a type the channel does not carry (D3, D1 on #543).
func TestStrictDecode(t *testing.T) {
	good := string(mustJSON(t, fxFlow()))
	cases := map[string]struct {
		in   string
		code Code
	}{
		"unknown field":        {strings.Replace(good, `"kind":`, `"extra":1,"kind":`, 1), CodeDecode},
		"duplicate key":        {strings.Replace(good, `"kind":"flow"`, `"kind":"flow","kind":"flow"`, 1), CodeDecode},
		"nested duplicate key": {strings.Replace(good, `"phase":"start"`, `"phase":"start","phase":"start"`, 1), CodeDecode},
		"key in another case":  {strings.Replace(good, `"kind":`, `"Kind":`, 1), CodeDecode},
		"later minor":          {strings.Replace(good, Identifier, "otsec.netobs/0.2", 1), CodeSchema},
		"alert type":           {strings.Replace(good, `"type":"observation"`, `"type":"alert"`, 1), CodeType},
		"not an object":        {`[1]`, CodeDecode},
		"trailing data":        {good + `{}`, CodeDecode},
	}
	for name, tc := range cases {
		_, err := DecodeChannel([]byte(tc.in))
		if !slices.Contains(Codes(err), tc.code) {
			t.Errorf("%s: got %v, want %s", name, Codes(err), tc.code)
		}
	}
	withNode := fxFlow()
	withNode.Node = fxStored().Node
	withNode.Node.StoredCapture, withNode.Node.FunctionClass, withNode.Node.FunctionTable = "", "", ""
	if _, err := DecodeChannel(mustJSON(t, withNode)); !slices.Contains(Codes(err), CodeConflict) {
		t.Errorf("a sensor body with node: %v", err)
	}
}

func TestStoredNode(t *testing.T) {
	cases := []struct {
		name string
		code Code
		mut  func(o *Observation)
	}{
		{"no node", CodeMissing, func(o *Observation) { o.Node = nil }},
		{"frames kept", CodeConflict, func(o *Observation) { o.Frames = fxFunction().Frames }},
		{"resolved_by ip with nothing resolved", CodeConflict, func(o *Observation) {
			o.Node.SrcAsset, o.Node.DstAsset = AssetUnresolved, AssetUnresolved
		}},
		{"ambiguous with an asset", CodeConflict, func(o *Observation) { o.Node.ResolvedBy = "ip-ambiguous" }},
		{"first sight with no capture", CodeMissing, func(o *Observation) { o.Node.StoredCapture = "" }},
		{"class without table", CodeConflict, func(o *Observation) { o.Node.FunctionTable = "" }},
		{"evidence class", CodeForm, func(o *Observation) { o.Node.EvidenceClass = "lab" }},
		{"tie", CodeForm, func(o *Observation) {
			o.Node.PlatformSession = &PlatformSession{InvocationID: fxRun, Tie: "guess"}
		}},
		{"no_sa on a challenged operate", CodeConflict, func(o *Observation) { o.Node.DNP3NoSA = ptr(true) }},
		{"no_sa false", CodeForm, func(o *Observation) { o.Node.DNP3NoSA = ptr(false) }},
		{"no_sa missing on an unchallenged operate", CodeConflict, func(o *Observation) { o.Function.SA = SANone }},
		{"no_sa on a read", CodeConflict, func(o *Observation) {
			o.Function.SA, o.Node.FunctionClass, o.Node.DNP3NoSA = SANone, ClassRead, ptr(true)
		}},
		{"no_sa with sa absent", CodeConflict, func(o *Observation) { o.Function.SA, o.Node.DNP3NoSA = "", ptr(true) }},
		{"no_sa with sa failed", CodeConflict, func(o *Observation) {
			o.Function.SA, o.Function.SAErrorFrom, o.Node.DNP3NoSA = SAFailed, "outstation", ptr(true)
		}},
	}
	for _, tc := range cases {
		o := fxStored()
		tc.mut(o)
		if got := Codes(o.ValidateStored()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
	}
	ok := fxStored()
	ok.Function.SA, ok.Node.DNP3NoSA = SANone, ptr(true)
	if err := ok.ValidateStored(); err != nil {
		t.Errorf("an unchallenged operate with dnp3_no_sa: %v", err)
	}
}

func TestStoredRoundTrip(t *testing.T) {
	b := mustJSON(t, fxStored())
	o, err := DecodeStored(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustJSON(t, o), b) {
		t.Error("stored observation does not round trip")
	}
	later := strings.Replace(string(b), Identifier, "otsec.netobs/0.9", 1)
	later = strings.Replace(later, `"kind":`, `"added_later":true,"kind":`, 1)
	if _, err := DecodeStored([]byte(later)); err != nil {
		t.Errorf("a later minor is read forward: %v", err)
	}
	if _, err := DecodeStored([]byte(strings.Replace(string(b), `"kind":`, `"added_later":true,"kind":`, 1))); err == nil {
		t.Error("an unknown field at this minor was accepted")
	}
}

func TestObservationFromEvent(t *testing.T) {
	e := &event.Event{Kind: event.KindNetworkObservation, Netobs: mustJSON(t, fxStored()),
		Source: event.Source{Asset: &event.AssetRef{ID: fxAsset}}}
	if _, err := ObservationFromEvent(e); err != nil {
		t.Fatal(err)
	}
	e.Source.Asset.ID = fxMaster
	if _, err := ObservationFromEvent(e); !slices.Contains(Codes(err), CodeConflict) {
		t.Errorf("event asset is not the destination: %v", err)
	}
	e.Kind = event.KindHealth
	if _, err := ObservationFromEvent(e); !slices.Contains(Codes(err), CodeType) {
		t.Errorf("health event: %v", err)
	}
}

func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	recs := [][]byte{[]byte(`{"a":1}`), {}, bytes.Repeat([]byte("x"), MaxChannelFrame)}
	for _, r := range recs {
		if err := WriteFrame(&buf, r); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range recs {
		got, err := ReadFrame(&buf)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Errorf("at the end: %v", err)
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxChannelFrame+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("write over the bound: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 1, 0, 1})); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("read over the bound: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 5, 'a'})); err != io.ErrUnexpectedEOF {
		t.Errorf("cut record: %v", err)
	}
}

func TestHeartbeat(t *testing.T) {
	prev := fxHeartbeat()
	next := fxHeartbeat()
	next.Seq, next.Counters.Packets = "45", 1001
	if err := next.Follows(prev); err != nil {
		t.Errorf("a later heartbeat: %v", err)
	}
	next.Counters.TableEvictions = 0
	next.Counters.DNP3SeqReused = 0
	prev.Counters.DNP3SeqReused = 2
	if !slices.Contains(Codes(next.Follows(prev)), CodeOrder) {
		t.Error("a counter that decreased in one run was accepted")
	}
	next.RunID = fxSensor
	if err := next.Follows(prev); err != nil {
		t.Errorf("a new run starts afresh: %v", err)
	}
	same := fxHeartbeat()
	if !slices.Contains(Codes(same.Follows(fxHeartbeat())), CodeOrder) {
		t.Error("a repeated seq was accepted")
	}
	drv := fxHeartbeat()
	drv.Seq, drv.Counters.DropsDriver = "45", nil
	if err := drv.Follows(fxHeartbeat()); err != nil {
		t.Errorf("an absent driver counter is skipped: %v", err)
	}
	bad := fxHeartbeat()
	bad.InterfaceCheck = "fine"
	if !slices.Contains(Codes(bad.Validate()), CodeForm) {
		t.Error("interface_check outside its set accepted")
	}
	var raw map[string]any
	_ = json.Unmarshal(mustJSON(t, fxHeartbeat()), &raw)
	if _, ok := raw["counters"].(map[string]any)["drops_driver"]; !ok {
		t.Error("drops_driver dropped when zero: zero and unknown differ")
	}
}

// TestRedactionBound: MaxRedactions entries on one frame pass and one more
// is refused, and a lone slot-not-placed passes (C13 §3.2, §14; D6 on #543).
func TestRedactionBound(t *testing.T) {
	with := func(rs []Redaction) *Observation {
		o := fxFlow()
		o.Citation.Frames[1].Redactions = rs
		return o
	}
	var rs []Redaction
	for i := range MaxRedactions + 1 {
		rs = append(rs, Redaction{Offset: i * 2, Length: 1, Reason: ReasonCredential})
	}
	if err := with(rs[:MaxRedactions]).Validate(); err != nil {
		t.Errorf("%d redactions: %v", MaxRedactions, err)
	}
	if !slices.Contains(Codes(with(rs).Validate()), CodeRange) {
		t.Errorf("%d redactions accepted", MaxRedactions+1)
	}
	lone := []Redaction{{Offset: 54, Length: 36, Reason: ReasonSlotNotPlaced}}
	if err := with(lone).Validate(); err != nil {
		t.Errorf("lone slot-not-placed: %v", err)
	}
}

// TestValidUUID: C13's IDs take C1's and C2's form, version 1 to 8 and
// variant 8, 9, a or b (D5 on #549).
func TestValidUUID(t *testing.T) {
	for _, s := range []string{fxSensor, fxRun, fxAsset, "00000000-0000-1000-8000-000000000000"} {
		if !ValidUUID(s) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{
		"00000000-0000-0000-8000-000000000000", // version 0
		"00000000-0000-9000-8000-000000000000", // version 9
		"00000000-0000-4000-c000-000000000000", // variant c
		"00000000-0000-4000-8000-00000000000A", // uppercase
	} {
		if ValidUUID(s) {
			t.Errorf("%s accepted", s)
		}
	}
	o := fxFlow()
	o.SensorID = "5f0c2a7e-3b1d-0c8e-9a2f-6d4e8b1c7a90"
	if !slices.Contains(Codes(o.Validate()), CodeForm) {
		t.Error("a version-0 sensor_id accepted")
	}
}
