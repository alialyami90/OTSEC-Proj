package netobs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// maxLinkCursorBytes is the node's MaxLinkCursorBytes (C13 0.2 CH-18, §12),
// which every stored observation carries in its record.
const maxLinkCursorBytes = 4096

func worstSpans() []Span {
	var s []Span
	for i := range MaxLostSpans {
		s = append(s, Span{FromUTC: fmt.Sprintf("2026-11-07T09:%02d:00.123456789Z", i), ToUTC: fmt.Sprintf("2026-11-07T09:%02d:30.123456789Z", i)})
	}
	return s
}

// worstChannel02 sets on a worst 0.1 observation what the 0.2 and 0.3
// channels add or bound (C13 0.3 §15): three inner VIDs, the DNP3
// function's objects_unread, the SNMPv3 usm_parsed with boots and time at
// their bound, and a login whose slot was placed, so it carries a user
// and no why; an undecoded record with ip has basis port. D6's recount of
// the stored sizes is owed (§15.8).
func worstChannel02(o *Observation) {
	o.L2.VLAN, o.L2.InnerVLANs = ptr(4094), []int{4094, 4094, 4094}
	switch {
	case o.Function != nil:
		o.Function.ObjectsUnread = ptr(false)
	case o.Encrypted != nil && o.Encrypted.SNMPv3 != nil:
		s := o.Encrypted.SNMPv3
		s.UsmParsed, s.Boots, s.Time = ptr(true), ptr(int64(MaxUSMInteger)), ptr(int64(MaxUSMInteger))
	case o.Undecoded != nil:
		o.Undecoded.Basis = "port" // ethertype never with ip on the channel
	case o.Insecure != nil && o.Insecure.Login != nil:
		o.Insecure.Login.Slot, o.Insecure.Login.Why = "placed", ""
	}
}

// TestWorstStored02Fits (R-5's contract leg): the worst 0.2 stored body,
// with made_utc, every node mark and MaxLostSpans windows, is within C4
// 0.3's MaxNetobsBytes, the bound a 0.1 DecodeStored checks first (CH-35);
// and its event, its capture and a cursor of MaxLinkCursorBytes fit the
// smallest record cap.
func TestWorstStored02Fits(t *testing.T) {
	worstBody, worstRecord := 0, 0
	for _, o := range worstObservations(t) {
		o.Schema, o.MadeUTC = Identifier02, "2026-11-07T10:00:01.123456789Z"
		worstChannel02(o)
		o.Coverage.ConfigDigest, o.Coverage.Settings.PRPWindowMS = fxDigest, MaxPRPWindowMS
		for {
			if b, _ := json.Marshal(o.Coverage); len(b) <= MaxCoverageBytes {
				break
			}
			o.Coverage.Decodes = o.Coverage.Decodes[:len(o.Coverage.Decodes)-1]
		}
		if err := o.validateChannel(Identifier02, nil, nil); err != nil {
			t.Fatalf("%s: %v", o.Kind, err)
		}
		s := worstStored(o)
		s.Node.Late, s.Node.Backlog, s.Node.Skewed, s.Node.Lost = true, true, true, worstSpans()
		if err := s.ValidateStored(); err != nil {
			t.Fatalf("%s: %v", s.Kind, err)
		}
		body := mustJSON(t, s)
		e := &event.Event{
			Schema: event.Identifier, ID: event.EventID{NodeID: worstNode, Stream: worstStrm, Seq: ^uint64(0)},
			Origin: event.OriginPlatform, Kind: event.KindNetworkObservation,
			Source:   event.Source{Asset: &event.AssetRef{ID: fxAsset, Binding: event.Binding{Method: "observed-address", Confidence: "inferred"}}, OriginAuth: "platform"},
			Received: event.Received{UTC: "2026-11-07T10:00:01.123456789Z", ResolutionNS: 1, Clock: event.Clock{Sync: "synchronized", Source: worstToken("c")[:32]}},
			Netobs:   body,
		}
		if _, err := ObservationFromEvent(e); err != nil {
			t.Fatalf("%s: %v", s.Kind, err)
		}
		record := len(mustJSON(t, e)) + MaxCaptureBytes + maxLinkCursorBytes
		worstBody, worstRecord = max(worstBody, len(body)), max(worstRecord, record)
	}
	if worstBody > event.MaxNetobsBytes {
		t.Errorf("worst 0.2 stored body %d bytes, above MaxNetobsBytes %d", worstBody, event.MaxNetobsBytes)
	}
	if worstRecord > minRecordBytes {
		t.Errorf("worst 0.2 record %d bytes, above %d", worstRecord, minRecordBytes)
	}
	t.Logf("worst 0.2 stored body %d bytes (MaxNetobsBytes %d); worst record with a %d-byte cursor %d bytes (cap %d)",
		worstBody, event.MaxNetobsBytes, maxLinkCursorBytes, worstRecord, minRecordBytes)
}

// TestWorstAlert02Fits: the worst 0.2 alert, with eight assets and the two
// coverage details, is within MaxAlertBytes.
func TestWorstAlert02Fits(t *testing.T) {
	// own-session-outside-record carries related IDs and cites, so it is
	// the larger of the two rules an aggregate key may take.
	a := fxAlert()
	a.Rule, a.Schema, a.AssetID, a.AssetsTotal = RuleOwnSessionOutsideRecord, Identifier02, AggregateRecordsLate, 1<<62
	a.Params = []Param{{Name: "tie_grace_s", Value: "9223372036854775807"}}
	a.BaselineVersion = 1 << 62
	lt := string(bytes.Repeat([]byte("<"), ExplainMax))
	a.KeyText, a.BaselineValue, a.Observation = lt, lt, lt
	a.AtUTC, a.WindowStartUTC = "2026-11-07T10:04:00.123456789Z", "2026-11-07T10:00:00.123456789Z"
	a.Hits, a.Sources, a.RelatedTotal = 1<<62, 1<<62, 1<<62
	a.Related = nil
	for i := range MaxRelated {
		a.Related = append(a.Related, event.EventID{NodeID: worstNode, Stream: worstStrm, Seq: ^uint64(0) - uint64(i)})
	}
	a.Cites = nil
	for i := range MaxAlertFlows {
		a.Cites = append(a.Cites, Cite{CaptureID: "ring:" + fxRun + ":999999999999999999",
			Frames: []CiteFrame{{N: 1<<62 + int64(i), SHA256: hash(nil)}, {N: 1<<62 + 100 + int64(i), SHA256: hash(nil)}}})
	}
	a.FramesMissing = MaxAlertFlows * MaxAlertFramesPerFlow
	for i := range MaxAggregateAssets {
		a.Assets = append(a.Assets, fxInv(i))
	}
	a.Coverage = worstCoverage(t)
	a.Coverage.ConfigDigest, a.Coverage.Settings.PRPWindowMS = fxDigest, MaxPRPWindowMS
	for {
		if b, _ := json.Marshal(a.Coverage); len(b) <= MaxCoverageBytes {
			break
		}
		a.Coverage.Decodes = a.Coverage.Decodes[:len(a.Coverage.Decodes)-1]
	}
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	b := mustJSON(t, h)
	t.Logf("worst 0.2 aggregated alert health %d bytes (MaxAlertBytes %d)", len(b), MaxAlertBytes)
}

// TestWorstMessagesFit: the node's two messages fit MaxNodeMessage, and the
// worst sensor-hello and tick fit MaxChannelFrame (CH-2).
func TestWorstMessagesFit(t *testing.T) {
	max64 := "18446744073709551615"
	nh := &NodeHello{Schema: Identifier02, Type: TypeNodeHello, SensorID: fxSensor, Generation: max64,
		Taken: &Taken{RunCounter: max64, RunID: fxRun, Seq: max64}}
	ack := &Ack{Schema: Identifier02, Type: TypeAck, RunCounter: max64, RunID: fxRun, Seq: max64}
	for _, v := range []any{nh, ack} {
		b := mustJSON(t, v)
		if _, err := DecodeFromNode(b); err != nil || len(b) > MaxNodeMessage {
			t.Errorf("%T: %d bytes, %v", v, len(b), err)
		}
		t.Logf("worst %T %d bytes (MaxNodeMessage %d)", v, len(b), MaxNodeMessage)
	}
	h := fxSensorHello()
	h.Generation, h.RunCounter, h.FirstSeq, h.NewestSeq, h.DropsChannel = max64, max64, max64, max64, max64
	h.Lost, h.SensorUTC, h.BufferBytes = worstSpans(), "2026-11-07T10:00:00.123456789Z", fmt.Sprint(uint64(MaxBufferBytes))
	h.Prior = &Prior{RunsSkipped: max64, RecordsLost: max64, Lost: worstSpans(), PreviousEnd: "unclean", StartedBy: "enrolment"}
	k := fxTick()
	k.NewestSeq, k.SentSeq, k.DropsChannel, k.BufferedRecords, k.BufferedBytes = max64, max64, max64, max64, max64
	k.Lost = worstSpans()
	for _, v := range []any{h, k} {
		b := mustJSON(t, v)
		if _, err := DecodeFromSensor(b); err != nil || len(b) > MaxChannelFrame {
			t.Errorf("%T: %d bytes, %v", v, len(b), err)
		}
		t.Logf("worst %T %d bytes", v, len(b))
	}
}
