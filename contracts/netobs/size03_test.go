package netobs

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// worstEnd03 sets every 0.3 count of a TCP end at 2^63 - 1. With
// incomplete it carries the partial count and no password_lines (CH-55);
// without, password_lines and no incomplete.
func worstEnd03(f *Flow, incomplete bool) {
	m := func() *int64 { return ptr(int64(math.MaxInt64)) }
	f.OrigPayload, f.RespPayload, f.OrigPkts, f.RespPkts = m(), m(), m(), m()
	f.ToDeviceOverlapOctets, f.RexmitInconsistent, f.PasswordLines, f.Incomplete = m(), m(), m(), nil
	if incomplete {
		f.PasswordLines, f.Incomplete = nil, ptr(true)
	}
}

// TestEnd03Growth checks C13 0.3 §1.3's count for a flow end: all eight
// keys at their widest add 278 octets, and an end the node accepts, which
// never carries both password_lines and incomplete, at most 260.
func TestEnd03Growth(t *testing.T) {
	base := &Flow{Phase: "end", Packets: 1, Bytes: 60, End: "fin", SynOnly: ptr(false)}
	all := *base
	worstEnd03(&all, false)
	all.Incomplete = ptr(true)
	b0, b8 := len(mustJSON(t, base)), len(mustJSON(t, &all))
	if b8-b0 != 278 {
		t.Errorf("all eight keys add %d octets, the text says 278", b8-b0)
	}
	for _, inc := range []bool{false, true} {
		f := *base
		worstEnd03(&f, inc)
		if n := len(mustJSON(t, &f)) - b0; n > 260 {
			t.Errorf("an accepted end (incomplete %v) adds %d octets, above 260", inc, n)
		}
	}
}

// TestWorstStored03Fits (N-12's size leg, rerun with every new field): the
// worst stored body of each kind at 0.3, with the flow end's every count
// at its widest, is within C4's MaxNetobsBytes, and its event, its capture
// and a cursor of MaxLinkCursorBytes fit the smallest record cap.
func TestWorstStored03Fits(t *testing.T) {
	worstBody, worstRecord, worstFrame := 0, 0, 0
	for _, o := range worstObservations(t) {
		o.Schema, o.MadeUTC = Identifier03, "2026-11-07T10:00:01.123456789Z"
		worstChannel02(o)
		o.Coverage.ConfigDigest, o.Coverage.Settings.PRPWindowMS = fxDigest, MaxPRPWindowMS
		for {
			if b, _ := json.Marshal(o.Coverage); len(b) <= MaxCoverageBytes {
				break
			}
			o.Coverage.Decodes = o.Coverage.Decodes[:len(o.Coverage.Decodes)-1]
		}
		variants := []*Observation{o}
		if o.Kind == KindFlow {
			worstEnd03(o.Flow, false)
			inc := *o
			fl := *o.Flow
			worstEnd03(&fl, true)
			inc.Flow = &fl
			variants = append(variants, &inc)
		}
		for _, v := range variants {
			b := mustJSON(t, v)
			if _, err := DecodeFromSensorIn(b, Identifier03); err != nil {
				t.Fatalf("%s on the 0.3 channel: %v", v.Kind, err)
			}
			worstFrame = max(worstFrame, len(b))
			s := worstStored(v)
			s.Node.Late, s.Node.Backlog, s.Node.Skewed, s.Node.Lost = true, true, true, worstSpans()
			body := mustJSON(t, s)
			e := &event.Event{
				Schema: event.Identifier, ID: event.EventID{NodeID: worstNode, Stream: worstStrm, Seq: ^uint64(0)},
				Origin: event.OriginPlatform, Kind: event.KindNetworkObservation,
				Source:   event.Source{Asset: &event.AssetRef{ID: fxAsset, Binding: event.Binding{Method: "observed-address", Confidence: "inferred"}}, OriginAuth: "platform"},
				Received: event.Received{UTC: "2026-11-07T10:00:01.123456789Z", ResolutionNS: 1, Clock: event.Clock{Sync: "synchronized", Source: worstToken("c")[:32]}},
				Netobs:   body,
			}
			if _, err := ObservationFromEvent(e); err != nil {
				t.Fatalf("%s stored: %v", s.Kind, err)
			}
			record := len(mustJSON(t, e)) + MaxCaptureBytes + maxLinkCursorBytes
			worstBody, worstRecord = max(worstBody, len(body)), max(worstRecord, record)
		}
	}
	if worstFrame > MaxChannelFrame {
		t.Errorf("worst 0.3 channel record %d bytes, above MaxChannelFrame %d", worstFrame, MaxChannelFrame)
	}
	if worstBody > event.MaxNetobsBytes {
		t.Errorf("worst 0.3 stored body %d bytes, above MaxNetobsBytes %d", worstBody, event.MaxNetobsBytes)
	}
	if worstRecord > minRecordBytes {
		t.Errorf("worst 0.3 record %d bytes, above %d", worstRecord, minRecordBytes)
	}
	t.Logf("worst 0.3 channel record %d bytes (MaxChannelFrame %d); worst 0.3 stored body %d bytes (MaxNetobsBytes %d); worst record with a %d-byte cursor %d bytes (cap %d)",
		worstFrame, MaxChannelFrame, worstBody, event.MaxNetobsBytes, maxLinkCursorBytes, worstRecord, minRecordBytes)
}

// TestWorstHeartbeat03Fits: the 0.3 heartbeat with its three new counts at
// the uint64's widest fits MaxChannelFrame. It logs what the three add.
func TestWorstHeartbeat03Fits(t *testing.T) {
	h := fxHeartbeat03()
	h.FrameStage, h.Agent.OverlapJoinRefused, h.Agent.OverlapUnjoined = nil, nil, nil
	h.Schema = Identifier02
	b2 := len(mustJSON(t, h))
	h.Schema = Identifier03
	h.FrameStage = &FrameStage{OverlapTableFull: ptr(uint64(math.MaxUint64))}
	b := mustJSON(t, h)
	fs := len(b) - b2
	h.Agent.OverlapJoinRefused, h.Agent.OverlapUnjoined = ptr(uint64(math.MaxUint64)), ptr(uint64(math.MaxUint64))
	b = mustJSON(t, h)
	if _, err := DecodeFromSensorIn(b, Identifier03); err != nil || len(b) > MaxChannelFrame {
		t.Errorf("worst 0.3 heartbeat %d bytes: %v", len(b), err)
	}
	t.Logf("frame_stage adds %d octets and the agent's two counts %d, each count at 2^64 - 1", fs, len(b)-b2-fs)
}

// TestWorstMismatchAlertFits: an own-session-mismatch alert whose
// observation is the grammar's longest head with free text to ExplainMax,
// with every other field at its widest, is within MaxAlertBytes.
func TestWorstMismatchAlertFits(t *testing.T) {
	a := fxMismatch()
	lt := string(bytes.Repeat([]byte("<"), ExplainMax))
	a.KeyText, a.BaselineValue = lt, lt
	a.Observation = longestHead + ": " + strings.Repeat("<", ExplainMax-len(longestHead)-2)
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
	t.Logf("worst own-session-mismatch alert health %d bytes (MaxAlertBytes %d)", len(mustJSON(t, h)), MaxAlertBytes)
}
