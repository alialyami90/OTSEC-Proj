package netobs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// The worst cases of C13 §10. '<' grows to six bytes when JSON escapes it
// as HTML, the most any byte grows, so every Text holds MaxTextBytes of it.
// The node stores json.Marshal of the whole C4 event, so the stored cases
// measure that, plus the capture, as C5's Record.Bytes does (D5 on #543).

const minRecordBytes = 64 << 10 // C5's MinRecordBytes, the smallest record cap

var (
	worstText = NewText([]byte(strings.Repeat("<", MaxTextBytes+1)))
	worstIP6  = "1111:2222:3333:4444:5555:6666:7777:8888"
	worstNode = event.NodeID(strings.Repeat("a", 63))
	worstStrm = event.Stream(strings.Repeat("b", 128))
)

func worstToken(ch string) string { return strings.Repeat(ch, 64) }

// worstCoverage fills a coverage statement to MaxCoverageBytes.
func worstCoverage(t testing.TB) Coverage {
	cv := fxCoverage()
	cv.SensorVersion, cv.Engine = worstToken("v"), Engine{Name: worstToken("n"), Version: worstToken("e")}
	cv.Interfaces = nil
	for i := range MaxInterfaces {
		cv.Interfaces = append(cv.Interfaces, Interface{Name: fmt.Sprintf("%063d", i), Attachment: "unknown", LAN: "unknown"})
	}
	cv.PRP = PRP{LANsSeen: []string{"a", "b"}, DuplicatesDiscarded: true}
	cv.VLANsSeen = nil
	for v := 4094 - MaxVLANs + 1; v <= 4094; v++ {
		cv.VLANsSeen = append(cv.VLANsSeen, v)
	}
	cv.VLANsOverflow = true
	cv.Degraded = append([]string(nil), Degraded...)
	cv.Settings = Settings{SAReplyTimeoutMS: MaxSAReplyTimeoutMS, MaxPendingDNP3: MaxMaxPendingDNP3, FlowIdleS: MaxFlowIdleS}
	cv.SinceUTC = "2026-11-07T08:00:00.123456789Z"
	cv.Decodes = nil
	for i := 0; ; i++ {
		next := cv
		next.Decodes = append(append([]string(nil), cv.Decodes...), fmt.Sprintf("%064d", i))
		if b, _ := json.Marshal(next); len(b) > MaxCoverageBytes {
			break
		}
		cv = next
	}
	b, _ := json.Marshal(cv)
	if len(b) < MaxCoverageBytes-70 {
		t.Fatalf("worst coverage only %d bytes", len(b))
	}
	return cv
}

// worstObservations are one channel observation of each kind at its
// largest: 8 frames of MaxFrameBytes, each with MaxRedactions, and every
// field at its bound.
func worstObservations(t testing.TB) []*Observation {
	cv := worstCoverage(t)
	var kinds []*Observation
	for _, k := range Kinds {
		o := fxFunction()
		o.Kind, o.Function = k, nil
		o.Seq = "18446744073709551615"
		o.FirstUTC, o.LastUTC = "2026-11-07T10:00:00.123456789Z", "2026-11-07T10:00:01.123456789Z"
		o.ResolutionNS = 1
		o.IP = &IP{Src: worstIP6, Dst: worstIP6, L4: "tcp", Sport: ptr(65535), Dport: ptr(65535)}
		o.L2.EtherType = "0x86dd"
		o.Protocol = worstToken("p")
		o.Coverage = cv
		o.Citation = Citation{CaptureID: "ring:" + fxRun + ":999999999999999999", FramesTotal: 1 << 62}
		o.Frames = nil
		for i := range MaxCitedFrames {
			var rs []Redaction
			for j := range MaxRedactions {
				rs = append(rs, Redaction{Offset: 1000 + j*2, Length: 1, Reason: ReasonCredential})
			}
			data := fxFrame(MaxFrameBytes, 0, 0)
			for _, r := range rs {
				data[r.Offset] = RedactionByte
			}
			n := int64(1<<62) + int64(i)
			o.Citation.Frames = append(o.Citation.Frames, CitedFrame{N: n, CapturedLen: MaxFrameBytes, WireLen: 1 << 30,
				SHA256: hash(data), LAN: "a", Redactions: rs})
			o.Frames = append(o.Frames, Frame{N: n, TS: "2026-11-07T10:00:00.123456789Z", Data: base64.StdEncoding.EncodeToString(data)})
		}
		switch k {
		case KindFlow:
			// client-server and false are the longest direction and the
			// longest syn_only.
			o.Direction = DirectionClientServer
			o.Flow = &Flow{Phase: "end", Packets: 1 << 62, Bytes: 1 << 62, End: "sensor-stop", SynOnly: ptr(false)}
		case KindService:
			o.Service = &Service{Basis: "content", Version: &worstText}
		case KindFunction:
			o.Protocol = "dnp3"
			o.Function = &Function{Code: 254, SA: SAFailed, SAErrorFrom: "outstation"}
			for i := range MaxObjects {
				o.Function.Objects = append(o.Function.Objects, fmt.Sprintf("g%dv255", 100+i))
			}
		case KindInsecure:
			o.Insecure = &Insecure{Reason: "http-plain", Login: &Login{User: &worstText, Attempts: 1 << 62, Slot: "not-placed", Why: worstToken("w")}, RedirectOnly: ptr(true)}
		case KindEncrypted:
			o.Encrypted = &Encrypted{Scheme: "snmpv3", SNMPv3: &SNMPv3{EngineID: strings.Repeat("ab", 32), User: worstText, Level: "noAuthNoPriv", Boots: ptr(int64(1 << 62)), Time: ptr(int64(1 << 62))}}
		case KindIdentity:
			o.Identity = &Identity{Attribute: "snmp-sysdescr", Value: worstText, Via: worstToken("v")}
		case KindUndecoded:
			o.Undecoded = &Undecoded{Basis: "ethertype", Packets: 1 << 62}
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("worst %s: %v", k, err)
		}
		kinds = append(kinds, o)
	}
	// The TLS form of encrypted, which carries an SNI instead.
	tls := *kinds[slicesIndex(Kinds, KindEncrypted)]
	tls.Encrypted = &Encrypted{Scheme: "tls", TLS: &TLS{Version: worstToken("t"), SNI: &worstText}}
	if err := tls.Validate(); err != nil {
		t.Fatal(err)
	}
	return append(kinds, &tls)
}

func slicesIndex(ks []Kind, k Kind) int {
	for i, x := range ks {
		if x == k {
			return i
		}
	}
	return -1
}

// TestWorstObservationFits: the largest channel record fits MaxChannelFrame.
func TestWorstObservationFits(t *testing.T) {
	worst := 0
	for _, o := range worstObservations(t) {
		b := mustJSON(t, o)
		if len(b) > MaxChannelFrame {
			t.Errorf("%s: %d bytes, above MaxChannelFrame %d", o.Kind, len(b), MaxChannelFrame)
		}
		if _, err := DecodeChannel(b); err != nil {
			t.Errorf("%s: %v", o.Kind, err)
		}
		worst = max(worst, len(b))
	}
	t.Logf("worst channel record %d bytes, MaxChannelFrame %d", worst, MaxChannelFrame)
}

// worstStored is o as the node stores it, with every node field set.
func worstStored(o *Observation) *Observation {
	s := *o
	s.Frames = nil
	s.Node = &Node{SrcAsset: fxMaster, DstAsset: fxAsset, ResolvedBy: "ip",
		PlatformSession: &PlatformSession{InvocationID: fxRun, Tie: "connection"},
		EvidenceClass:   "device-observed", StoredCapture: hash(nil)}
	if s.Kind == KindFunction {
		s.Node.FunctionClass, s.Node.FunctionTable = ClassSessionSetup, FunctionTable
		f := *s.Function
		f.SA, f.SAErrorFrom = SANone, ""
		s.Function = &f
		s.Node.DNP3NoSA = ptr(true)
	}
	return &s
}

// TestWorstStoredObservationFits pins C4's MaxNetobsBytes, and checks the
// C4 event the node stores, marshaled, plus the largest capture, fits the
// smallest record cap C5 allows (C13 §10).
func TestWorstStoredObservationFits(t *testing.T) {
	worstBody, worstRecord := 0, 0
	for _, o := range worstObservations(t) {
		s := worstStored(o)
		if err := s.ValidateStored(); err != nil {
			t.Fatalf("%s: %v", s.Kind, err)
		}
		body := mustJSON(t, s)
		e := &event.Event{
			Schema: event.Identifier, ID: event.EventID{NodeID: worstNode, Stream: worstStrm, Seq: ^uint64(0)},
			Origin: event.OriginPlatform, Kind: event.KindNetworkObservation,
			Source:   event.Source{Asset: &event.AssetRef{ID: fxAsset, Binding: event.Binding{Method: "sender-address", Confidence: "inferred"}}, OriginAuth: "platform"},
			Received: event.Received{UTC: "2026-11-07T10:00:01.123456789Z", ResolutionNS: 1, Clock: event.Clock{Sync: "synchronized", Source: worstToken("c")[:32]}},
			Netobs:   body,
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("%s: the C4 event: %v", s.Kind, err)
		}
		stored := mustJSON(t, e)
		if _, err := ObservationFromEvent(e); err != nil {
			t.Fatalf("%s: %v", s.Kind, err)
		}
		record := len(stored) + MaxCaptureBytes
		if record > minRecordBytes {
			t.Errorf("%s: event %d + capture %d = %d bytes, above %d", s.Kind, len(stored), MaxCaptureBytes, record, minRecordBytes)
		}
		worstBody, worstRecord = max(worstBody, len(body)), max(worstRecord, record)
	}
	if worstBody > event.MaxNetobsBytes {
		t.Errorf("worst stored body %d bytes, above C4's MaxNetobsBytes %d", worstBody, event.MaxNetobsBytes)
	}
	t.Logf("worst stored body %d bytes (MaxNetobsBytes %d); worst record %d bytes (cap %d)", worstBody, event.MaxNetobsBytes, worstRecord, minRecordBytes)
}

// TestWorstAlertFits: the largest alert Validate accepts encodes under
// MaxAlertBytes, and its C4 event plus its capture fits the smallest record
// cap C5 allows (C13 §10).
func TestWorstAlertFits(t *testing.T) {
	a := fxAlert()
	a.Rule = RuleOwnSessionOutsideRecord
	a.Params = []Param{{Name: "tie_grace_s", Value: "9223372036854775807"}}
	a.BaselineVersion = 1 << 62
	a.KeyText = strings.Repeat("<", ExplainMax)
	a.BaselineValue = strings.Repeat("<", ExplainMax)
	a.Observation = strings.Repeat("<", ExplainMax)
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
	a.Coverage = worstCoverage(t)
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(h)
	e := &event.Event{
		Schema: event.Identifier, ID: event.EventID{NodeID: worstNode, Stream: worstStrm, Seq: ^uint64(0)},
		Origin: event.OriginPlatform, Kind: event.KindHealth,
		Source:   event.Source{Asset: &event.AssetRef{ID: fxAsset, Binding: event.Binding{Method: "adapter-target", Confidence: "configured"}}, OriginAuth: "platform"},
		Received: event.Received{UTC: "2026-11-07T10:04:01.123456789Z", ResolutionNS: 1, Clock: event.Clock{Sync: "synchronized", Source: worstToken("c")[:32]}},
		Health:   &h,
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the C4 event: %v", err)
	}
	if _, err := AlertFromEvent(e); err != nil {
		t.Fatal(err)
	}
	stored := mustJSON(t, e)
	record := len(stored) + MaxCaptureBytes
	if record > minRecordBytes {
		t.Errorf("event %d + capture %d = %d bytes, above %d", len(stored), MaxCaptureBytes, record, minRecordBytes)
	}
	t.Logf("worst alert health %d bytes (MaxAlertBytes %d); worst record %d bytes (cap %d)", len(body), MaxAlertBytes, record, minRecordBytes)
	a.Observation += "<"
	if _, err := a.Health(); err == nil {
		t.Error("an observation past ExplainMax encoded")
	}
}
