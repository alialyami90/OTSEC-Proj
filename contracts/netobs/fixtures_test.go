package netobs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Constructed fixtures. Every value is illustrative: no sensor produced
// them and no device was contacted.
const (
	fxSensor = "5f0c2a7e-3b1d-4c8e-9a2f-6d4e8b1c7a90"
	fxRun    = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"
	fxAsset  = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	fxMaster = "7c1e5a20-4d3b-4f6a-8b2c-9e0d1f2a3b4c"
)

func ptr[T any](v T) *T { return &v }

func fxCoverage() Coverage {
	return Coverage{
		SensorVersion: "0.1.0", Engine: Engine{Name: "test-engine", Version: "1"},
		Interfaces: []Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
		PRP:        PRP{LANsSeen: []string{}, DuplicatesDiscarded: false},
		HSR:        HSRNotDecoded, VLANsSeen: []int{10}, UntaggedSeen: true,
		Decodes:  []string{"dnp3", "modbus", "telnet"},
		Degraded: []string{},
		Settings: Settings{SAReplyTimeoutMS: DefaultSAReplyTimeoutMS, MaxPendingDNP3: DefaultMaxPendingDNP3, FlowIdleS: DefaultFlowIdleS},
		SinceUTC: "2026-11-07T08:00:00.000000Z",
	}
}

// fxFrame is a stored frame of n bytes whose bytes [off, off+ln) are
// redacted.
func fxFrame(n, off, ln int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	for i := off; i < off+ln; i++ {
		b[i] = RedactionByte
	}
	return b
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fxFunction is a first-sight DNP3 direct operate, challenged, on the
// channel: two frames with their bytes, the second with a redaction.
func fxFunction() *Observation {
	f1, f2 := fxFrame(74, 0, 0), fxFrame(90, 60, 8)
	return &Observation{
		Schema: Identifier, Type: TypeObservation, SensorID: fxSensor, RunID: fxRun, Seq: "42",
		Kind: KindFunction, FirstSight: true,
		FirstUTC: "2026-11-07T10:00:00.000001Z", LastUTC: "2026-11-07T10:00:00.120001Z", ResolutionNS: 1000,
		L2:        L2{SrcMAC: "00:30:a7:00:00:01", DstMAC: "00:30:a7:00:00:02", VLAN: ptr(10), EtherType: "0x0800"},
		IP:        &IP{Src: "192.0.2.10", Dst: "192.0.2.20", L4: "tcp", Sport: ptr(51234), Dport: ptr(20000)},
		Direction: DirectionClientServer, Protocol: "dnp3",
		Citation: Citation{CaptureID: "ring:" + fxRun + ":3", FramesTotal: 2, Frames: []CitedFrame{
			{N: 17, CapturedLen: len(f1), WireLen: len(f1), SHA256: hash(f1)},
			{N: 19, CapturedLen: len(f2), WireLen: len(f2), SHA256: hash(f2),
				Redactions: []Redaction{{Offset: 60, Length: 8, Reason: ReasonCredential}}},
		}},
		Coverage: fxCoverage(),
		Function: &Function{Code: 5, Objects: []string{"g12v1"}, SA: SAChallenged},
		Frames: []Frame{
			{N: 17, TS: "2026-11-07T10:00:00.000001Z", Data: base64.StdEncoding.EncodeToString(f1)},
			{N: 19, TS: "2026-11-07T10:00:00.120001Z", Data: base64.StdEncoding.EncodeToString(f2)},
		},
	}
}

// fxFlow is a flow start that is not a first sight.
func fxFlow() *Observation {
	o := fxFunction()
	o.Kind, o.Function, o.Frames, o.FirstSight, o.Seq = KindFlow, nil, nil, false, "43"
	o.Flow = &Flow{Phase: "start", Packets: 3, Bytes: 222}
	return o
}

// fxStored is fxFunction as the node stores it.
func fxStored() *Observation {
	o := fxFunction()
	o.Frames = nil
	o.Node = &Node{SrcAsset: fxMaster, DstAsset: fxAsset, ResolvedBy: "ip", EvidenceClass: "simulated",
		StoredCapture: hash([]byte("capture")), FunctionClass: ClassControl, FunctionTable: FunctionTable}
	return o
}

func fxHeartbeat() *Heartbeat {
	return &Heartbeat{Schema: Identifier, Type: TypeHeartbeat, SensorID: fxSensor, RunID: fxRun, Seq: "44",
		AtUTC: "2026-11-07T10:00:10.000000Z", Coverage: fxCoverage(),
		Counters:      Counters{Packets: 1000, Bytes: 90000, DropsDriver: ptr(uint64(0))},
		RingOldestUTC: "2026-11-07T09:00:00.000000Z", InterfaceCheck: "ok"}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
