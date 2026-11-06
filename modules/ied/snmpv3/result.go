package snmpv3

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
)

// AdapterID and Version name this build in every result (C2 adapter, A4
// EP-4), as modules/ied/sel751 does.
const (
	AdapterID = "sel-27x1-snmpv3"
	Version   = "0.1.0" // 0.1.0: the SEL-2731M and SEL-2741M identity run over SNMPv3 (P4-3-C2, D4-54)
)

// Meta is what the collector adds to a result: the adapter build, the
// endpoint's target (C1, never what the agent says) and when the run began.
type Meta struct {
	Adapter adapter.AdapterRef
	Target  c1.EvidenceClass
	Started time.Time
}

// Result turns a session's Outcome into the C2 result for inv, run under
// package p. The identity is compared here: the engine ID read at discovery
// first, then, once every step completed, the FID read from an
// authenticated answer.
//   - No FID, or two different ones: failed.snmp_fid_unreadable (D4-54).
//   - A FID that differs from the declared one: failed.identity_mismatch.
//     That suspends the asset, not the credential (C1 on #445).
//
// A FID, model or firmware version is reported only when the FID was
// compared and matched, or when none was declared. The engine ID and the
// hostname come from authenticated answers, so they are reported whenever
// they were read.
func Result(o Outcome, inv adapter.Invocation, p *register.Package, m Meta) adapter.Result {
	r := adapter.Result{
		Schema: adapter.Contract, InvocationID: inv.InvocationID, OperationID: inv.OperationID,
		Adapter: m.Adapter, RegisterVersion: p.Revision, Target: m.Target,
		StartedAt: stamp(m.Started), EndedAt: stamp(m.Started),
		Session: adapter.SessionFacts{LanguageProbe: adapter.ProbeNotRun, EchoScan: adapter.EchoScanNotApplicable,
			SNMP: &adapter.SNMPFacts{EngineID: hex.EncodeToString(o.EngineID), Authenticated: o.Authenticated}},
	}
	base := make([]int64, len(o.Segments)) // where each segment starts in Data
	for i, sg := range o.Segments {
		base[i] = int64(len(r.Transcript.Data))
		r.Transcript.Data = append(r.Transcript.Data, sg.Bytes...)
		r.Transcript.Segments = append(r.Transcript.Segments, adapter.Segment{Offset: base[i], Length: int64(len(sg.Bytes)),
			Dir: sg.Dir, Phase: sg.Phase, At: stamp(sg.At)})
		if sg.DigestLen > 0 {
			r.Transcript.Redactions = append(r.Transcript.Redactions, adapter.Redaction{Offset: base[i] + int64(sg.DigestOff),
				Length: int64(sg.DigestLen), Reason: adapter.RedactUSMDigest, Component: "transport"})
		}
		r.Session.Connected = r.Session.Connected || sg.Dir == adapter.Sent
		r.EndedAt = stamp(sg.At)
	}
	sum := sha256.Sum256(r.Transcript.Data)
	r.Transcript.SHA256 = hex.EncodeToString(sum[:])
	span := func(seg, off, n int) adapter.Span {
		return adapter.Span{Offset: base[seg] + int64(off), Length: int64(n)}
	}

	expected := map[string]string{}
	for _, e := range inv.Expected {
		expected[e.Name] = e.Value
	}
	// The engine ID item: the first discovery answer that carried the
	// engine ID the session took.
	var items []adapter.IdentityItem
	for i, sg := range o.Segments {
		if o.EngineID != nil && sg.Dir == adapter.Received && sg.Phase == adapter.PhaseProbe && sg.EngineIDOff >= 0 &&
			string(sg.Bytes[sg.EngineIDOff:sg.EngineIDOff+sg.EngineIDLen]) == string(o.EngineID) {
			items = append(items, adapter.IdentityItem{Name: c1.AttrSNMPEngineID, Expected: expected[c1.AttrSNMPEngineID],
				Observed: hex.EncodeToString(o.EngineID), Span: span(i, sg.EngineIDOff, sg.EngineIDLen)})
			break
		}
	}

	code, detail := o.Code, o.Detail
	obs, missing := Identity(o)
	fidRead := false
	if code == "" {
		switch fid, want := find(obs, c1.AttrFirmwareID), expected[c1.AttrFirmwareID]; {
		case len(missing) > 0:
			code, detail = adapter.FailedSNMPFIDUnreadable, missing[0]
		case want == "":
			fidRead = true
		default:
			items = append(items, adapter.IdentityItem{Name: c1.AttrFirmwareID, Expected: want, Observed: fid.Value,
				Span: span(fid.Segment, fid.Offset, fid.Length)})
			if fid.Value != want {
				code, detail = adapter.FailedIdentityMismatchLate, "the FID read is not the declared one"
			}
			fidRead = code == ""
		}
	}

	r.Identity.Result = adapter.IdentityNotChecked
	if len(items) > 0 {
		r.Identity.Result, r.Identity.Items = adapter.IdentityMatch, items
		for _, it := range items {
			if it.Expected != it.Observed {
				r.Identity.Result = adapter.IdentityMismatch
			}
		}
	}

	for _, ob := range obs {
		switch ob.Name {
		case c1.AttrFirmwareID, c1.AttrModel, c1.AttrFirmwareVersion:
			if !fidRead {
				continue
			}
		}
		step := ""
		for _, v := range o.Values {
			if v.Segment == ob.Segment && (ob.OID == "" || v.OID == ob.OID) {
				step = v.Step
				break
			}
		}
		if step == "" {
			continue
		}
		r.Observations = append(r.Observations, adapter.Observation{Name: ob.Name, Value: ob.Value,
			Span: span(ob.Segment, ob.Offset, ob.Length), Read: &adapter.Read{Operation: step, OID: ob.OID, Header: ob.Header}})
	}

	r.Status = adapter.StatusOK
	if code != "" {
		r.Status, r.Error = code.Status(), &adapter.Error{Code: code, Detail: detail}
	}
	return r
}

func find(obs []Observation, name string) Observation {
	for _, ob := range obs {
		if ob.Name == name {
			return ob
		}
	}
	return Observation{}
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
