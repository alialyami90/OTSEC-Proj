package snmpv3

import (
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// A noError Response to a Get or GetNext must carry one binding for each of
// the request's (RFC 3416 §4.2.1, §4.2.2). Any other count ends the run with
// failed.snmp_varbinds_mismatch, the bytes kept, and no binding of that
// Response gives a value (C2 0.9, D4-60).
func TestVarbindsMismatch(t *testing.T) {
	getNext := func(p *register.Package) {
		op := &p.SNMPOperations[1]
		op.PDU, op.MaxRepetitions = register.PDUGetNext, 0
	}
	for name, c := range map[string]struct {
		tag   byte
		delta int
		edit  func(p *register.Package)
		kept  int // values kept before the Response that ends the run
	}{
		"get answered with one of two": {tagGetRequest, -1, nil, 0},
		"get answered with three":      {tagGetRequest, 1, nil, 0},
		"getnext answered with none":   {tagGetNextRequest, -1, getNext, 2},
		"getnext answered with two":    {tagGetNextRequest, 1, getNext, 2},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAgent(t)
			a.countTag, a.countDelta = c.tag, c.delta
			o := run(t, a, c.edit)
			if o.Code != adapter.FailedSNMPVarbindsMismatch {
				t.Fatalf("%s %s", o.Code, o.Detail)
			}
			if len(o.Values) != c.kept {
				t.Errorf("%d values kept, want %d: those of earlier Responses only", len(o.Values), c.kept)
			}
			last := o.Segments[len(o.Segments)-1]
			if last.Dir != adapter.Received || last.Phase != adapter.PhaseOperate {
				t.Errorf("the Response is not kept: last segment %s %s", last.Dir, last.Phase)
			}
		})
	}
	// A GetNext walk with one binding each time still completes.
	if o := run(t, newAgent(t), func(p *register.Package) {
		op := &p.SNMPOperations[1]
		op.PDU, op.MaxRepetitions = register.PDUGetNext, 0
	}); o.Code != "" {
		t.Errorf("a well-formed getnext walk: %s %s", o.Code, o.Detail)
	}
}

// A Conn without an IP local address sends nothing: the run could not be
// tied to its flow (C2 0.9).
func TestNoLocalAddress(t *testing.T) {
	a := newAgent(t)
	s := session(a)
	s.Conn = noAddr{a}
	if o := s.Run(identityPackage(t, nil), runID); o.Code != adapter.FailedInternal || len(a.sent) != 0 {
		t.Errorf("%s %s, %d sent", o.Code, o.Detail, len(a.sent))
	}
}

type noAddr struct{ *agent }

func (noAddr) LocalAddr() string { return "[::ffff:192.0.2.10]:40161" }
