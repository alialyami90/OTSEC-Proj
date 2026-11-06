package snmpv3

import (
	"bytes"
	"testing"
)

// The decoder reads bytes from a device, so it must never panic, index past
// its input or accept a message it cannot re-read. go test runs the seeds;
// go test -fuzz runs more.

func seedMessages(f *testing.F) {
	a := newAgent(nil)
	bulk, _ := requestPDU(tagGetBulkRequest, 9, 0, 4, []string{"1.3.6.1.2.1.47.1.1.1"})
	f.Add(messageOf(1, 484, flagReportable, usmParams{}, scopedOf(nil, nil, bulk)))
	f.Add(a.report(2, 3, oidUnknownEngineIDs, false))
	f.Add(a.report(2, 3, oidNotInTimeWindows, true))
	f.Add(a.response(4, pdu{Tag: tagGetRequest, RequestID: 5, VarBinds: []varbind{{OID: "1.3.6.1.2.1.1.1.0"}}}))
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
}

func FuzzDecodeMessage(f *testing.F) {
	seedMessages(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := decodeMessage(b)
		if err != nil {
			return
		}
		if m.AuthOff < 0 || m.AuthOff+len(m.USM.AuthParams) > len(b) || m.Data.End() != len(b) {
			t.Fatalf("offsets outside the message: %+v", m)
		}
		if !bytes.Equal(b[m.EngineIDOff:m.EngineIDOff+len(m.USM.EngineID)], m.USM.EngineID) {
			t.Fatal("the engine ID is not at its offset")
		}
		if m.encrypted() {
			return
		}
		plain := b[m.Data.Off:m.Data.End()]
		sc, err := decodeScoped(plain)
		if err != nil {
			return
		}
		for _, vb := range sc.PDU.VarBinds {
			if vb.Value.End() > len(plain) || vb.OID == "" {
				t.Fatalf("varbind %+v outside the scoped PDU", vb)
			}
		}
		// The stored form re-reads as the same message.
		out, so, do, dl := storedForm(b, m, plain)
		sm, err := decodeMessage(out)
		if err != nil {
			t.Fatalf("the stored form does not decode: %v", err)
		}
		if sm.MsgID != m.MsgID || !bytes.Equal(out[so:], plain) || (dl > 0 && !bytes.Equal(out[do:do+dl], make([]byte, dl))) {
			t.Fatal("the stored form differs")
		}
	})
}

func FuzzOID(f *testing.F) {
	for _, s := range []string{"1.3.6.1.2.1.1.1.0", "2.999.1", "0.39", "1.3.6.1.4.1.4294967295"} {
		b, _ := oidOf(s)
		f.Add(b[2:])
	}
	f.Add([]byte{0x80})
	f.Add([]byte{0x8f, 0xff, 0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, v []byte) {
		if len(v) > 0x7F {
			return
		}
		s, err := oid(elem{Tag: tagOID, Hdr: 2, Val: v})
		if err != nil {
			return
		}
		b, err := oidOf(s)
		if err != nil {
			t.Fatalf("%s decoded but does not encode: %v", s, err)
		}
		if !bytes.Equal(b[2:], v) {
			t.Fatalf("%x decodes as %s, which encodes as %x", v, s, b[2:])
		}
	})
}
