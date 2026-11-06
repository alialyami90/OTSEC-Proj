package snmpv3

// C6's case for #453: a datagram flagged authPriv whose msgData is a
// plaintext ScopedPDU, not an encryptedPDU. It needs no key and no digest:
// anyone who can send from the endpoint's address can send it. Evidence
// class: simulated (the package's own agent, no device).

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
)

// The client must neither trust such a message nor store it in the form of
// an authenticated, decrypted Response (RFC 3412 §7.2: with privacy, msgData
// is the encryptedPDU). Otherwise the transcript shows a message nobody
// authenticated as if it were one, and Identity, which reads the engine ID
// from the first stored authPriv Response, takes the forged header and the
// result loses its snmp_engine_id observation while the run reports ok.
func TestC6PlaintextUnderPrivIsNotTrusted(t *testing.T) {
	a := newAgent(t)
	forged := mustHex("80007c4f030200002731ff")
	sent := 0
	a.before = func(m *message, id int64) [][]byte {
		if m.Flags&flagPriv == 0 || sent > 0 {
			return nil
		}
		sent++
		sc := scopedOf(forged, nil, seqOf(tagResponse, intOf(0), intOf(0), intOf(0), seqOf(tagSequence)))
		u := usmParams{EngineID: forged, Boots: 7, Time: 1000, User: []byte(testKeys.User),
			AuthParams: make([]byte, testKeys.digestLen()), PrivParams: make([]byte, 8)}
		return [][]byte{messageOf(id, 1472, flagAuth|flagPriv, u, sc)}
	}
	o := run(t, a, nil)
	if o.Code != "" || len(o.Values) != 16 || sent != 1 {
		t.Fatalf("%s %s, %d values, %d forged", o.Code, o.Detail, len(o.Values), sent)
	}
	for i, sg := range o.Segments {
		if sg.Dir == adapter.Received && sg.EngineIDOff >= 0 && bytes.Equal(sg.Bytes[sg.EngineIDOff:sg.EngineIDOff+sg.EngineIDLen], forged) && sg.ScopedOff >= 0 {
			t.Errorf("segment %d: the forged message is stored in the authenticated form, its scoped PDU at %d", i, sg.ScopedOff)
		}
	}
	obs, _ := Identity(o)
	for _, ob := range obs {
		if ob.Name == c1.AttrSNMPEngineID && ob.Value != hex.EncodeToString(testEngine) {
			t.Errorf("Identity took the engine ID %s from an unauthenticated message", ob.Value)
		}
	}
	r := Result(o, invocation(testFID), identityPackage(t, nil), Meta{Target: c1.Simulated, Started: time.Now()})
	var got []string
	for _, ob := range r.Observations {
		if ob.Name == c1.AttrSNMPEngineID {
			got = append(got, ob.Value)
		}
	}
	if r.Status != adapter.StatusOK || len(got) != 1 || got[0] != hex.EncodeToString(testEngine) {
		t.Errorf("status %s, snmp_engine_id observations %v, want the pinned engine ID once", r.Status, got)
	}
}
