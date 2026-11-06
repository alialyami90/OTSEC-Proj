package snmpv3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/contracts/register"
)

// A simulated SNMPv3 agent for the session tests. It is built from the same
// reading of RFC 3412, 3414 and 3826 as the client, so it shows the state
// machine and the bounds, not interoperability: that is GT-MIB's agent and,
// later, hardware. Every value in it is invented. Test keys only.

var (
	testEngine = mustHex("80007c4f03020000273101")
	testKeys   = Keys{User: "otsec-ro", Auth: HMACSHA256, AuthKey: bytes.Repeat([]byte{0x11}, 32),
		Priv: AES128, PrivKey: bytes.Repeat([]byte{0x22}, 16)}
	testFID = "SEL-2731M-R102-V1-Z003001-D20260408"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// mibValue is one object: its BER value element, encoded.
type mibValue []byte

func str(s string) mibValue { return tlvOf(tagOctetString, []byte(s)) }

// agent answers requests from a sorted MIB. Its knobs bend it for one case.
type agent struct {
	t        *testing.T
	engineID []byte
	keys     Keys
	boots    int64
	time     int64
	mib      map[string]mibValue

	inbox [][]byte // datagrams waiting for the client's Read
	sent  [][]byte // every request the client wrote

	// Knobs.
	dropFirst       int                                      // drop this many requests unanswered
	before          func(req *message, msgID int64) [][]byte // extra datagrams queued before the answer
	errorStatus     int64                                    // error-status on every Response
	loopWalk        bool                                     // getnext answers with the request's own OID
	unauthTimeRep   bool                                     // the time-window Report is not authenticated
	timeRepAlways   bool                                     // every request gets a time-window Report
	noAnswer        bool
	saltCount       uint64
	tamperResponses bool // flip a ciphertext bit after signing
}

func newAgent(t *testing.T) *agent {
	return &agent{t: t, engineID: testEngine, keys: testKeys, boots: 7, time: 1000, mib: map[string]mibValue{
		"1.3.6.1.2.1.1.1.0":           str("SEL-2731M Ethernet Switch " + testFID),
		"1.3.6.1.2.1.1.5.0":           str("sw-bay-1"),
		"1.3.6.1.2.1.47.1.1.1.1.2.1":  str("SEL-2731M chassis"),
		"1.3.6.1.2.1.47.1.1.1.1.10.1": str(testFID),
		"1.3.6.1.2.1.47.1.1.1.1.13.1": str("SEL-2731M"),
		"1.3.6.1.2.1.47.1.1.1.1.2.2":  str("port 1"),
		"1.3.6.1.2.1.47.1.1.1.1.10.2": str(""),
		"1.3.6.1.2.1.47.1.1.1.1.13.2": str(""),
		"1.3.6.1.2.1.47.1.1.2.1.2.1":  str("after the table"),
		"1.3.6.1.6.3.10.2.1.1.0":      tlvOf(tagOctetString, testEngine),
		"1.3.6.1.2.1.47.1.1.1.1.5.1":  intOf(3),
		"1.3.6.1.2.1.47.1.1.1.1.5.2":  intOf(10),
		"1.3.6.1.2.1.47.1.1.1.1.11.1": str("SN-INVENTED-1"),
		"1.3.6.1.2.1.47.1.1.1.1.11.2": str(""),
		"1.3.6.1.2.1.47.1.1.1.1.12.1": str("SEL"),
		"1.3.6.1.2.1.47.1.1.1.1.12.2": str(""),
		"1.3.6.1.2.1.47.1.1.1.1.16.1": tlvOf(tagInteger, []byte{2}),
		"1.3.6.1.2.1.47.1.1.1.1.16.2": tlvOf(tagInteger, []byte{2}),
	}}
}

func (a *agent) Write(b []byte) error {
	a.sent = append(a.sent, append([]byte(nil), b...))
	if a.noAnswer || a.dropFirst > 0 {
		a.dropFirst--
		return nil
	}
	m, err := decodeMessage(b)
	if err != nil {
		a.t.Fatalf("agent: the client sent a message it cannot decode: %v", err)
	}
	if a.before != nil {
		a.inbox = append(a.inbox, a.before(m, m.MsgID)...)
	}
	a.inbox = append(a.inbox, a.answer(b, m)...)
	return nil
}

func (a *agent) Read(deadline time.Time) ([]byte, error) {
	if len(a.inbox) == 0 {
		return nil, ErrDeadline
	}
	b := a.inbox[0]
	a.inbox = a.inbox[1:]
	return b, nil
}

// answer handles one request as an authoritative engine (RFC 3414 §3.2).
func (a *agent) answer(b []byte, m *message) [][]byte {
	if m.Flags&flagAuth == 0 {
		// Discovery: report usmStatsUnknownEngineIDs, noAuthNoPriv.
		sc, err := decodeScoped(b[m.Data.Off:m.Data.End()])
		if err != nil {
			a.t.Fatalf("agent: discovery scoped PDU: %v", err)
		}
		return [][]byte{a.report(m.MsgID, sc.PDU.RequestID, oidUnknownEngineIDs, false)}
	}
	if !bytes.Equal(m.USM.EngineID, a.engineID) || !a.keys.verify(b, m) {
		return [][]byte{a.report(m.MsgID, 0, oidWrongDigests, false)}
	}
	plain, err := a.keys.cfb(m.USM.Boots, m.USM.Time, m.USM.PrivParams, m.Data.Val, false)
	if err != nil {
		a.t.Fatal(err)
	}
	sc, err := decodeScoped(plain)
	if err != nil {
		return [][]byte{a.report(m.MsgID, 0, oidDecryptionErrors, false)}
	}
	if a.timeRepAlways || m.USM.Boots != a.boots || m.USM.Time < a.time-timeWindow || m.USM.Time > a.time+timeWindow {
		return [][]byte{a.report(m.MsgID, sc.PDU.RequestID, oidNotInTimeWindows, !a.unauthTimeRep)}
	}
	return [][]byte{a.response(m.MsgID, sc.PDU)}
}

func (a *agent) sortedOIDs() []string {
	var out []string
	for o := range a.mib {
		out = append(out, o)
	}
	slices.SortFunc(out, func(x, y string) int {
		switch {
		case oidLess(x, y):
			return -1
		case oidLess(y, x):
			return 1
		}
		return 0
	})
	return out
}

func (a *agent) next(o string) (string, mibValue) {
	if _, seen := a.mib[o]; a.loopWalk && seen {
		return o, a.mib[o] // a looping agent answers with the OID it was asked for
	}
	for _, k := range a.sortedOIDs() {
		if oidLess(o, k) {
			return k, a.mib[k]
		}
	}
	return o, tlvOf(tagEndOfMibView, nil)
}

func (a *agent) response(msgID int64, req pdu) []byte {
	var vbs [][]byte
	add := func(o string, v mibValue) {
		ob, err := oidOf(o)
		if err != nil {
			a.t.Fatal(err)
		}
		vbs = append(vbs, seqOf(tagSequence, ob, v))
	}
	switch req.Tag {
	case tagGetRequest:
		for _, vb := range req.VarBinds {
			if v, ok := a.mib[vb.OID]; ok {
				add(vb.OID, v)
			} else {
				add(vb.OID, tlvOf(tagNoSuchObject, nil))
			}
		}
	case tagGetNextRequest:
		for _, vb := range req.VarBinds {
			add(a.next(vb.OID))
		}
	case tagGetBulkRequest:
		o := req.VarBinds[0].OID
		for range req.ErrIndex {
			k, v := a.next(o)
			add(k, v)
			if v[0] == tagEndOfMibView {
				break
			}
			o = k
		}
	default:
		a.t.Fatalf("agent: the client sent PDU 0x%02x", req.Tag)
	}
	p := seqOf(tagResponse, intOf(req.RequestID), intOf(a.errorStatus), intOf(0), seqOf(tagSequence, vbs...))
	return a.protect(msgID, scopedOf(a.engineID, nil, p), true)
}

// report builds a Report: authNoPriv when auth, else noAuthNoPriv.
func (a *agent) report(msgID, reqID int64, o string, auth bool) []byte {
	ob, _ := oidOf(o)
	p := seqOf(tagReport, intOf(reqID), intOf(0), intOf(0), seqOf(tagSequence, seqOf(tagSequence, ob, tlvOf(tagCounter32, []byte{1}))))
	sc := scopedOf(a.engineID, nil, p)
	if !auth {
		u := usmParams{EngineID: a.engineID, Boots: a.boots, Time: a.time}
		return messageOf(msgID, 1472, 0, u, sc)
	}
	u := usmParams{EngineID: a.engineID, Boots: a.boots, Time: a.time, User: []byte(a.keys.User),
		AuthParams: make([]byte, a.keys.digestLen())}
	w := messageOf(msgID, 1472, flagAuth, u, sc)
	m, _ := decodeMessage(w)
	a.keys.sign(w, m)
	return w
}

// protect builds an authPriv message.
func (a *agent) protect(msgID int64, sc []byte, sign bool) []byte {
	a.saltCount++
	salt := binary.BigEndian.AppendUint64(nil, a.saltCount)
	enc, err := a.keys.cfb(a.boots, a.time, salt, sc, true)
	if err != nil {
		a.t.Fatal(err)
	}
	u := usmParams{EngineID: a.engineID, Boots: a.boots, Time: a.time, User: []byte(a.keys.User),
		AuthParams: make([]byte, a.keys.digestLen()), PrivParams: salt}
	w := messageOf(msgID, 1472, flagAuth|flagPriv, u, tlvOf(tagOctetString, enc))
	m, _ := decodeMessage(w)
	if sign {
		a.keys.sign(w, m)
	}
	if a.tamperResponses {
		w[len(w)-1] ^= 1
	}
	return w
}

// randomBytes is for keys a forger does not hold.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// identityPackage is a C3 0.4 package of the approved text's two example
// operations and their run, with an invented test source.
func identityPackage(t *testing.T, edit func(p *register.Package)) *register.Package {
	t.Helper()
	p := &register.Package{
		Contract: "otsec.register/0.4", Family: "sel-27x1", Revision: 1, Issued: "2026-11-05", Owner: "C2",
		Sources: []register.Source{{ID: "T1", Title: "test source"}},
		SNMPOperations: []register.SNMPOperation{
			{ID: "sel27x1.snmp.system", PDU: register.PDUGet, OIDs: []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"},
				Limits:    &register.Limits{MaxReplyBytes: 1472, TimeoutMS: 3000},
				Citations: []register.Citation{{Source: "T1", Ref: "p. 1"}}, Evidence: register.Evidence{Class: "documented-untested"}, SideEffects: "none"},
			{ID: "sel27x1.snmp.entity", PDU: register.PDUGetBulk, Subtree: "1.3.6.1.2.1.47.1.1.1", MaxRepetitions: 4,
				Walk:      &register.Walk{MaxVarbinds: 512, MaxRequests: 32},
				Limits:    &register.Limits{MaxReplyBytes: 1472, TimeoutMS: 3000},
				Citations: []register.Citation{{Source: "T1", Ref: "p. 1"}}, Evidence: register.Evidence{Class: "documented-untested"}, SideEffects: "none"},
		},
		Runs: []register.Run{{ID: "sel27x1.snmp.identity", Steps: []string{"sel27x1.snmp.system", "sel27x1.snmp.entity"},
			MaxTotalBytes: 65536, DeadlineMS: 30000, Citations: []register.Citation{{Source: "T1", Ref: "p. 1"}},
			Evidence: register.Evidence{Class: "documented-untested"}, SideEffects: "none"}},
		Firmware: register.Firmware{
			Known:    []register.KnownFirmware{{FID: testFID, Branch: "R102", Version: 1, Citation: register.Citation{Source: "T1", Ref: "p. 1"}}},
			Branches: []register.BranchRule{{Branch: "R102", Status: register.BranchAllow, Basis: "test", Evidence: register.Evidence{Class: "documented-untested"}}},
		},
	}
	if edit != nil {
		edit(p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}
