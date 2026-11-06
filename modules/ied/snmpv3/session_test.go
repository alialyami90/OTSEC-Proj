package snmpv3

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

const runID = "sel27x1.snmp.identity"

func session(a *agent) *Session {
	return &Session{Conn: a, Keys: testKeys, EngineID: testEngine, Permit: func([]byte) error { return nil }, Now: time.Now}
}

func run(t *testing.T, a *agent, edit func(p *register.Package)) Outcome {
	t.Helper()
	return session(a).Run(identityPackage(t, edit), runID)
}

func TestRunOK(t *testing.T) {
	a := newAgent(t)
	o := run(t, a, nil)
	if o.Code != "" || !o.Authenticated || !bytes.Equal(o.EngineID, testEngine) {
		t.Fatalf("%s %s, authenticated %v, engine %x", o.Code, o.Detail, o.Authenticated, o.EngineID)
	}
	// Discovery, the time-window Report, then the steps.
	var phases []string
	for _, sg := range o.Segments {
		phases = append(phases, string(sg.Phase)+"/"+string(sg.Dir))
	}
	if got := strings.Join(phases[:6], ","); got != "probe/tx,probe/rx,auth/tx,auth/rx,operate/tx,operate/rx" {
		t.Errorf("phases %s", got)
	}
	// Values: the two system scalars and the whole entPhysicalTable, which
	// ends at the first OID after it.
	var system, entity int
	for _, v := range o.Values {
		switch v.Step {
		case "sel27x1.snmp.system":
			system++
		case "sel27x1.snmp.entity":
			entity++
			if !register.InSubtree(v.OID, "1.3.6.1.2.1.47.1.1.1") {
				t.Errorf("walk kept %s", v.OID)
			}
		}
		sg := o.Segments[v.Segment]
		if sg.Dir != adapter.Received || !bytes.Equal(sg.Bytes[v.Offset:v.Offset+len(v.Content)], v.Content) {
			t.Errorf("%s: the value is not at its offset in a received segment", v.OID)
		}
	}
	if system != 2 || entity != 14 {
		t.Errorf("%d system and %d entity values", system, entity)
	}
	checkTranscript(t, a, o)
}

// checkTranscript holds every stored segment to the transcript form: valid
// SNMPv3 BER with the plaintext scoped PDU and the digest zeroed, and every
// sent PDU a read request.
func checkTranscript(t *testing.T, a *agent, o Outcome) {
	t.Helper()
	sent := 0
	for i, sg := range o.Segments {
		m, err := decodeMessage(sg.Bytes)
		if err != nil {
			t.Errorf("segment %d: %v", i, err)
			continue
		}
		if m.encrypted() || sg.ScopedOff != m.Data.Off {
			t.Errorf("segment %d: msgData is not the plaintext choice", i)
		}
		sc, err := decodeScoped(sg.Bytes[m.Data.Off:])
		if err != nil {
			t.Errorf("segment %d: %v", i, err)
			continue
		}
		if sg.DigestLen != len(m.USM.AuthParams) || (sg.DigestLen > 0 && (sg.DigestOff != m.AuthOff ||
			!bytes.Equal(m.USM.AuthParams, make([]byte, sg.DigestLen)))) {
			t.Errorf("segment %d: the digest is not zeroed in place", i)
		}
		if sg.EngineIDOff != m.EngineIDOff || sg.EngineIDLen != len(m.USM.EngineID) {
			t.Errorf("segment %d: engine ID offset %d, want %d", i, sg.EngineIDOff, m.EngineIDOff)
		}
		if sg.Dir == adapter.Sent {
			switch sc.PDU.Tag {
			case tagGetRequest, tagGetNextRequest, tagGetBulkRequest:
			default:
				t.Errorf("segment %d: sent PDU 0x%02x", i, sc.PDU.Tag)
			}
			// The wire carried a real digest.
			if w, _ := decodeMessage(a.sent[sent]); w.Flags&flagAuth != 0 && bytes.Equal(w.USM.AuthParams, make([]byte, len(w.USM.AuthParams))) {
				t.Errorf("segment %d: sent unsigned", i)
			}
			sent++
		}
	}
	if sent != len(a.sent) {
		t.Errorf("%d sent segments for %d datagrams", sent, len(a.sent))
	}
}

func authSent(a *agent) int {
	n := 0
	for _, b := range a.sent {
		if m, _ := decodeMessage(b); m.Flags&flagAuth != 0 {
			n++
		}
	}
	return n
}

// A different engine ID ends the run before any authenticated message, and
// no key is used (D4-49 Q1).
func TestEngineIDMismatch(t *testing.T) {
	a := newAgent(t)
	a.engineID = mustHex("80007c4f03020000273199")
	o := run(t, a, nil)
	if o.Code != adapter.RefusedEngineIDMismatch || authSent(a) != 0 || !bytes.Equal(o.EngineID, a.engineID) || o.Authenticated {
		t.Fatalf("%s %s; %d authenticated sent", o.Code, o.Detail, authSent(a))
	}
	for _, sg := range o.Segments {
		if sg.Phase != adapter.PhaseProbe {
			t.Errorf("a %s segment after a mismatch", sg.Phase)
		}
	}
}

// The failure Reports end the run with their code even unauthenticated, but
// only when they carry the outstanding msgID (D4-53).
func TestFailureReports(t *testing.T) {
	for o, code := range reportCodes {
		a := newAgent(t)
		a.before = func(m *message, id int64) [][]byte {
			if m.Flags&flagAuth == 0 {
				return nil
			}
			return [][]byte{a.report(id, 0, o, false)}
		}
		if got := run(t, a, nil); got.Code != code {
			t.Errorf("%s: %s %s", o, got.Code, got.Detail)
		}
		// The same Report on another msgID is discarded.
		a = newAgent(t)
		a.before = func(m *message, id int64) [][]byte { return [][]byte{a.report(id+1, 0, o, false)} }
		if got := run(t, a, nil); got.Code != "" {
			t.Errorf("%s on another msgID: %s %s", o, got.Code, got.Detail)
		}
	}
}

// Two Reports are expected, each once and in order; any other Report that
// carries the outstanding msgID ends the session (#437 §4 rule 1, GT-MIB
// U19, C2 0.8).
func TestUnexpectedReports(t *testing.T) {
	cases := []struct {
		name   string
		before func(a *agent) func(*message, int64) [][]byte
	}{
		{"a second usmStatsUnknownEngineIDs, after authentication (U19a)", func(a *agent) func(*message, int64) [][]byte {
			return func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth == 0 || len(a.sent) < 4 {
					return nil
				}
				return [][]byte{a.report(id, 0, oidUnknownEngineIDs, false)}
			}
		}},
		{"a time-window Report answering discovery (U19b)", func(a *agent) func(*message, int64) [][]byte {
			return func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth != 0 {
					return nil
				}
				return [][]byte{a.report(id, 0, oidNotInTimeWindows, false)}
			}
		}},
		{"a failure Report answering discovery", func(a *agent) func(*message, int64) [][]byte {
			return func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth != 0 {
					return nil
				}
				return [][]byte{a.report(id, 0, oidUnknownUserNames, false)}
			}
		}},
		{"a Report this contract does not name", func(a *agent) func(*message, int64) [][]byte {
			return func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth == 0 {
					return nil
				}
				return [][]byte{a.report(id, 0, "1.3.6.1.6.3.11.2.1.3.0", false)} // snmpUnknownPDUHandlers
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAgent(t)
			a.before = c.before(a)
			o := run(t, a, nil)
			if o.Code != adapter.FailedSNMPUnexpectedReport {
				t.Fatalf("%s %s", o.Code, o.Detail)
			}
			if strings.Contains(c.name, "discovery") && (len(o.EngineID) != 0 || len(a.sent) != 1) {
				t.Errorf("engine ID %x adopted, %d sent", o.EngineID, len(a.sent))
			}
			checkTranscript(t, a, o)
		})
	}
}

// An authenticated, encrypted message whose ScopedPDU does not decode ends
// the run, and its decrypted bytes are stored, never the ciphertext
// (GT-MIB §2.6, C2 0.8).
func TestScopedPDUUnreadable(t *testing.T) {
	a := newAgent(t)
	garbage := []byte{0x30, 0x10, 0x04, 0x00} // a SEQUENCE cut short
	a.before = func(m *message, id int64) [][]byte {
		if m.Flags&flagAuth == 0 || len(a.sent) < 3 {
			return nil
		}
		return [][]byte{a.protect(id, garbage, true)}
	}
	o := run(t, a, nil)
	if o.Code != adapter.FailedSNMPScopedPDUUnreadable {
		t.Fatalf("%s %s", o.Code, o.Detail)
	}
	last := o.Segments[len(o.Segments)-1]
	if last.Dir != adapter.Received || !bytes.HasSuffix(last.Bytes, garbage) || last.DigestLen == 0 {
		t.Errorf("the stored message does not end in its decrypted bytes, with the digest zeroed: % x", last.Bytes)
	}
	if !bytes.Equal(last.Bytes[last.DigestOff:last.DigestOff+last.DigestLen], make([]byte, last.DigestLen)) {
		t.Error("the digest is not zeroed")
	}
	// The same bytes unsigned are not trusted: discarded, and the real
	// Response is read.
	a = newAgent(t)
	a.before = func(m *message, id int64) [][]byte {
		if m.Flags&flagAuth == 0 {
			return nil
		}
		return [][]byte{a.protect(id, garbage, false)}
	}
	if o := run(t, a, nil); o.Code != "" {
		t.Errorf("an unsigned message ended the run: %s %s", o.Code, o.Detail)
	}
}

func TestTimeWindow(t *testing.T) {
	a := newAgent(t)
	a.unauthTimeRep = true
	if o := run(t, a, nil); o.Code != adapter.FailedUSMNotInTimeWindow {
		t.Errorf("unauthenticated time-window Report: %s %s", o.Code, o.Detail)
	}
	a = newAgent(t)
	a.timeRepAlways = true
	if o := run(t, a, nil); o.Code != adapter.FailedUSMNotInTimeWindow || len(a.sent) != 3 {
		t.Errorf("a second time-window Report: %s %s, %d sent", o.Code, o.Detail, len(a.sent))
	}
}

func TestErrorStatus(t *testing.T) {
	a := newAgent(t)
	a.errorStatus = 16 // authorizationError
	if o := run(t, a, nil); o.Code != adapter.FailedSNMPErrorStatus {
		t.Errorf("%s %s", o.Code, o.Detail)
	}
}

func TestWalkBounds(t *testing.T) {
	a := newAgent(t)
	a.loopWalk = true
	o := run(t, a, nil)
	if o.Code != adapter.FailedSNMPWalkNotIncreasing {
		t.Errorf("looping agent: %s %s", o.Code, o.Detail)
	}
	// Discovery, time synchronization, the get, then one walk request, not
	// max_requests: the repeat is inside the first response.
	if n := len(a.sent); n != 4 {
		t.Errorf("looping agent: %d requests", n)
	}
	o = run(t, newAgent(t), func(p *register.Package) { p.SNMPOperations[1].Walk.MaxVarbinds = 13 })
	if o.Code != adapter.FailedResponseTooLarge || !strings.Contains(o.Detail, "more than 13") {
		t.Errorf("max_varbinds: %s %s", o.Code, o.Detail)
	}
	o = run(t, newAgent(t), func(p *register.Package) { p.SNMPOperations[1].Walk.MaxRequests = 3 })
	if o.Code != adapter.FailedResponseTooLarge || !strings.Contains(o.Detail, "within 3 requests") {
		t.Errorf("max_requests: %s %s", o.Code, o.Detail)
	}
	// A walk of exactly its varbinds still completes.
	if o = run(t, newAgent(t), func(p *register.Package) { p.SNMPOperations[1].Walk.MaxVarbinds = 14 }); o.Code != "" {
		t.Errorf("exactly max_varbinds: %s %s", o.Code, o.Detail)
	}
	if o = run(t, newAgent(t), func(p *register.Package) {
		for i := range p.SNMPOperations {
			p.SNMPOperations[i].Limits.MaxReplyBytes = 484
		}
		p.Runs[0].MaxTotalBytes = 1000
	}); o.Code != adapter.FailedResponseTooLarge {
		t.Errorf("max_total_bytes: %s %s", o.Code, o.Detail)
	}
}

func TestRetransmission(t *testing.T) {
	a := newAgent(t)
	a.dropFirst = 1
	if o := run(t, a, nil); o.Code != "" {
		t.Fatalf("one drop: %s %s", o.Code, o.Detail)
	}
	m0, _ := decodeMessage(a.sent[0])
	m1, _ := decodeMessage(a.sent[1])
	if m0.MsgID == m1.MsgID {
		t.Error("the retransmission reused its msgID")
	}
	a = newAgent(t)
	a.noAnswer = true
	if o := run(t, a, nil); o.Code != adapter.FailedTimeout || len(a.sent) != 2 {
		t.Errorf("no answer: %s, %d sent", o.Code, len(a.sent))
	}
}

// A response that does not authenticate, or that comes from another engine
// with keys the client does not hold, is discarded, not read (C3 on #445).
func TestUnauthenticatedResponsesDiscarded(t *testing.T) {
	a := newAgent(t)
	a.tamperResponses = true
	o := run(t, a, nil)
	if o.Code != adapter.FailedTimeout || o.Authenticated || len(o.Values) != 0 {
		t.Errorf("tampered: %s, authenticated %v, %d values", o.Code, o.Authenticated, len(o.Values))
	}
	a = newAgent(t)
	forger := newAgent(t)
	forger.engineID = mustHex("80007c4f030200002731ff")
	forger.keys.AuthKey, forger.keys.PrivKey = randomBytes(32), randomBytes(16)
	a.before = func(m *message, id int64) [][]byte {
		if m.Flags&flagPriv == 0 {
			return nil
		}
		sc := scopedOf(forger.engineID, nil, seqOf(tagResponse, intOf(0), intOf(0), intOf(0), seqOf(tagSequence)))
		return [][]byte{forger.protect(id, sc, true)}
	}
	if o = run(t, a, nil); o.Code != "" || len(o.Values) != 16 {
		t.Errorf("forged responses beside real ones: %s %s, %d values", o.Code, o.Detail, len(o.Values))
	}
	// Every later response carries the pinned engine ID (C11 §4 rule 2, GT-MIB
	// U16). One under another engine ID is discarded even when it is signed
	// and encrypted with the pinned keys: those keys belong to the pinned
	// engine alone.
	a = newAgent(t)
	other := newAgent(t)
	other.engineID = mustHex("80007c4f030200002731fe")
	a.before = func(m *message, id int64) [][]byte {
		if m.Flags&flagPriv == 0 {
			return nil
		}
		sc := scopedOf(other.engineID, nil, seqOf(tagResponse, intOf(0), intOf(0), intOf(0), seqOf(tagSequence)))
		return [][]byte{other.protect(id, sc, true)}
	}
	if o = run(t, a, nil); o.Code != "" || len(o.Values) != 16 {
		t.Errorf("responses under another engine ID beside real ones: %s %s, %d values", o.Code, o.Detail, len(o.Values))
	}
	// With the real responses spoiled, those are all that arrive: nothing is
	// read from them.
	a.tamperResponses = true
	if o = run(t, a, nil); o.Code != adapter.FailedTimeout || len(o.Values) != 0 {
		t.Errorf("only responses under another engine ID: %s %s, %d values", o.Code, o.Detail, len(o.Values))
	}
}

func TestRefusesBeforeSending(t *testing.T) {
	a := newAgent(t)
	s := session(a)
	s.Permit = func([]byte) error { return errors.New("refused") }
	if o := s.Run(identityPackage(t, nil), runID); o.Code != adapter.FailedEgressViolation || len(a.sent) != 0 {
		t.Errorf("egress: %s, %d sent", o.Code, len(a.sent))
	}
	for name, k := range map[string]Keys{
		"md5":          {User: "u", Auth: "hmac-md5", AuthKey: make([]byte, 16), Priv: AES128, PrivKey: make([]byte, 16)},
		"sha-1":        {User: "u", Auth: "hmac-sha", AuthKey: make([]byte, 20), Priv: AES128, PrivKey: make([]byte, 16)},
		"des":          {User: "u", Auth: HMACSHA256, AuthKey: make([]byte, 32), Priv: "des", PrivKey: make([]byte, 16)},
		"aes-256":      {User: "u", Auth: HMACSHA256, AuthKey: make([]byte, 32), Priv: "aes-256", PrivKey: make([]byte, 32)},
		"short key":    {User: "u", Auth: HMACSHA512, AuthKey: make([]byte, 32), Priv: AES128, PrivKey: make([]byte, 16)},
		"no user":      {Auth: HMACSHA256, AuthKey: make([]byte, 32), Priv: AES128, PrivKey: make([]byte, 16)},
		"no priv key":  {User: "u", Auth: HMACSHA256, AuthKey: make([]byte, 32), Priv: AES128},
		"no auth":      {User: "u", Priv: AES128, PrivKey: make([]byte, 16)},
		"empty":        {},
		"user too big": {User: strings.Repeat("u", 33), Auth: HMACSHA256, AuthKey: make([]byte, 32), Priv: AES128, PrivKey: make([]byte, 16)},
	} {
		a := newAgent(t)
		s := session(a)
		s.Keys = k
		if o := s.Run(identityPackage(t, nil), runID); o.Code != adapter.FailedInternal || len(a.sent) != 0 {
			t.Errorf("%s: %s, %d sent", name, o.Code, len(a.sent))
		}
	}
	a = newAgent(t)
	if o := session(a).Run(identityPackage(t, nil), "sel27x1.snmp.system"); o.Code != adapter.FailedInternal || len(a.sent) != 0 {
		t.Errorf("an operation named as a run: %s", o.Code)
	}
}

// HMAC-SHA-512 runs the same way, with a 48-octet digest.
func TestSHA512(t *testing.T) {
	a := newAgent(t)
	a.keys.Auth, a.keys.AuthKey = HMACSHA512, bytes.Repeat([]byte{0x33}, 64)
	s := session(a)
	s.Keys = a.keys
	o := s.Run(identityPackage(t, nil), runID)
	if o.Code != "" {
		t.Fatalf("%s %s", o.Code, o.Detail)
	}
	for _, sg := range o.Segments[2:] {
		if sg.DigestLen != 48 {
			t.Errorf("digest of %d octets", sg.DigestLen)
		}
	}
}
