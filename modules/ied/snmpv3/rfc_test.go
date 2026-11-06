package snmpv3

import (
	"bytes"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// Tests from D2's check of the client against the RFC texts
// (docs/phase4/D2-snmpv3-rfc-check.md). Each names the section it holds the
// client to.

// RFC 3417 §8.1: the example GetBulkRequest decodes, and the client encodes
// the same PDU with the minimal length (the example's a5 82 00 39 uses more
// length octets than it needs, which §8 (1) permits).
func TestRFC3417Example(t *testing.T) {
	example := mustHex("a5820039" + "020454525d76" + "020101" + "020102" + "302b" +
		"300b" + "06072b060102010103" + "0500" +
		"300d" + "06092b0601020104160102" + "0500" +
		"300d" + "06092b0601020104160104" + "0500")
	sc, err := decodeScoped(scopedOf(nil, nil, example))
	if err != nil {
		t.Fatal(err)
	}
	oids := []string{"1.3.6.1.2.1.1.3", "1.3.6.1.2.1.4.22.1.2", "1.3.6.1.2.1.4.22.1.4"}
	p := sc.PDU
	if p.Tag != tagGetBulkRequest || p.RequestID != 1414684022 || p.ErrStatus != 1 || p.ErrIndex != 2 || len(p.VarBinds) != 3 {
		t.Fatalf("%+v", p)
	}
	for i, vb := range p.VarBinds {
		if vb.OID != oids[i] || vb.Value.Tag != tagNull {
			t.Errorf("varbind %d: %s 0x%02x", i, vb.OID, vb.Value.Tag)
		}
	}
	got, err := requestPDU(tagGetBulkRequest, 1414684022, 1, 2, oids)
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{0xa5, 0x39}, example[4:]...); !bytes.Equal(got, want) {
		t.Errorf("encoded\n% x\nwant\n% x", got, want)
	}
}

// RFC 3416 §3 gives request-id the range -214783648..214783647 as printed.
// The client's request-ids are inside it, so an agent that holds to the
// printed range accepts every request.
func TestRequestIDRange(t *testing.T) {
	a := newAgent(t)
	o := run(t, a, nil)
	if o.Code != "" {
		t.Fatalf("%s %s", o.Code, o.Detail)
	}
	n := 0
	for _, sg := range o.Segments {
		if sg.Dir != adapter.Sent {
			continue
		}
		sc, err := decodeScoped(sg.Bytes[sg.ScopedOff:])
		if err != nil {
			t.Fatal(err)
		}
		if id := sc.PDU.RequestID; id < 0 || id > 214783647 {
			t.Errorf("request-id %d", id)
		}
		n++
	}
	if n < 5 {
		t.Fatalf("%d requests", n)
	}
}

// RFC 3416 §4.2.3: a GetBulk Response may hold fewer varbinds than asked,
// possibly none, when the full one would not fit the message size. With
// max-repetitions at least 1 and one repeated varbind, none can only mean
// that, so it never ends a walk as complete.
func TestGetBulkEmptyResponse(t *testing.T) {
	a := newAgent(t)
	a.emptyBulk = true
	o := run(t, a, nil)
	if o.Code != adapter.FailedResponseTooLarge {
		t.Fatalf("%s %s", o.Code, o.Detail)
	}
	checkTranscript(t, a, o)
}

// RFC 3412 §7.2 step 12 b): a Response whose contextEngineID or contextName
// differs from the outstanding request's is discarded.
func TestResponseContext(t *testing.T) {
	for name, edit := range map[string]func(a *agent){
		"contextEngineID": func(a *agent) { a.ctxEngineID = mustHex("80007c4f03020000273199") },
		"contextName":     func(a *agent) { a.ctxName = []byte("other") },
	} {
		t.Run(name, func(t *testing.T) {
			a := newAgent(t)
			edit(a)
			o := run(t, a, nil)
			if o.Code != adapter.FailedTimeout || len(o.Values) != 0 {
				t.Fatalf("%s %s, %d values", o.Code, o.Detail, len(o.Values))
			}
		})
	}
}

// RFC 3826 §3.3.2 step 1: msgPrivacyParameters that is not 8 octets is a
// decryption error, so the message is discarded. It does not end the run as
// an unreadable ScopedPDU: nothing was decrypted (D4-54 keeps decrypted
// bytes).
func TestPrivacyParametersLength(t *testing.T) {
	a := newAgent(t)
	a.shortSalt = true
	o := run(t, a, nil)
	if o.Code != adapter.FailedTimeout || len(o.Values) != 0 {
		t.Fatalf("%s %s", o.Code, o.Detail)
	}
}

// RFC 3414 §3.2 step 7 b): the non-authoritative side takes the agent's
// boots and time from any authentic message newer than the latest it
// received (latestReceivedEngineTime), and only then checks the window.
// Here the collector's clock runs 40 s per request while the agent's runs
// 1 s per Response: without the update, the client's notion runs ahead of
// the agent's window and the agent refuses its requests.
func TestTimeWindowLatestReceived(t *testing.T) {
	a := newAgent(t)
	a.tick = 1
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	c := &clockConn{agent: a, now: &now, step: 40 * time.Second}
	s := session(a)
	s.Conn, s.Now = c, func() time.Time { return now }
	o := s.Run(identityPackage(t, func(p *register.Package) { p.Runs[0].DeadlineMS = register.MaxDeadlineMS }), runID)
	if o.Code != "" {
		t.Fatalf("%s %s, %d sent", o.Code, o.Detail, len(a.sent))
	}
}

// RFC 3414 §3.2 step 7 b) 2): with the local notion of boots at 2147483647
// every message is outside the window.
func TestTimeWindowBootsMax(t *testing.T) {
	st := &state{s: &Session{Now: time.Now}, synced: true, boots: 0x7FFFFFFF, agentTime: 10, syncedAt: time.Now()}
	if st.inWindow(&message{USM: usmParams{Boots: 0x7FFFFFFF, Time: 20}}) {
		t.Error("accepted at boots 2147483647")
	}
	st = &state{s: &Session{Now: time.Now}, synced: true, boots: 5, agentTime: 1000, syncedAt: time.Now()}
	for _, c := range []struct {
		boots, time int64
		in          bool
	}{{5, 1000, true}, {5, 851, true}, {5, 849, false}, {4, 2000, false}, {6, 0, true}} {
		if got := st.inWindow(&message{USM: usmParams{Boots: c.boots, Time: c.time}}); got != c.in {
			t.Errorf("boots %d time %d: in window %v", c.boots, c.time, got)
		}
	}
}

// RFC 3411 §5: an SnmpEngineID is never all zeros or all 'ff'H, so a pinned
// one of that form is refused before anything is sent.
func TestPinnedEngineIDForm(t *testing.T) {
	for _, e := range [][]byte{make([]byte, 5), bytes.Repeat([]byte{0xff}, 12)} {
		a := newAgent(t)
		a.engineID = e
		s := session(a)
		s.EngineID = e
		if o := s.Run(identityPackage(t, nil), runID); o.Code != adapter.FailedInternal || len(a.sent) != 0 {
			t.Errorf("%x: %s %s, %d sent", e, o.Code, o.Detail, len(a.sent))
		}
	}
}

// clockConn advances the session clock by step on every write.
type clockConn struct {
	agent *agent
	now   *time.Time
	step  time.Duration
}

func (c *clockConn) Write(b []byte) error {
	*c.now = c.now.Add(c.step)
	return c.agent.Write(b)
}

func (c *clockConn) Read(deadline time.Time) ([]byte, error) { return c.agent.Read(deadline) }

// RFC 3414 §3.2 step 7 b): the time-window Report's boots and time are the
// latest received, so an older authentic message neither moves the notion of
// time back nor escapes the window (D6 on #495).
func TestTimeWindowAfterReport(t *testing.T) {
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	st := &state{s: &Session{Now: func() time.Time { return now }}}
	r := &reply{m: &message{USM: usmParams{Boots: 5, Time: 1000}}, authed: true,
		sc: &scoped{PDU: pdu{Tag: tagReport, VarBinds: []varbind{{OID: oidNotInTimeWindows}}}}}
	if err := st.report(r, false); err != nil || !r.timeRep {
		t.Fatalf("the time-window Report was not adopted: %v", err)
	}
	if !st.inWindow(&message{USM: usmParams{Boots: 5, Time: 900}}) || st.agentTime != 1000 {
		t.Errorf("time 900: notion moved to %d", st.agentTime)
	}
	if st.inWindow(&message{USM: usmParams{Boots: 5, Time: 800}}) {
		t.Error("time 800 accepted, more than 150 s before 1000")
	}
}
