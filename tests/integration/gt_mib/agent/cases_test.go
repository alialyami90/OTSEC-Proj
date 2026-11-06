package agent

// Each case's agent does what ../cases.json says it does. The runner checks
// the client against these behaviours, so they are tested here first, with
// the test manager of agent_test.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"testing"
)

type table struct {
	Cases []struct {
		ID string `json:"id"`
	} `json:"cases"`
	Hostile struct {
		Layers []string `json:"layers"`
		Corpus []struct {
			ID     string   `json:"id"`
			Layers []string `json:"layers"`
		} `json:"corpus"`
		Positive []struct {
			ID     string   `json:"id"`
			Layers []string `json:"layers"`
		} `json:"positive"`
	} `json:"hostile"`
}

// tableIDs are the case IDs ../cases.json names: each case, and each
// hostile or positive entry at each of its layers ("H0" has none).
func tableIDs(t *testing.T) []string {
	b, err := os.ReadFile("../cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var g table
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range g.Cases {
		ids = append(ids, c.ID)
	}
	for _, h := range append(g.Hostile.Corpus, g.Hostile.Positive...) {
		ls := h.Layers
		if ls == nil && h.ID != "H0" {
			ls = g.Hostile.Layers
		}
		if ls == nil {
			ids = append(ids, h.ID)
		}
		for _, l := range ls {
			ids = append(ids, h.ID+"/"+l)
		}
	}
	sort.Strings(ids)
	return ids
}

func TestEveryTableCaseIsKnown(t *testing.T) {
	want, got := tableIDs(t), Cases()
	if fmt.Sprint(want) != fmt.Sprint(got) {
		t.Errorf("the table names %v\nthe agent knows %v", want, got)
	}
	for _, id := range got {
		if _, err := NewCase(id, testSpec(t)); err != nil {
			t.Error(err)
		}
	}
	if _, err := NewCase("X9", testSpec(t)); err == nil {
		t.Error("an unknown case was accepted")
	}
}

// flow is one manager run against case id: discovery, the time-window
// round, a get and its retransmission, then three GetBulk requests (the
// second a retransmission of the first). Every step is sent whatever the
// one before it got, to show the agent's behaviour at each.
type flow struct {
	a                *Agent
	c                *mgr
	disc, tw, g1, g2 []rx
	b1, b2, b3       []rx
	reqMsgID         int64 // the time-window round's msgID
}

func runFlow(t *testing.T, id string) *flow {
	spec := testSpec(t)
	a := start(t, id, spec)
	f := &flow{a: a}
	f.again(t, spec)
	return f
}

func (f *flow) again(t *testing.T, spec Spec) {
	c := newMgr(t, f.a, spec)
	f.c = c
	f.disc = c.discover()
	if c.engine == nil { // silent at discovery: go on with the pinned one
		c.engine = spec.EngineID
		c.u = NewUser(spec.User, spec.Auth, true, spec.Password, c.engine)
	}
	f.tw = c.request(get(2, SysDescr, SysName))
	f.reqMsgID = c.msgID
	c.adopt(f.tw)
	f.g1 = c.request(get(3, SysDescr, SysName))
	f.g2 = c.request(get(3, SysDescr, SysName))
	f.b1 = c.request(bulk(4, EntPhysicalTable))
	f.b2 = c.request(bulk(4, EntPhysicalTable))
	f.b3 = c.request(bulk(5, EntPhysicalTable))
}

func one(t *testing.T, step string, rs []rx) rx {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("%s: %d datagrams, want 1: %+v", step, len(rs), rs)
	}
	return rs[0]
}

func none(t *testing.T, step string, rs []rx) {
	t.Helper()
	if len(rs) != 0 {
		t.Fatalf("%s: %d datagrams, want none", step, len(rs))
	}
}

func flagsOf(r rx) byte { return r.m.Flags & 0x03 }

func wantReport(t *testing.T, step string, r rx, oid string, flags byte) {
	t.Helper()
	if reportOID(r) != oid || flagsOf(r) != flags {
		t.Fatalf("%s: Report %q at flags %d, want %q at %d", step, reportOID(r), flagsOf(r), oid, flags)
	}
}

func wantResponse(t *testing.T, step string, r rx) {
	t.Helper()
	if r.s == nil || r.s.PDU.Tag != PDUResponse || flagsOf(r) != FlagAuth|FlagPriv || !r.authed {
		t.Fatalf("%s: not an authenticated authPriv Response: %+v", step, r)
	}
}

const authPriv = FlagAuth | FlagPriv

// The time-window round and the get, as the default agent answers them.
func defaultStart(t *testing.T, f *flow) {
	t.Helper()
	wantReport(t, "discovery", one(t, "discovery", f.disc), UsmStatsUnknownEngineIDs, 0)
	wantReport(t, "time window", one(t, "time window", f.tw), UsmStatsNotInTimeWindows, FlagAuth)
}

var behaviour = map[string]func(t *testing.T, f *flow){
	"U1": func(t *testing.T, f *flow) {
		d := one(t, "discovery", f.disc)
		if bytes.Equal(d.m.EngineID, testEngine) || len(d.m.EngineID) != len(testEngine) {
			t.Errorf("discovery engine %x, want one other than the pinned %x", d.m.EngineID, testEngine)
		}
	},
	"U2":  func(t *testing.T, f *flow) { wantReport(t, "tw", one(t, "tw", f.tw), UsmStatsWrongDigests, 0) },
	"U3":  func(t *testing.T, f *flow) { wantReport(t, "tw", one(t, "tw", f.tw), UsmStatsUnknownUserNames, 0) },
	"U4a": func(t *testing.T, f *flow) { wantReport(t, "tw", one(t, "tw", f.tw), UsmStatsWrongDigests, 0) },
	"U4b": func(t *testing.T, f *flow) {
		wantReport(t, "discovery", one(t, "discovery", f.disc), UsmStatsUnknownEngineIDs, 0)
		none(t, "tw", f.tw)
		none(t, "get", f.g1)
	},
	"U5": func(t *testing.T, f *flow) { wantReport(t, "tw", one(t, "tw", f.tw), UsmStatsUnsupportedSecLevels, 0) },
	"U6": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		wantReport(t, "get", one(t, "get", f.g1), UsmStatsDecryptionErrors, 0)
	},
	"U7": func(t *testing.T, f *flow) { defaultStart(t, f); wantResponse(t, "get", one(t, "get", f.g1)) },
	"U7b": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		none(t, "get", f.g1)
		wantResponse(t, "retransmission", one(t, "retransmission", f.g2))
	},
	"U8": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		wantReport(t, "get", one(t, "get", f.g1), UsmStatsNotInTimeWindows, FlagAuth)
	},
	"U9": func(t *testing.T, f *flow) {
		r := one(t, "tw", f.tw)
		wantReport(t, "tw", r, UsmStatsNotInTimeWindows, 0)
	},
	"U10": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		if r := one(t, "get", f.g1); flagsOf(r) != 0 || r.s == nil || r.s.PDU.Tag != PDUResponse {
			t.Fatalf("get: %+v", r)
		}
	},
	"U11": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		if r := one(t, "get", f.g1); flagsOf(r) != authPriv || r.authed {
			t.Fatalf("get: flags %d authed %v", flagsOf(r), r.authed)
		}
		none(t, "retransmission", f.g2)
	},
	"U12": func(t *testing.T, f *flow) { none(t, "discovery", f.disc); none(t, "tw", f.tw) },
	"U15": func(t *testing.T, f *flow) {
		if len(f.tw) != 2 {
			t.Fatalf("tw: %d datagrams", len(f.tw))
		}
		wantReport(t, "forged", f.tw[0], UsmStatsWrongDigests, 0)
		if f.tw[0].m.MsgID != f.reqMsgID {
			t.Errorf("forged msgID %d, the request's %d", f.tw[0].m.MsgID, f.reqMsgID)
		}
		wantReport(t, "tw", f.tw[1], UsmStatsNotInTimeWindows, FlagAuth)
		f.again(t, f.c.spec) // the next run is the default
		defaultStart(t, f)
		wantResponse(t, "next run's get", one(t, "get", f.g1))
	},
	"U16": func(t *testing.T, f *flow) {
		if len(f.tw) != 3 {
			t.Fatalf("tw: %d datagrams", len(f.tw))
		}
		wantReport(t, "forged", f.tw[0], UsmStatsWrongDigests, 0)
		if f.tw[0].m.MsgID == f.reqMsgID {
			t.Error("the first forged Report has the request's msgID")
		}
		wantReport(t, "forged from another port", f.tw[1], UsmStatsWrongDigests, 0)
		if f.tw[1].m.MsgID != f.reqMsgID || f.tw[1].from.Port == f.a.Addr().Port {
			t.Errorf("second forged Report: msgID %d from %v", f.tw[1].m.MsgID, f.tw[1].from)
		}
		wantReport(t, "tw", f.tw[2], UsmStatsNotInTimeWindows, FlagAuth)
		wantResponse(t, "get", one(t, "get", f.g1))
	},
	"U17": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		if r := one(t, "get", f.g1); flagsOf(r) != FlagAuth || !r.authed || r.s == nil || r.s.PDU.Tag != PDUResponse {
			t.Fatalf("get: flags %d authed %v", flagsOf(r), r.authed)
		}
	},
	"U18": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		if r := one(t, "get", f.g1); bytes.Equal(r.m.EngineID, testEngine) {
			t.Fatal("the Response carries the pinned engine ID")
		}
	},
	"U19a": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		wantReport(t, "get", one(t, "get", f.g1), UsmStatsUnknownEngineIDs, 0)
	},
	"U19b": func(t *testing.T, f *flow) {
		if len(f.disc) != 2 {
			t.Fatalf("discovery: %d datagrams", len(f.disc))
		}
		wantReport(t, "first", f.disc[0], UsmStatsNotInTimeWindows, 0)
		wantReport(t, "second", f.disc[1], UsmStatsUnknownEngineIDs, 0)
	},
	"U20": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		if len(f.g1) != 3 {
			t.Fatalf("get: %d datagrams", len(f.g1))
		}
		b, tm := f.tw[0].m.Boots, f.tw[0].m.Time
		wantResponse(t, "lower boots", f.g1[0])
		wantResponse(t, "older time", f.g1[1])
		wantReport(t, "lower-boots Report", f.g1[2], UsmStatsNotInTimeWindows, FlagAuth)
		if f.g1[0].m.Boots != b-1 || f.g1[1].m.Time > tm-TimeWindow || f.g1[2].m.Boots != b-1 || !f.g1[2].authed {
			t.Errorf("boots %d time %d after (%d, %d)", f.g1[0].m.Boots, f.g1[1].m.Time, b, tm)
		}
	},
	"W1": func(t *testing.T, f *flow) {
		wantResponse(t, "bulk", one(t, "bulk", f.b1))
		b := one(t, "bulk at the FID", f.c.request(bulk(6, EntCol(9, 6)))).s.PDU.Binds
		if len(b) < 3 || b[0].OID != EntCol(10, 1) || b[1].OID != outside || !Under(b[2].OID, EntPhysicalTable) {
			t.Fatalf("bulk: %+v", b)
		}
	},
	"W2": func(t *testing.T, f *flow) {
		if b := one(t, "bulk", f.b1).s.PDU.Binds; b[1].OID != b[0].OID {
			t.Fatal("no repeated OID")
		}
	},
	"W3": func(t *testing.T, f *flow) {
		if b := one(t, "bulk", f.b1).s.PDU.Binds; b[2].OID != b[0].OID || b[1].OID == b[0].OID {
			t.Fatal("no earlier OID")
		}
	},
	"W4": func(t *testing.T, f *flow) {
		n := 0
		for _, v := range f.a.MIB().Vars() {
			if Under(v.OID, EntPhysicalTable) {
				n++
			}
		}
		if n != 720 {
			t.Fatalf("%d cells, want 40 x 18 = 720", n)
		}
	},
	"W5": func(t *testing.T, f *flow) {
		for _, rs := range [][]rx{f.b1, f.b2, f.b3} {
			if n := len(one(t, "bulk", rs).s.PDU.Binds); n != 1 {
				t.Fatalf("%d varbinds", n)
			}
		}
	},
	"W6": func(t *testing.T, f *flow) {
		if r := one(t, "bulk", f.b1); len(r.raw) > 1472 || len(r.s.PDU.Binds) < 2 {
			t.Fatalf("%d bytes, %d varbinds", len(r.raw), len(r.s.PDU.Binds))
		}
	},
	"W7": func(t *testing.T, f *flow) {
		if r := one(t, "bulk", f.b1); len(r.raw) < 4000 || !r.authed {
			t.Fatalf("%d bytes", len(r.raw))
		}
		if r := one(t, "next bulk", f.b2); len(r.raw) > 1472 {
			t.Fatalf("then %d bytes", len(r.raw))
		}
	},
	"W8": func(t *testing.T, f *flow) {
		if p := one(t, "bulk", f.b1).s.PDU; p.F1 != AuthorizationError || p.F2 != 1 {
			t.Fatalf("error-status %d index %d", p.F1, p.F2)
		}
	},
	"W9": func(t *testing.T, f *flow) {
		wantResponse(t, "bulk", one(t, "bulk", f.b1))
		b := one(t, "bulk at the FID", f.c.request(bulk(6, EntCol(9, 6)))).s.PDU.Binds
		if len(b) != 2 || b[0].OID != EntCol(10, 1) || b[1].Tag != EndOfMibView || b[1].OID != b[0].OID {
			t.Fatalf("bulk: %+v", b)
		}
	},
	"T1": func(t *testing.T, f *flow) {
		defaultStart(t, f)
		wantResponse(t, "get", one(t, "get", f.g1))
		none(t, "bulk", f.b1)
		wantResponse(t, "bulk retransmission", one(t, "bulk", f.b2))
	},
	"T2": func(t *testing.T, f *flow) {
		none(t, "bulk", f.b1)
		none(t, "bulk retransmission", f.b2)
	},
	"T3": func(t *testing.T, f *flow) { none(t, "discovery", f.disc); none(t, "tw", f.tw) },
	"T4": func(t *testing.T, f *flow) {
		if len(f.g1) != 3 {
			t.Fatalf("get: %d datagrams", len(f.g1))
		}
		if f.g1[0].m.MsgID == f.c.msgID-1 || f.g1[1].s.PDU.ReqID == 3 || f.g1[2].s.PDU.ReqID != 3 {
			t.Errorf("msgID %d request-ids %d %d", f.g1[0].m.MsgID, f.g1[1].s.PDU.ReqID, f.g1[2].s.PDU.ReqID)
		}
	},
	"T5": func(t *testing.T, f *flow) {
		if len(f.g1) != 2 || f.g1[0].from.Port == f.a.Addr().Port || f.g1[1].from.Port != f.a.Addr().Port {
			t.Fatalf("get: %+v", f.g1)
		}
	},
	"H0": func(t *testing.T, f *flow) {
		b := one(t, "bulk", f.b1).s.PDU.Binds[1]
		if v, err := Uint(TLV{Tag: b.Tag, Val: b.Val}); err != nil || b.Tag != TagCounter64 || v != 1<<63 {
			t.Fatalf("Counter64 %x: %v", b.Val, err)
		}
	},
}

// The default-behaving cases answer the whole flow as the default does.
var defaults = []string{"I1", "I2", "I3", "I4", "I5", "I6", "F1", "F2", "F3", "F4", "F5a", "F5b", "F6", "U13", "U14", "M1", "M2", "M3"}

func TestCaseBehaviour(t *testing.T) {
	for _, id := range defaults {
		behaviour[id] = func(t *testing.T, f *flow) {
			defaultStart(t, f)
			wantResponse(t, "get", one(t, "get", f.g1))
			wantResponse(t, "bulk", one(t, "bulk", f.b1))
		}
	}
	for _, id := range Cases() {
		if _, ok := cases[id]; !ok {
			continue // the hostile corpus: TestHostileCorpus
		}
		check, ok := behaviour[id]
		if !ok {
			t.Errorf("%s: no behaviour test", id)
			continue
		}
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			check(t, runFlow(t, id))
		})
	}
}

// The identity cases' served values.
func TestIdentityCases(t *testing.T) {
	grammar := regexp.MustCompile(`^SEL-(?:2731|2741)M-R[0-9]{3}-V[0-9]+-Z[0-9]{6}-D[0-9]{8}$`)
	fids := func(id string) map[string]string {
		cfg, err := NewCase(id, testSpec(t))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, v := range cfg.MIB.Vars() {
			if v.Tag == TagOctets && (grammar.Match(v.Val) || bytes.HasPrefix(v.Val, []byte("SEL-27"))) {
				out[v.OID] = string(v.Val)
			}
		}
		if v := cfg.MIB.Get(SysName); id == "I5" && v.Tag != NoSuchObject {
			t.Errorf("I5: sysName tag 0x%02x", v.Tag)
		}
		return out
	}
	for id, want := range map[string]map[string]string{
		"I1":  {EntCol(10, 1): FID2731},
		"I2":  {EntCol(10, 1): FID2741},
		"I3":  {EntCol(2, 3): FID2731},
		"I4":  {EntCol(10, 1): FID2731, SysDescr: FID2731},
		"I5":  {EntCol(10, 1): FID2731},
		"I6":  {EntCol(10, 1): FID2731R100},
		"F1":  {},
		"F2":  {EntCol(10, 1): FID2731, EntCol(10, 3): FID2741},
		"F3":  {EntCol(10, 1): FIDSDN},
		"F4":  {EntCol(10, 1): FID2743},
		"F5a": {EntCol(10, 1): FID2731 + "X"},
		"F5b": {EntCol(10, 1): "SEL-2731M-R102-\xc31-Z003001-D20260408"},
		"F6":  {EntCol(10, 1): FID2741},
	} {
		if got := fids(id); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: serves %q, want %q", id, got, want)
		}
	}
	for _, id := range []string{"F1", "F3", "F4", "F5a", "F5b"} {
		for oid, v := range fids(id) {
			if grammar.MatchString(v) {
				t.Errorf("%s: %s matches the family grammar", id, oid)
			}
		}
	}
}

// --- the hostile corpus ---

// strict checks a ScopedPDU's encoding against the texts, beyond what the
// agent's decoder needs: RFC 3417 section 8 (definite lengths; the
// primitive form for simple types), RFC 2578 sections 3.5 and 7 (an OID of
// 1 to 128 sub-identifiers each below 2^32; Integer32 in 4 octets;
// Counter64 in at most 9 with a 0x00 lead), RFC 3416 section 3 (the value
// types, the exceptions as NULLs, request-id an Integer32), and X.690's
// minimal sub-identifiers.
func strict(raw []byte) error {
	top, err := readOne(raw)
	if err != nil {
		return err
	}
	c, err := seq(top, TagSequence, 3)
	if err != nil {
		return err
	}
	if c[2].Tag != PDUResponse && c[2].Tag != PDUReport {
		return fmt.Errorf("PDU tag 0x%02x is not one a manager accepts", c[2].Tag)
	}
	f, err := seq(c[2], c[2].Tag, 4)
	if err != nil {
		return err
	}
	for _, x := range f[:3] {
		if x.Tag != TagInteger || len(x.Val) > 4 {
			return fmt.Errorf("an Integer32 of %d octets", len(x.Val))
		}
	}
	vbs, err := seq(f[3], TagSequence, -1)
	if err != nil {
		return err
	}
	for _, vb := range vbs {
		kv, err := seq(vb, TagSequence, 2)
		if err != nil {
			return err
		}
		if kv[0].Tag != TagOID {
			return errors.New("varbind name is not an OID")
		}
		if err := strictOID(kv[0].Val); err != nil {
			return err
		}
		if err := strictValue(kv[1]); err != nil {
			return err
		}
	}
	return nil
}

func strictOID(v []byte) error {
	if len(v) == 0 {
		return errors.New("empty OID")
	}
	arcs, n, startArc := 1, uint64(0), true // the first sub-identifier holds two arcs
	for i, b := range v {
		if startArc && b == 0x80 {
			return errors.New("a sub-identifier with a leading 0x80")
		}
		startArc = false
		n = n<<7 | uint64(b&0x7f)
		if b&0x80 == 0 {
			if n >= 1<<32 && i > 0 && arcs > 1 {
				return errors.New("an arc of 2^32 or more")
			}
			arcs++
			n, startArc = 0, true
		}
	}
	if !startArc {
		return errors.New("an OID that ends inside a sub-identifier")
	}
	if arcs > 128 {
		return fmt.Errorf("%d arcs", arcs)
	}
	return nil
}

func strictValue(t TLV) error {
	switch t.Tag {
	case TagInteger:
		if len(t.Val) == 0 || len(t.Val) > 4 {
			return fmt.Errorf("an Integer32 of %d octets", len(t.Val))
		}
	case TagOctets, TagOpaque:
	case TagNull, NoSuchObject, NoSuchInstance, EndOfMibView:
		if len(t.Val) != 0 {
			return errors.New("a NULL with contents")
		}
	case TagOID:
		return strictOID(t.Val)
	case TagIPAddress:
		if len(t.Val) != 4 {
			return errors.New("an IpAddress not of 4 octets")
		}
	case TagCounter32, TagGauge32, TagTimeTicks:
		if _, err := Uint(t); err != nil || len(t.Val) > 5 {
			return fmt.Errorf("an unsigned32 of %d octets", len(t.Val))
		}
	case TagCounter64:
		if _, err := Uint(t); err != nil {
			return err
		}
	default:
		return fmt.Errorf("value tag 0x%02x", t.Tag)
	}
	return nil
}

// TestHostileCorpus checks that every corpus entry breaks a rule of the
// texts at its layer, and that the positives break none.
func TestHostileCorpus(t *testing.T) {
	for _, id := range Cases() {
		if _, ok := cases[id]; ok {
			continue
		}
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			f := runFlow(t, id)
			hid, layer, _ := cutLayer(id)
			switch {
			case hid == "H15":
				r := one(t, "get", f.g1)
				if len(r.m.AuthParams) == 24 || r.authed {
					t.Fatalf("authentication parameters of %d octets", len(r.m.AuthParams))
				}
			case hid == "H16":
				r := one(t, "get", f.g1)
				if len(r.m.PrivParams) == 8 {
					t.Fatal("privacy parameters of 8 octets")
				}
			case hid == "H12":
				var r rx
				if layer == "outer" {
					r = one(t, "discovery", f.disc)
				} else {
					r = one(t, "get", f.g1)
				}
				raw := r.m.Plain
				if r.m.Encrypted != nil {
					raw, _ = r.m.Decrypt(f.c.u)
				}
				if r.err != nil || strict(raw) != nil {
					t.Fatalf("H12 must be well formed: %v %v", r.err, strict(raw))
				}
				if !bytes.Contains(r.raw, []byte{0x30, 0x84}) && !bytes.Contains(raw, []byte{0x30, 0x84}) {
					t.Fatal("no long-form length")
				}
			case layer == "outer":
				r := one(t, "discovery", f.disc)
				if r.err == nil && strict(r.m.Plain) == nil {
					t.Fatalf("%s: the discovery Report is well formed", hid)
				}
				// Sent again for the retransmission.
				if again := one(t, "retransmission", f.c.discover()); again.err == nil && strict(again.m.Plain) == nil {
					t.Fatal("the retransmission got a well-formed Report")
				}
			default: // scoped
				defaultStart(t, f)
				want := 1
				if hid == "H17" {
					want = 3 // a SetRequest, a Trap and an Inform
				}
				for _, rs := range [][]rx{f.g1, f.g2} { // the get, and its retransmission
					if len(rs) != want {
						t.Fatalf("%d datagrams, want %d", len(rs), want)
					}
					for _, r := range rs {
						if !r.authed || flagsOf(r) != authPriv {
							t.Fatalf("the hostile Response must authenticate: flags %d", flagsOf(r))
						}
						raw, err := r.m.Decrypt(f.c.u)
						if err != nil {
							t.Fatal(err)
						}
						if strict(raw) == nil {
							t.Fatalf("%s: the ScopedPDU is well formed", hid)
						}
					}
				}
			}
		})
	}
	// The positive H0 passes strict.
	f := runFlow(t, "H0")
	r := one(t, "bulk", f.b1)
	raw, _ := r.m.Decrypt(f.c.u)
	if err := strict(raw); err != nil {
		t.Errorf("H0: %v", err)
	}
}

func cutLayer(id string) (string, string, bool) {
	for i := range id {
		if id[i] == '/' {
			return id[:i], id[i+1:], true
		}
	}
	return id, "", false
}
