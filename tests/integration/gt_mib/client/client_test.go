// Package client runs C2's SNMPv3 session against GT-MIB's agent over a
// real UDP socket, for the cases that V-M1's binary run can't hold: W11
// and W12 need the entity operation as a GetNext walk, which no signed
// register holds while D4-60's bar stands (C6-gt-mib-plan.md section 2.4).
// W10 runs here too, beside its binary run, as the Get half of C2 0.9's
// test 3 (docs/phase4/D2-c2-0.9.md section 6).
//
// The table's expectation is read from ../cases.json, and what the agent
// received from its own log. Evidence class: simulated. The agent is
// GT-MIB on 127.0.0.1, and the password is a test value.
package client

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/ied/snmpv3"
	"otsec.local/otsec/tests/integration/gt_mib/agent"
)

const (
	password = "gt-mib-client-test-password-1" // test only, used on nothing else
	user     = "gt-mib"
	runID    = "sel27x1.snmp.identity"
	system   = "sel27x1.snmp.system"
	entity   = "sel27x1.snmp.entity"
)

var engineID, _ = hex.DecodeString("80007c4f03020000273101")

type tableCase struct {
	ID       string `json:"id"`
	Register string `json:"register"`
	Expect   struct {
		Code      string   `json:"code"`
		BytesKept bool     `json:"bytes_kept"`
		Absent    []string `json:"absent"`
	} `json:"expect"`
}

func table(t *testing.T) map[string]tableCase {
	t.Helper()
	b, err := os.ReadFile("../cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Cases []tableCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	out := map[string]tableCase{}
	for _, c := range g.Cases {
		out[c.ID] = c
	}
	return out
}

// pkg is the identity run of the C2 test package as V-M1's binary run holds
// it (system get, then the entity GetBulk walk), with the entity operation
// made a GetNext walk when the case's register says so.
func pkg(t *testing.T, getNext bool) *register.Package {
	t.Helper()
	cite := []register.Citation{{Source: "T1", Ref: "p. 1"}}
	ev := register.Evidence{Class: "documented-untested"}
	limits := &register.Limits{MaxReplyBytes: 1472, TimeoutMS: 2000}
	ent := register.SNMPOperation{ID: entity, PDU: register.PDUGetBulk, Subtree: agent.EntPhysicalTable, MaxRepetitions: 16,
		Walk: &register.Walk{MaxVarbinds: 512, MaxRequests: 32}, Limits: limits, Citations: cite, Evidence: ev, SideEffects: "none"}
	if getNext {
		ent.PDU, ent.MaxRepetitions = register.PDUGetNext, 0
	}
	p := &register.Package{
		Contract: "otsec.register/0.4", Family: "sel-27x1", Revision: 1, Issued: "2026-11-07", Owner: "D6",
		Sources: []register.Source{{ID: "T1", Title: "GT-MIB client test source"}},
		SNMPOperations: []register.SNMPOperation{
			{ID: system, PDU: register.PDUGet, OIDs: []string{agent.SysDescr, agent.SysName}, Limits: limits,
				Citations: cite, Evidence: ev, SideEffects: "none"},
			ent,
		},
		Runs: []register.Run{{ID: runID, Steps: []string{system, entity}, MaxTotalBytes: 262144, DeadlineMS: 30000,
			Citations: cite, Evidence: ev, SideEffects: "none"}},
		Firmware: register.Firmware{
			Known:    []register.KnownFirmware{{FID: agent.FID2731, Branch: "R102", Version: 1, Citation: cite[0]}},
			Branches: []register.BranchRule{{Branch: "R102", Status: register.BranchAllow, Basis: "test", Evidence: ev}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// udp is snmpv3.Conn over a connected UDP socket, as the collector's is.
type udp struct{ c *net.UDPConn }

func (u udp) LocalAddr() string    { return adapter.LocalAddrOf(u.c.LocalAddr()) }
func (u udp) Write(b []byte) error { _, err := u.c.Write(b); return err }
func (u udp) Read(deadline time.Time) ([]byte, error) {
	if err := u.c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := u.c.Read(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, snmpv3.ErrDeadline
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

type logged struct {
	PDU *struct {
		Type     string `json:"type"`
		Varbinds []struct {
			OID string `json:"oid"`
		} `json:"varbinds"`
	} `json:"pdu"`
}

// run runs case id once and returns the outcome and the agent's log.
func run(t *testing.T, id string, getNext bool) (snmpv3.Outcome, []logged) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "agent.jsonl")
	cfg, err := agent.NewCase(id, agent.Spec{EngineID: engineID, User: user, Auth: agent.AuthSHA256,
		Password: password, LogPath: logPath})
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.Start("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, a.Addr())
	if err != nil {
		t.Fatal(err)
	}
	u := agent.NewUser(user, agent.AuthSHA256, true, password, engineID)
	s := snmpv3.Session{
		Conn: udp{c},
		Keys: snmpv3.Keys{User: user, Auth: snmpv3.HMACSHA256, AuthKey: u.AuthKey, Priv: snmpv3.AES128,
			PrivKey: u.PrivKey[:16]},
		EngineID: engineID,
		Permit:   func(string, bool, []byte) error { return nil },
		Now:      time.Now,
	}
	o := s.Run(pkg(t, getNext), runID)
	c.Close()
	a.Close()
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []logged
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var r logged
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	return o, recs
}

func requests(recs []logged, typ string) int {
	n := 0
	for _, r := range recs {
		if r.PDU != nil && r.PDU.Type == typ {
			n++
		}
	}
	return n
}

// The three cases of C2 0.9's test 3: each ends with the table's code,
// keeps the Response that ends it, takes no value from it, and sends
// nothing after it.
func TestVarbindsMismatchAtTheClient(t *testing.T) {
	tab := table(t)
	for _, c := range []struct {
		id      string
		getNext bool
		kept    int    // values kept, all from earlier Responses
		last    string // the PDU type of the agent's last request
		count   int    // requests of that type the agent received
	}{
		{"W10", false, 0, "GetRequest", 1},
		{"W11", true, 3, "GetNextRequest", 2},
		{"W12", true, 3, "GetNextRequest", 2},
	} {
		t.Run(c.id, func(t *testing.T) {
			want := tab[c.id]
			if want.ID == "" || (want.Register == "getnext") != c.getNext {
				t.Fatalf("cases.json: %+v", want)
			}
			o, recs := run(t, c.id, c.getNext)
			if string(o.Code) != want.Expect.Code {
				t.Fatalf("code %q (%s), want %q", o.Code, o.Detail, want.Expect.Code)
			}
			if len(o.Values) != c.kept {
				t.Errorf("%d values kept, want %d: %+v", len(o.Values), c.kept, o.Values)
			}
			last := o.Segments[len(o.Segments)-1]
			if want.Expect.BytesKept && (last.Dir != adapter.Received || last.Phase != adapter.PhaseOperate) {
				t.Errorf("the Response that ends the run is not the last kept segment: %s %s", last.Dir, last.Phase)
			}
			for _, v := range o.Values {
				if v.Segment == len(o.Segments)-1 {
					t.Errorf("a value from the Response that ends the run: %+v", v)
				}
			}
			if requests(recs, "GetBulkRequest") != 0 {
				t.Error("a GetBulk was sent")
			}
			if c.getNext && requests(recs, "GetRequest") == 0 {
				t.Error("the system get was not sent")
			}
			// The time-window round is the run's first get (authenticated,
			// answered by a Report), so W10's Response is to its second.
			n := requests(recs, c.last)
			if c.id == "W10" {
				n--
			}
			if n != c.count {
				t.Errorf("%d %s, want %d: nothing is sent after the Response that ends the run", n, c.last, c.count)
			}
		})
	}
}

// The control: against the default agent, every GetNext Response carries
// one binding, so the same walk goes on to its max_requests bound (32) and
// ends there, never with failed.snmp_varbinds_mismatch. The default table's
// 6 rows of 18 columns are more than one walk's 32 requests can reach. So
// W11's and W12's codes come from the counts, not from GetNext itself.
func TestGetNextWalkGoesOnWithOneBindingEach(t *testing.T) {
	o, recs := run(t, "I1", true)
	if o.Code != adapter.FailedResponseTooLarge {
		t.Fatalf("code %q (%s), want %s at the walk's bound", o.Code, o.Detail, adapter.FailedResponseTooLarge)
	}
	if n := requests(recs, "GetNextRequest"); n != 32 || requests(recs, "GetBulkRequest") != 0 {
		t.Errorf("%d GetNext, %d GetBulk; want 32 and none", n, requests(recs, "GetBulkRequest"))
	}
	if len(o.Values) != 2+32 {
		t.Errorf("%d values, want the get's 2 and one per GetNext", len(o.Values))
	}
}
