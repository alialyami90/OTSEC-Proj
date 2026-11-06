package agent

// GT-MIB's acceptance tests (D6-handoff task 1): the agent imports nothing
// of the product, serves exactly S29's list, derives keys as RFC 3414
// A.3.2's vector says, and answers a manager over loopback through
// discovery, the time-window round, a get and a walk. The manager here is
// written from the same texts with the agent's own codec; it is a test of
// the agent, not of the client.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testPassword is a test-only USM password, used on nothing else.
const testPassword = "gt-mib-agent-test-password-1"

var testEngine = mustHex("80007c4f03020000273101")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func testSpec(t *testing.T) Spec {
	return Spec{EngineID: testEngine, User: "gt-mib", Auth: AuthSHA256, Password: testPassword,
		LogPath: filepath.Join(t.TempDir(), "agent.jsonl")}
}

// --- the import rule ---

// The agent imports only the standard library, so a bug shared with the
// client, the egress check or a contract cannot make them agree.
func TestImportsStandardLibraryOnly(t *testing.T) {
	var files []string
	err := filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".go") {
			files = append(files, p)
		}
		return err
	})
	if err != nil || len(files) < 6 {
		t.Fatalf("walk: %v, %d files", err, len(files))
	}
	for _, f := range files {
		ast, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range ast.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "otsec.local/otsec/tests/integration/gt_mib/agent" && strings.HasPrefix(f, "cmd") {
				continue // the command runs the agent, and imports nothing else
			}
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %s: GT-MIB imports only the standard library", f, p)
			}
		}
	}
}

// --- what it serves ---

// served.json is S29's table, pp. 46 and 47, 76 lines.
func TestServedListIsS29(t *testing.T) {
	l := ServedList()
	if len(l) != 76 {
		t.Fatalf("%d served objects, S29 lists 76", len(l))
	}
	seen := map[string]bool{}
	for _, s := range l {
		if seen[s.OID] {
			t.Errorf("%s twice", s.OID)
		}
		seen[s.OID] = true
		if s.Page != 46 && s.Page != 47 {
			t.Errorf("%s cites p. %d", s.OID, s.Page)
		}
		if _, err := ParseOID(s.OID); err != nil || s.Name == "" || s.MIB == "" {
			t.Errorf("%+v", s)
		}
	}
}

// The default MIB serves an instance under every listed object and nothing
// outside them, and answers the exceptions as RFC 3416 4.2.1 to 4.2.3 say.
func TestServesExactlyTheList(t *testing.T) {
	m := NewMIB(Options{EngineID: testEngine, FID: FID2731})
	l := ServedList()
	for _, v := range m.Vars() {
		in := 0
		for _, s := range l {
			if Under(v.OID, s.OID) {
				in++
			}
		}
		// dot1dStpPortTable's listed columns lie under the listed table.
		if in == 0 || in > 2 {
			t.Errorf("%s lies under %d served objects", v.OID, in)
		}
	}
	for _, s := range l {
		n := 0
		for _, v := range m.Vars() {
			if Under(v.OID, s.OID) {
				n++
			}
		}
		if n == 0 {
			t.Errorf("%s (%s) serves nothing", s.OID, s.Name)
		}
	}
	// entPhysicalTable: 6 rows of the 18 accessible columns, 2 to 19 (RFC
	// 6933 section 4).
	n := 0
	for _, v := range m.Vars() {
		if Under(v.OID, EntPhysicalTable) {
			n++
		}
	}
	if n != 6*18 {
		t.Errorf("entPhysicalTable has %d cells, want 108", n)
	}
	if v := m.Get(EntCol(10, 1)); string(v.Val) != FID2731 {
		t.Errorf("the FID cell holds %q", v.Val)
	}
	if v := m.Get("1.3.6.1.2.1.99.1.0"); v.Tag != NoSuchObject {
		t.Errorf("an unlisted object: tag 0x%02x", v.Tag)
	}
	if v := m.Get(SysName + ".7"); v.Tag != NoSuchInstance {
		t.Errorf("a missing instance of sysName: tag 0x%02x", v.Tag)
	}
	last := m.Vars()[len(m.Vars())-1]
	if v := m.Next(last.OID); v.Tag != EndOfMibView || v.OID != last.OID {
		t.Errorf("past the last object: %+v", v)
	}
}

// --- the keys: RFC 3414 A.3.2 ---

func TestRFC3414A32SHAVector(t *testing.T) {
	ku := PasswordToKey(AuthSHA1, []byte("maplesyrup"))
	if want := mustHex("9fb5cc0381497b3793528939ff788d5d79145211"); !bytes.Equal(ku, want) {
		t.Errorf("Ku = %x, want %x", ku, want)
	}
	kul := Localize(AuthSHA1, ku, mustHex("000000000000000000000002"))
	if want := mustHex("6695febc9288e36282235fc7151f128497b38f3f"); !bytes.Equal(kul, want) {
		t.Errorf("Kul = %x, want %x", kul, want)
	}
	// The same code with SHA-256 and SHA-512 gives keys of M octets (RFC
	// 7860 section 4.1: 32 and 64).
	for a, m := range map[Auth]int{AuthSHA256: 32, AuthSHA512: 64} {
		if k := Localize(a, PasswordToKey(a, []byte("maplesyrup")), testEngine); len(k) != m {
			t.Errorf("%s: a %d-octet key", a, len(k))
		}
	}
}

// --- a manager for the tests ---

type rx struct {
	raw    []byte
	from   *net.UDPAddr
	m      *Msg
	s      *Scoped
	authed bool
	err    error
}

type mgr struct {
	t      *testing.T
	c      *net.UDPConn
	to     *net.UDPAddr
	spec   Spec
	u      User
	engine []byte
	boots  int64
	time   int64
	msgID  int64
	salt   uint64
}

func newMgr(t *testing.T, a *Agent, spec Spec) *mgr {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &mgr{t: t, c: c, to: a.Addr(), spec: spec, msgID: 100}
}

// exchange sends o and collects every datagram that arrives within wait.
func (c *mgr) exchange(o Out, wait time.Duration) []rx {
	c.msgID++
	o.MsgID = c.msgID
	if _, err := c.c.WriteToUDP(o.Encode(c.u), c.to); err != nil {
		c.t.Fatal(err)
	}
	var out []rx
	buf := make([]byte, 65536)
	deadline := time.Now().Add(wait)
	for {
		c.c.SetReadDeadline(deadline)
		n, from, err := c.c.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		out = append(out, c.decode(append([]byte(nil), buf[:n]...), from))
	}
}

func (c *mgr) decode(b []byte, from *net.UDPAddr) rx {
	r := rx{raw: b, from: from}
	m, err := DecodeMsg(b)
	r.m = m
	if err != nil {
		r.err = err
		return r
	}
	plain := m.Plain
	if m.Flags&FlagAuth != 0 && c.u.Auth != "" {
		r.authed = m.CheckMAC(c.u)
	}
	if m.Encrypted != nil {
		if plain, err = m.Decrypt(c.u); err != nil {
			r.err = err
			return r
		}
	}
	s, err := DecodeScoped(plain)
	if err != nil {
		r.err = err
		return r
	}
	r.s = &s
	return r
}

const wait = 150 * time.Millisecond

// discover sends RFC 3414 section 4's discovery message and adopts the
// engine ID it learns, localizing the user's keys to it.
func (c *mgr) discover() []rx {
	got := c.exchange(Out{MaxSize: 1472, Flags: FlagReportable, Scoped: Scoped{PDU: PDU{Tag: PDUGet, ReqID: 1}}}, wait)
	for _, r := range got {
		if r.s != nil && r.s.PDU.Tag == PDUReport && c.engine == nil {
			c.engine = r.m.EngineID
			c.u = NewUser(c.spec.User, c.spec.Auth, true, c.spec.Password, c.engine)
		}
	}
	return got
}

// request sends an authPriv request at the manager's boots and time.
func (c *mgr) request(p PDU) []rx {
	c.salt++
	salt := make([]byte, 8)
	salt[7] = byte(c.salt)
	return c.exchange(Out{MaxSize: 1472, Flags: FlagAuth | FlagPriv | FlagReportable, EngineID: c.engine,
		Boots: c.boots, Time: c.time, User: []byte(c.spec.User), Salt: salt,
		Scoped: Scoped{CtxEngine: c.engine, PDU: p}}, wait)
}

func get(id int64, oids ...string) PDU {
	p := PDU{Tag: PDUGet, ReqID: id}
	for _, o := range oids {
		p.Binds = append(p.Binds, Bind{OID: o, Tag: TagNull})
	}
	return p
}

func bulk(id int64, oid string) PDU {
	return PDU{Tag: PDUGetBulk, ReqID: id, F1: 0, F2: 16, Binds: []Bind{{OID: oid, Tag: TagNull}}}
}

// adopt takes boots and time from an authenticated time-window Report.
func (c *mgr) adopt(rs []rx) bool {
	for _, r := range rs {
		if r.authed && r.s != nil && r.s.PDU.Tag == PDUReport && len(r.s.PDU.Binds) == 1 &&
			r.s.PDU.Binds[0].OID == UsmStatsNotInTimeWindows {
			c.boots, c.time = r.m.Boots, r.m.Time
			return true
		}
	}
	return false
}

func start(t *testing.T, id string, spec Spec) *Agent {
	cfg, err := NewCase(id, spec)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Start("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func reportOID(r rx) string {
	if r.s == nil || r.s.PDU.Tag != PDUReport || len(r.s.PDU.Binds) != 1 {
		return ""
	}
	return r.s.PDU.Binds[0].OID
}

// --- the loopback round ---

// Discovery, the time-window round, a get and a walk, against the default
// agent (case I1), checked against the texts and against the agent's log.
func TestLoopbackRound(t *testing.T) {
	spec := testSpec(t)
	a := start(t, "I1", spec)
	c := newMgr(t, a, spec)

	// RFC 3414 section 4: discovery is answered by a noAuthNoPriv Report of
	// usmStatsUnknownEngineIDs carrying the engine ID, boots and time.
	d := c.discover()
	if len(d) != 1 || reportOID(d[0]) != UsmStatsUnknownEngineIDs || d[0].m.Flags&0x03 != 0 {
		t.Fatalf("discovery: %+v", d)
	}
	if !bytes.Equal(c.engine, testEngine) || d[0].m.Boots != 1 || d[0].s.PDU.ReqID != 1 || d[0].m.MsgID != c.msgID {
		t.Errorf("discovery Report: engine %x boots %d request-id %d msgID %d", c.engine, d[0].m.Boots, d[0].s.PDU.ReqID, d[0].m.MsgID)
	}
	if d[0].m.Flags&FlagReportable != 0 {
		t.Error("a Report with the reportable flag set (RFC 3412 7.1 step 7)")
	}

	// RFC 3414 3.2 step 7a: boots and time 0 are outside the window, and
	// the Report goes authNoPriv.
	tw := c.request(get(2, SysDescr, SysName))
	if len(tw) != 1 || reportOID(tw[0]) != UsmStatsNotInTimeWindows || tw[0].m.Flags&0x03 != FlagAuth || !tw[0].authed {
		t.Fatalf("time-window round: %+v", tw)
	}
	// The window is checked (step 7) before decryption (step 8), so the
	// request-id cannot be read: it is 0 (RFC 3412 7.1 step 3c 4).
	if tw[0].s.PDU.ReqID != 0 || tw[0].m.MsgID != c.msgID || !bytes.Equal(tw[0].s.CtxEngine, testEngine) || len(tw[0].s.CtxName) != 0 {
		t.Errorf("time-window Report: request-id %d context %x %q", tw[0].s.PDU.ReqID, tw[0].s.CtxEngine, tw[0].s.CtxName)
	}
	if !c.adopt(tw) {
		t.Fatal("no authenticated time-window Report to adopt")
	}

	// The get: an authPriv Response with both values.
	g := c.request(get(3, SysDescr, SysName))
	if len(g) != 1 || g[0].s == nil || g[0].s.PDU.Tag != PDUResponse || g[0].m.Flags&0x03 != FlagAuth|FlagPriv || !g[0].authed {
		t.Fatalf("get: %+v", g)
	}
	if b := g[0].s.PDU.Binds; len(b) != 2 || b[0].OID != SysDescr || string(b[1].Val) != "gt-mib-sw1" {
		t.Errorf("get varbinds: %+v", b)
	}

	// The walk: GetBulk with max-repetitions 16 until it leaves the table;
	// every Response is at most msgMaxSize 1472 (RFC 3416 4.2.3 reason
	// (1)).
	var cells []Bind
	next, id := EntPhysicalTable, int64(4)
	for steps := 0; steps < 40; steps++ {
		r := c.request(bulk(id, next))
		id++
		if len(r) != 1 || r[0].s == nil || !r[0].authed {
			t.Fatalf("walk at %s: %+v", next, r)
		}
		if len(r[0].raw) > 1472 {
			t.Errorf("a Response of %d bytes", len(r[0].raw))
		}
		done := false
		for _, b := range r[0].s.PDU.Binds {
			if !Under(b.OID, EntPhysicalTable) || b.Tag == EndOfMibView {
				done = true
				break
			}
			cells = append(cells, b)
			next = b.OID
		}
		if done {
			break
		}
	}
	if len(cells) != 108 {
		t.Fatalf("the walk read %d cells, want 108", len(cells))
	}
	fid := 0
	for _, b := range cells {
		if string(b.Val) == FID2731 {
			fid++
			if b.OID != EntCol(10, 1) {
				t.Errorf("the FID under %s", b.OID)
			}
		}
	}
	if fid != 1 {
		t.Errorf("the FID read %d times", fid)
	}

	// The log: one line per datagram, decoded by the agent, and the PDUs
	// it names are the ones sent.
	time.Sleep(50 * time.Millisecond)
	lines := readLog(t, spec.LogPath)
	if len(lines) != a.Received() {
		t.Fatalf("%d log lines for %d datagrams", len(lines), a.Received())
	}
	if !lines[0].Discovery || lines[0].PDU == nil || lines[0].PDU.Type != "GetRequest" {
		t.Errorf("log line 1: %+v", lines[0])
	}
	if l := lines[1]; l.Stage != "report" || l.Report != UsmStatsNotInTimeWindows || !l.Authentic || l.PDU != nil {
		t.Errorf("log line 2, the time-window round: %+v", l)
	}
	for _, l := range lines[2:] {
		if l.Discovery || !l.Authentic || !l.Decrypted || l.Level != "authPriv" || l.PDU == nil {
			t.Errorf("log line %d: %+v", l.N, l)
			continue
		}
		if l.PDU.Type != "GetRequest" && l.PDU.Type != "GetBulkRequest" {
			t.Errorf("log line %d: %s", l.N, l.PDU.Type)
		}
	}
}

func readLog(t *testing.T, path string) []LogEntry {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []LogEntry
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e LogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// RFC 3412 7.1 step 3b: a Report answers a Confirmed Class PDU even
// without the reportable flag, never a PDU of another class, and, when the
// PDU cannot be read, only a reportable message.
func TestReportRule(t *testing.T) {
	spec := testSpec(t)
	a := start(t, "I1", spec)
	c := newMgr(t, a, spec)
	if r := c.exchange(Out{MaxSize: 1472, Scoped: Scoped{PDU: PDU{Tag: PDUGet, ReqID: 1}}}, wait); len(r) != 1 {
		t.Errorf("a GetRequest without the reportable flag: %d replies, want the Report", len(r))
	}
	if r := c.exchange(Out{MaxSize: 1472, Flags: FlagReportable, Scoped: Scoped{PDU: PDU{Tag: PDUReport, ReqID: 1}}}, wait); len(r) != 0 {
		t.Errorf("a Report PDU: %d replies, want none", len(r))
	}
	// An authPriv message at boots and time 0 is outside the window; its
	// PDU is encrypted and not read before that check, so the reportable
	// flag decides.
	c.discover()
	for flags, want := range map[byte]int{FlagAuth | FlagPriv: 0, FlagAuth | FlagPriv | FlagReportable: 1} {
		r := c.exchange(Out{MaxSize: 1472, Flags: flags, EngineID: c.engine, User: []byte(spec.User), Salt: make([]byte, 8),
			Scoped: Scoped{CtxEngine: c.engine, PDU: get(9, SysName)}}, wait)
		if len(r) != want {
			t.Errorf("flags 0x%02x outside the window: %d replies, want %d", flags, len(r), want)
		}
	}
}

// TestStartListensOnLoopbackOnly: Start itself refuses every address that
// is not a loopback IP literal, before either socket binds (D3 on #496).
func TestStartListensOnLoopbackOnly(t *testing.T) {
	cfg, err := NewCase("I1", Spec{EngineID: testEngine, User: "gt-mib", Auth: AuthSHA256, Password: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"0.0.0.0:0", ":0", "localhost:0", "[::]:0", "192.0.2.1:0", "127.0.0.1"} {
		if a, err := Start(addr, cfg); err == nil {
			a.Close()
			t.Errorf("Start(%q) listened on %v", addr, a.Addr())
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		if addr == "[::1]:0" {
			c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
			if err != nil {
				t.Logf("not started at %s: this host has no IPv6 loopback (%v)", addr, err)
				continue
			}
			c.Close()
		}
		a, err := Start(addr, cfg)
		if err != nil {
			t.Errorf("Start(%q): %v", addr, err)
			continue
		}
		if !a.Addr().IP.IsLoopback() || !a.alt.LocalAddr().(*net.UDPAddr).IP.IsLoopback() {
			t.Errorf("Start(%q) bound %v and %v", addr, a.Addr(), a.alt.LocalAddr())
		}
		a.Close()
	}
}
