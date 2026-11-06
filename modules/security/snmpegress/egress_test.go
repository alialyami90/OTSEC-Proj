package snmpegress

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// The tests build messages with their own small encoder, written from RFC
// 3412, 3414, 3416 and 3826, so the check is never tested against itself.

func enc(tag byte, content ...[]byte) []byte {
	var c []byte
	for _, p := range content {
		c = append(c, p...)
	}
	out := []byte{tag}
	switch n := len(c); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, c...)
}

func encInt(n int64) []byte {
	b := []byte{byte(n)}
	for v := n >> 8; !(v == 0 && b[0]&0x80 == 0) && !(v == -1 && b[0]&0x80 != 0); v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return enc(0x02, b)
}

func encOID(s string) []byte {
	parts := strings.Split(s, ".")
	arcs := make([]uint64, len(parts))
	for i, p := range parts {
		arcs[i], _ = strconv.ParseUint(p, 10, 64)
	}
	var b []byte
	sub := append([]uint64{arcs[0]*40 + arcs[1]}, arcs[2:]...)
	for _, v := range sub {
		chunk := []byte{byte(v & 0x7f)}
		for v >>= 7; v > 0; v >>= 7 {
			chunk = append([]byte{byte(v&0x7f) | 0x80}, chunk...)
		}
		b = append(b, chunk...)
	}
	return enc(0x06, b)
}

func octets(b []byte) []byte { return enc(0x04, b) }

// arcs extends o with ".1" arcs until it has n sub-identifiers.
func arcs(o string, n int) string {
	return o + strings.Repeat(".1", n-strings.Count(o, ".")-1)
}

var (
	testEngine = []byte{0x80, 0x00, 0x7c, 0x4f, 0x03, 0x02, 0x00, 0x00, 0x27, 0x31, 0x01}
	testPriv   = []byte("0123456789abcdef")
	testSalt   = []byte{1, 2, 3, 4, 5, 6, 7, 8}
)

const (
	sysDescr  = "1.3.6.1.2.1.1.1.0"
	sysName   = "1.3.6.1.2.1.1.5.0"
	entityTbl = "1.3.6.1.2.1.47.1.1.1"
)

// msg is every field of an SNMPv3 request, so a test can change one.
type msg struct {
	version     int64
	community   string // v1 and v2c only: a community-based message
	maxSize     int64
	flags       byte
	model       int64
	engineID    []byte
	boots, time int64
	user        string
	authP       []byte
	privP       []byte
	ctxEngine   []byte
	ctxName     string
	pduTag      byte
	a, b        int64 // error-status and error-index, or non-repeaters and max-repetitions
	oids        []string
	value       []byte // a varbind's value; NULL when nil
	plain       bool   // send the scoped PDU unencrypted whatever the flags say
	afterScoped []byte // bytes after the scoped PDU, inside the encryption
}

func (m msg) bytes() []byte {
	var vbs [][]byte
	for _, o := range m.oids {
		v := m.value
		if v == nil {
			v = enc(0x05)
		}
		vbs = append(vbs, enc(0x30, encOID(o), v))
	}
	pdu := enc(m.pduTag, encInt(4242), encInt(m.a), encInt(m.b), enc(0x30, vbs...))
	if m.community != "" {
		return enc(0x30, encInt(m.version), octets([]byte(m.community)), pdu)
	}
	scoped := append(enc(0x30, octets(m.ctxEngine), octets([]byte(m.ctxName)), pdu), m.afterScoped...)
	data := scoped
	if m.flags&flagPriv != 0 && !m.plain {
		block, _ := aes.NewCipher(testPriv)
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:], uint32(m.boots))
		binary.BigEndian.PutUint32(iv[4:], uint32(m.time))
		copy(iv[8:], m.privP)
		ct := make([]byte, len(scoped))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, scoped) //nolint:staticcheck // RFC 3826
		data = octets(ct)
	}
	usm := enc(0x30, octets(m.engineID), encInt(m.boots), encInt(m.time), octets([]byte(m.user)), octets(m.authP), octets(m.privP))
	global := enc(0x30, encInt(77), encInt(m.maxSize), octets([]byte{m.flags}), encInt(m.model))
	return enc(0x30, encInt(m.version), global, octets(usm), data)
}

// discovery is RFC 3414 section 4's discovery message.
func discovery() msg {
	return msg{version: 3, maxSize: 1472, flags: flagReportable, model: 3, pduTag: tagGet}
}

// read is an authPriv request for op.
func read(op Op) msg {
	m := msg{version: 3, maxSize: int64(op.MaxReplyBytes), flags: flagAuth | flagPriv | flagReportable, model: 3,
		engineID: testEngine, boots: 3, time: 1200, user: "otsec-ro", authP: make([]byte, 48), privP: testSalt,
		ctxEngine: testEngine, pduTag: pduTag[op.PDU]}
	switch op.PDU {
	case Get:
		m.oids = op.OIDs
	case GetBulk:
		m.b, m.oids = int64(op.MaxRepetitions), []string{op.Subtree}
	default:
		m.oids = []string{op.Subtree}
	}
	return m
}

var (
	getOp  = Op{PDU: Get, OIDs: []string{sysDescr, sysName}, MaxReplyBytes: 1472}
	bulkOp = Op{PDU: GetBulk, Subtree: entityTbl, MaxRepetitions: 16, MaxReplyBytes: 1472}
	nextOp = Op{PDU: GetNext, Subtree: entityTbl, MaxReplyBytes: 1472}
)

func before() Session { return Session{} }
func after() Session {
	return Session{EngineKnown: true, EngineID: testEngine, UserName: "otsec-ro", PrivKey: testPriv}
}

func TestAllowed(t *testing.T) {
	cont := read(bulkOp)
	cont.oids = []string{entityTbl + ".1.2.6"} // a continuation from the last OID returned
	nextCont := read(nextOp)
	nextCont.oids = []string{entityTbl + ".1.7.1"}
	one := read(getOp)
	one.oids = []string{sysName}
	longest := read(bulkOp)
	longest.oids = []string{arcs(entityTbl, 128)} // RFC 2578 section 3.5's most
	for name, c := range map[string]struct {
		m  msg
		op Op
		s  Session
	}{
		"discovery":                {discovery(), getOp, before()},
		"get":                      {read(getOp), getOp, after()},
		"get of one named oid":     {one, getOp, after()},
		"getbulk at subtree":       {read(bulkOp), bulkOp, after()},
		"getbulk continuation":     {cont, bulkOp, after()},
		"getnext at subtree":       {read(nextOp), nextOp, after()},
		"getnext continuation":     {nextCont, nextOp, after()},
		"continuation of 128 arcs": {longest, bulkOp, after()},
		"authPriv not reportable":  {func() msg { m := read(getOp); m.flags &^= flagReportable; return m }(), getOp, after()},
	} {
		if r := Check(c.m.bytes(), c.op, c.s); r != Allowed {
			t.Errorf("%s: refused by %q", name, r)
		}
	}
}

// TestDenyCorpus is GT-MIB plan section 2.7: every SNMP write form, every
// lower level, every OID outside the operation, and one near miss per field of
// the discovery shape (C11 section 4 rule 4), each with the rule that refuses
// it.
func TestDenyCorpus(t *testing.T) {
	type tc struct {
		m    msg
		op   Op
		s    Session
		rule Rule
	}
	with := func(base msg, f func(*msg)) msg { f(&base); return base }
	d := discovery()
	cases := map[string]tc{
		// Write forms and other PDUs, at authPriv.
		"SetRequest":                      {with(read(getOp), func(m *msg) { m.pduTag = 0xa3; m.value = encInt(1) }), getOp, after(), RulePDUType},
		"InformRequest":                   {with(read(getOp), func(m *msg) { m.pduTag = 0xa6 }), getOp, after(), RulePDUType},
		"SNMPv2-Trap":                     {with(read(getOp), func(m *msg) { m.pduTag = 0xa7 }), getOp, after(), RulePDUType},
		"Report":                          {with(read(getOp), func(m *msg) { m.pduTag = 0xa8 }), getOp, after(), RulePDUType},
		"GetResponse":                     {with(read(getOp), func(m *msg) { m.pduTag = 0xa2 }), getOp, after(), RulePDUType},
		"getnext for a get operation":     {with(read(getOp), func(m *msg) { m.pduTag = tagGetNext }), getOp, after(), RulePDUType},
		"getbulk for a getnext operation": {with(read(nextOp), func(m *msg) { m.pduTag = tagGetBulk; m.b = 16 }), nextOp, after(), RulePDUType},
		"a value in a get":                {with(read(getOp), func(m *msg) { m.value = octets([]byte("x")) }), getOp, after(), RuleVarbindValue},
		// Lower levels.
		"authNoPriv":                          {with(read(getOp), func(m *msg) { m.flags = flagAuth | flagReportable }), getOp, after(), RuleSecurityLevel},
		"privacy without auth":                {with(read(getOp), func(m *msg) { m.flags = flagPriv | flagReportable }), getOp, after(), RuleSecurityLevel},
		"noAuthNoPriv get":                    {with(read(getOp), func(m *msg) { m.flags = flagReportable; m.plain = true }), getOp, after(), RuleSecurityLevel},
		"discovery after the engine is known": {d, getOp, after(), RuleSecurityLevel},
		"authPriv before discovery":           {read(getOp), getOp, before(), RuleEngineID},
		// v1 and v2c, whole messages (HR-17).
		"v1 GetRequest":        {msg{version: 0, community: "public", pduTag: tagGet, oids: []string{sysDescr}}, getOp, after(), RuleVersion},
		"v2c GetRequest":       {msg{version: 1, community: "public", pduTag: tagGet, oids: []string{sysDescr}}, getOp, after(), RuleVersion},
		"v2c before discovery": {msg{version: 1, community: "public", pduTag: tagGet, oids: []string{sysDescr}}, getOp, before(), RuleVersion},
		// The session.
		"another engine ID":             {with(read(getOp), func(m *msg) { m.engineID = append([]byte{}, testEngine[:10]...) }), getOp, after(), RuleEngineID},
		"another user":                  {with(read(getOp), func(m *msg) { m.user = "admin" }), getOp, after(), RuleUserName},
		"another security model":        {with(read(getOp), func(m *msg) { m.model = 2 }), getOp, after(), RuleSecurityModel},
		"msgMaxSize not the register's": {with(read(getOp), func(m *msg) { m.maxSize = 65507 }), getOp, after(), RuleMaxSize},
		"context name":                  {with(read(getOp), func(m *msg) { m.ctxName = "vlan1" }), getOp, after(), RuleContext},
		"context engine":                {with(read(getOp), func(m *msg) { m.ctxEngine = []byte{1, 2, 3, 4, 5} }), getOp, after(), RuleContext},
		"error-status on a get":         {with(read(getOp), func(m *msg) { m.a = 1 }), getOp, after(), RulePDUFields},
		// OIDs outside the operation (rules 4 and 5).
		"a get with an OID not named":        {with(read(getOp), func(m *msg) { m.oids = []string{sysDescr, "1.3.6.1.2.1.1.6.0"} }), getOp, after(), RuleOIDNotNamed},
		"a get of a named OID's parent":      {with(read(getOp), func(m *msg) { m.oids = []string{"1.3.6.1.2.1.1.1"} }), getOp, after(), RuleOIDNotNamed},
		"a get with no varbind":              {with(read(getOp), func(m *msg) { m.oids = nil }), getOp, after(), RuleVarbindCount},
		"a walk outside its subtree":         {with(read(bulkOp), func(m *msg) { m.oids = []string{"1.3.6.1.6.3.15.1.2.2"} }), bulkOp, after(), RuleOIDOutside},
		"a steered walk, sibling arc":        {with(read(bulkOp), func(m *msg) { m.oids = []string{"1.3.6.1.2.1.47.1.1.10"} }), bulkOp, after(), RuleOIDOutside},
		"a walk above its subtree":           {with(read(nextOp), func(m *msg) { m.oids = []string{"1.3.6.1.2.1.47.1.1"} }), nextOp, after(), RuleOIDOutside},
		"a walk of two varbinds":             {with(read(bulkOp), func(m *msg) { m.oids = []string{entityTbl, entityTbl + ".1"} }), bulkOp, after(), RuleVarbindCount},
		"max-repetitions not the register's": {with(read(bulkOp), func(m *msg) { m.b = 32 }), bulkOp, after(), RuleMaxRepetitions},
		"non-repeaters not 0":                {with(read(bulkOp), func(m *msg) { m.a = 1 }), bulkOp, after(), RuleNonRepeaters},
		// RFC 2578 section 3.5: at most 128 sub-identifiers, so an OID of
		// 129 inside the subtree is not an OID at all.
		"a walk continuation of 129 arcs": {with(read(bulkOp), func(m *msg) { m.oids = []string{arcs(entityTbl, 129)} }), bulkOp, after(), RuleBER},
		// The discovery shape, one field off at a time (13 near misses).
		"discovery: msgVersion 1":        {with(d, func(m *msg) { m.version = 1 }), getOp, before(), RuleVersion},
		"discovery: security model 2":    {with(d, func(m *msg) { m.model = 2 }), getOp, before(), RuleSecurityModel},
		"discovery: reportable cleared":  {with(d, func(m *msg) { m.flags = 0 }), getOp, before(), "discovery_shape.reportable"},
		"discovery: an engine ID":        {with(d, func(m *msg) { m.engineID = testEngine }), getOp, before(), "discovery_shape.engine_id"},
		"discovery: nonzero boots":       {with(d, func(m *msg) { m.boots = 1 }), getOp, before(), "discovery_shape.boots"},
		"discovery: nonzero time":        {with(d, func(m *msg) { m.time = 1 }), getOp, before(), "discovery_shape.time"},
		"discovery: a user name":         {with(d, func(m *msg) { m.user = "otsec-ro" }), getOp, before(), "discovery_shape.user_name"},
		"discovery: auth parameters":     {with(d, func(m *msg) { m.authP = make([]byte, 48) }), getOp, before(), "discovery_shape.auth_params"},
		"discovery: privacy parameters":  {with(d, func(m *msg) { m.privP = testSalt }), getOp, before(), "discovery_shape.priv_params"},
		"discovery: a context engine ID": {with(d, func(m *msg) { m.ctxEngine = testEngine }), getOp, before(), "discovery_shape.context_engine_id"},
		"discovery: a context name":      {with(d, func(m *msg) { m.ctxName = "x" }), getOp, before(), "discovery_shape.context_name"},
		"discovery: a GetNextRequest":    {with(d, func(m *msg) { m.pduTag = tagGetNext }), getOp, before(), "discovery_shape.pdu_type"},
		"discovery: one varbind":         {with(d, func(m *msg) { m.oids = []string{sysDescr} }), getOp, before(), "discovery_shape.varbinds"},
		"discovery: a SetRequest":        {with(d, func(m *msg) { m.pduTag = 0xa3 }), getOp, before(), "discovery_shape.pdu_type"},
		// A second scoped PDU hidden after the first, inside the encryption
		// (C6 on #449). CFB needs no padding, so any byte there is refused.
		"a SetRequest after the scoped PDU": {with(read(getOp), func(m *msg) {
			m.afterScoped = enc(0x30, octets(testEngine), octets(nil), enc(0xa3, encInt(5), encInt(0), encInt(0), enc(0x30, enc(0x30, encOID(sysName), encInt(1)))))
		}), getOp, after(), RuleBER},
		"one byte after the scoped PDU": {with(read(getOp), func(m *msg) { m.afterScoped = []byte{0} }), getOp, after(), RuleBER},
	}
	for name, c := range cases {
		if r := Check(c.m.bytes(), c.op, c.s); r != c.rule {
			t.Errorf("%s: got %q, want %q", name, r, c.rule)
		}
	}
}

// TestHostileBytes: malformed messages are refused as ber, never accepted and
// never a panic.
func TestHostileBytes(t *testing.T) {
	good := read(getOp).bytes()
	cases := map[string][]byte{
		"empty":               nil,
		"truncated":           good[:len(good)-1],
		"trailing byte":       append(append([]byte{}, good...), 0),
		"length past end":     append([]byte{0x30, 0x7f}, good[2:]...),
		"indefinite length":   append([]byte{0x30, 0x80}, good[2:]...),
		"non-minimal length":  append([]byte{0x30, 0x81, good[1]}, good[2:]...),
		"multi-byte tag":      {0x3f, 0x01, 0x00},
		"not a sequence":      {0x04, 0x00},
		"integer of 9 bytes":  enc(0x30, enc(0x02, make([]byte, 9))),
		"non-minimal integer": enc(0x30, enc(0x02, []byte{0, 3})),
	}
	for name, b := range cases {
		if r := Check(b, getOp, after()); r != RuleBER && r != RuleVersion {
			t.Errorf("%s: got %q", name, r)
		}
	}
	// An OID with a non-minimal arc, an arc of 2^32, and one that ends mid
	// arc.
	for name, o := range map[string][]byte{
		"leading 0x80":   {0x2b, 0x80, 0x01},
		"arc of 2^32":    {0x2b, 0x90, 0x80, 0x80, 0x80, 0x00},
		"unfinished arc": {0x2b, 0x86},
		"empty":          {},
	} {
		if _, err := oid(o); err == nil {
			t.Errorf("oid %s accepted", name)
		}
	}
	if s, err := oid([]byte{0x2b, 0x06, 0x01, 0x8f, 0xff, 0xff, 0xff, 0x7f}); err != nil || s != "1.3.6.1.4294967295" {
		t.Errorf("largest arc: %q, %v", s, err)
	}
}

// FuzzCheck: whatever the bytes, Check returns and never panics.
func FuzzCheck(f *testing.F) {
	f.Add(read(getOp).bytes())
	f.Add(read(bulkOp).bytes())
	f.Add(discovery().bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		Check(b, bulkOp, after())
		Check(b, getOp, before())
	})
}
