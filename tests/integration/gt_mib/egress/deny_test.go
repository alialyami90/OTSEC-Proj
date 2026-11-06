// Package egress runs GT-MIB's egress deny corpus (docs/phase4/C6-gt-mib-plan.md
// section 2.7) against C3's egress check, case by case. No agent is
// involved: each case is one encoded message, built here with C6's own
// encoder, and the check must refuse it with the named rule.
//
// Every refused case is a valid message with one field changed. The valid
// messages are checked first and must be allowed, so a case cannot pass by
// being refused for some other reason.
//
// The message layout follows RFC 3412 (msgGlobalData), RFC 3414 (USM and the
// discovery message), RFC 3416 (the PDUs), RFC 3826 (AES-128-CFB) and RFC
// 2578 section 3.5 (at most 128 sub-identifiers). It was first written from
// memory; D6 checked it against the texts in /mnt/project-files/rfc/ on
// 2026-11-06 (D4-58), and it holds. A layout error here would make the
// valid messages fail, which the positive cases catch.
//
// Evidence class: simulated. No agent or device is contacted.
package egress

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/modules/security/snmpegress"
)

func tlv(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	n := len(c)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, c...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, c...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, c...)
	}
}

func integer(n int64) []byte {
	// Minimal two's complement: stop once the rest is all sign bits and the
	// top bit of the last byte written agrees with them.
	b := []byte{byte(n)}
	for n >= 128 || n < -128 {
		n >>= 8
		b = append([]byte{byte(n)}, b...)
	}
	return tlv(0x02, b)
}

func str(b []byte) []byte { return tlv(0x04, b) }

func oid(s string) []byte {
	var arcs []uint64
	for _, p := range strings.Split(s, ".") {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			panic(s)
		}
		arcs = append(arcs, v)
	}
	subs := append([]uint64{arcs[0]*40 + arcs[1]}, arcs[2:]...)
	var out []byte
	for _, v := range subs {
		enc := []byte{byte(v & 0x7f)}
		for v >>= 7; v > 0; v >>= 7 {
			enc = append([]byte{byte(v&0x7f) | 0x80}, enc...)
		}
		out = append(out, enc...)
	}
	return tlv(0x06, out)
}

var null = []byte{0x05, 0x00}

// PDU tags (RFC 3416, unconfirmed).
const (
	pduGet      = 0xa0
	pduGetNext  = 0xa1
	pduResponse = 0xa2
	pduSet      = 0xa3
	pduGetBulk  = 0xa5
	pduInform   = 0xa6
	pduTrap     = 0xa7
	pduReport   = 0xa8
)

// msg is one SNMPv3 message, field by field. A case is a valid msg with one
// field changed.
type msg struct {
	version, msgID, maxSize int64
	flags                   byte
	model                   int64
	engineID                []byte
	boots, time             int64
	user, authP, privP      []byte
	ctxEngine, ctxName      []byte
	pdu                     byte
	reqID, f1, f2           int64 // error-status and error-index, or non-repeaters and max-repetitions
	oids                    []string
	value                   []byte // each varbind's value; NULL unless a case changes it
	encrypt                 bool
	afterScoped             []byte // bytes after the scoped PDU, inside the encryption
	afterMessage            []byte // bytes after the whole message
}

var (
	engine  = []byte{0x80, 0x00, 0x7c, 0x4f, 0x03, 0x02, 0x00, 0x00, 0x27, 0x31, 0x01} // GT-MIB's engine ID (plan 1.1)
	user    = []byte("gt-mib")
	privKey = []byte("gt-mib-test-key!") // 16 bytes, a test key held by this test only
	digest  = make([]byte, 24)           // HMAC-SHA-256-192's length; the check does not verify it
	salt    = []byte{0, 0, 0, 0, 0, 0, 0, 7}
)

const (
	sysDescr = "1.3.6.1.2.1.1.1.0"
	sysName  = "1.3.6.1.2.1.1.5.0"
	entity   = "1.3.6.1.2.1.47.1.1.1"
)

// The register's two operations for the SEL-2731/2741 in RSTP mode (C3 0.4,
// contracts/adapter/testdata/snmp/register.json).
var (
	opGet  = snmpegress.Op{PDU: snmpegress.Get, OIDs: []string{sysDescr, sysName}, MaxReplyBytes: 1472}
	opBulk = snmpegress.Op{PDU: snmpegress.GetBulk, Subtree: entity, MaxRepetitions: 16, MaxReplyBytes: 1472}
	before = snmpegress.Session{}
	after  = snmpegress.Session{EngineKnown: true, EngineID: engine, UserName: string(user), PrivKey: privKey}
)

func (m msg) encode() []byte {
	var binds []byte
	for _, o := range m.oids {
		v := m.value
		if v == nil {
			v = null
		}
		binds = append(binds, tlv(0x30, oid(o), v)...)
	}
	pdu := tlv(m.pdu, integer(m.reqID), integer(m.f1), integer(m.f2), tlv(0x30, binds))
	scoped := append(tlv(0x30, str(m.ctxEngine), str(m.ctxName), pdu), m.afterScoped...)
	data := scoped
	if m.encrypt {
		block, err := aes.NewCipher(privKey)
		if err != nil {
			panic(err)
		}
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:], uint32(m.boots))
		binary.BigEndian.PutUint32(iv[4:], uint32(m.time))
		copy(iv[8:], m.privP)
		out := make([]byte, len(scoped))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, scoped) //nolint:staticcheck // RFC 3826 fixes CFB128
		data = str(out)
	}
	global := tlv(0x30, integer(m.msgID), integer(m.maxSize), str([]byte{m.flags}), integer(m.model))
	usm := tlv(0x30, str(m.engineID), integer(m.boots), integer(m.time), str(m.user), str(m.authP), str(m.privP))
	return append(tlv(0x30, integer(m.version), global, str(usm), data), m.afterMessage...)
}

// discovery is RFC 3414's discovery message: reportable, noAuthNoPriv, empty
// USM fields and context, and a GetRequest with no varbinds.
func discovery() msg {
	return msg{version: 3, msgID: 101, maxSize: 1472, flags: 0x04, model: 3, pdu: pduGet, reqID: 1}
}

// get is the system get, authPriv, after discovery.
func get() msg {
	return msg{version: 3, msgID: 102, maxSize: 1472, flags: 0x07, model: 3, engineID: engine, boots: 3, time: 1200,
		user: user, authP: digest, privP: salt, ctxEngine: engine, pdu: pduGet, reqID: 2, oids: []string{sysDescr, sysName}, encrypt: true}
}

// bulk is the entity walk's first request, authPriv.
func bulk() msg {
	m := get()
	m.msgID, m.reqID, m.pdu, m.f1, m.f2, m.oids = 103, 3, pduGetBulk, 0, 16, []string{entity}
	return m
}

// continuation is a later request of the same walk, inside the subtree.
func continuation() msg {
	m := bulk()
	m.oids = []string{entity + ".2.6"}
	return m
}

type tcase struct {
	name string
	m    msg
	op   snmpegress.Op
	s    snmpegress.Session
	want snmpegress.Rule
}

func with(m msg, f func(*msg)) msg { f(&m); return m }

func corpus() []tcase {
	var cs []tcase
	add := func(name string, m msg, op snmpegress.Op, s snmpegress.Session, want snmpegress.Rule) {
		cs = append(cs, tcase{name, m, op, s, want})
	}
	near := func(field string) snmpegress.Rule { return snmpegress.Rule("discovery_shape." + field) }

	// The admitted messages.
	add("allowed: discovery before the engine ID is known", discovery(), opGet, before, snmpegress.Allowed)
	add("allowed: the system get", get(), opGet, after, snmpegress.Allowed)
	add("allowed: one OID of the get", with(get(), func(m *msg) { m.oids = []string{sysName} }), opGet, after, snmpegress.Allowed)
	add("allowed: the walk's first GetBulk", bulk(), opBulk, after, snmpegress.Allowed)
	add("allowed: a walk continuation inside the subtree", continuation(), opBulk, after, snmpegress.Allowed)

	// Section 2.7: PDU types no request may carry.
	for _, p := range []struct {
		name string
		tag  byte
	}{{"SetRequest", pduSet}, {"InformRequest", pduInform}, {"SNMPv2-Trap", pduTrap}, {"Report", pduReport}, {"GetResponse", pduResponse}} {
		add("pdu: "+p.name, with(get(), func(m *msg) { m.pdu = p.tag }), opGet, after, "pdu_type")
	}
	add("pdu: a SetRequest for an OID the get names, with a value", with(get(), func(m *msg) {
		m.pdu, m.oids, m.value = pduSet, []string{sysName}, str([]byte("x"))
	}), opGet, after, "pdu_type")
	add("pdu: a GetNext for an operation that names get", with(get(), func(m *msg) { m.pdu = pduGetNext }), opGet, after, "pdu_type")
	add("pdu: a Get for the walk", with(continuation(), func(m *msg) { m.pdu, m.f2 = pduGet, 0 }), opBulk, after, "pdu_type")

	// Section 2.7: the security level.
	add("level: authNoPriv", with(get(), func(m *msg) { m.flags, m.encrypt = 0x05, false }), opGet, after, "security_level")
	add("level: noAuthNoPriv that is not discovery", with(get(), func(m *msg) { m.flags, m.encrypt = 0x04, false }), opGet, after, "security_level")
	add("level: privacy without authentication", with(get(), func(m *msg) { m.flags = 0x06 }), opGet, after, "security_level")
	add("level: the discovery message after the engine ID is known", discovery(), opGet, after, "security_level")

	// Section 2.7: OIDs and the walk.
	add("oid: a get with an OID the operation does not name", with(get(), func(m *msg) { m.oids = []string{sysDescr, "1.3.6.1.2.1.1.3.0"} }), opGet, after, "oid_not_named")
	add("oid: a get with an OID that only extends a named one", with(get(), func(m *msg) { m.oids = []string{sysName + ".1"} }), opGet, after, "oid_not_named")
	add("oid: a walk continuation outside the subtree", with(continuation(), func(m *msg) { m.oids = []string{"1.3.6.1.2.1.47.1.2.1"} }), opBulk, after, "oid_outside_subtree")
	add("oid: a walk OID that shares the subtree's text but not its arcs", with(continuation(), func(m *msg) { m.oids = []string{entity + "0.1"} }), opBulk, after, "oid_outside_subtree")
	add("oid: a walk OID above the subtree", with(continuation(), func(m *msg) { m.oids = []string{"1.3.6.1.2.1.47.1.1"} }), opBulk, after, "oid_outside_subtree")
	// RFC 2578 section 3.5: at most 128 sub-identifiers. entity has 10 arcs.
	add("allowed: a walk continuation of 128 arcs", with(continuation(), func(m *msg) { m.oids = []string{entity + strings.Repeat(".1", 118)} }), opBulk, after, snmpegress.Allowed)
	add("ber: a walk continuation of 129 arcs inside the subtree", with(continuation(), func(m *msg) { m.oids = []string{entity + strings.Repeat(".1", 119)} }), opBulk, after, "ber")
	add("bulk: max-repetitions other than the register's", with(bulk(), func(m *msg) { m.f2 = 17 }), opBulk, after, "max_repetitions")
	add("bulk: non-repeaters other than 0", with(bulk(), func(m *msg) { m.f1 = 1 }), opBulk, after, "non_repeaters")

	// Section 2.7: whole community-based messages (HR-17). A v1 or v2c
	// GetRequest is SEQUENCE { version, community, PDU }.
	for _, v := range []struct {
		name    string
		version int64
	}{{"v1", 0}, {"v2c", 1}} {
		raw := tlv(0x30, integer(v.version), str([]byte("public")), tlv(pduGet, integer(9), integer(0), integer(0), tlv(0x30, tlv(0x30, oid(sysName), null))))
		cs = append(cs, tcase{name: "community: a " + v.name + " GetRequest", op: opGet, s: after, want: "version", m: msg{afterMessage: raw}})
	}

	// Section 2.7: the thirteen near misses of the discovery shape.
	add("near 1: msgVersion 1", with(discovery(), func(m *msg) { m.version = 1 }), opGet, before, "version")
	add("near 2: msgSecurityModel 2", with(discovery(), func(m *msg) { m.model = 2 }), opGet, before, "security_model")
	add("near 3: the reportable flag cleared", with(discovery(), func(m *msg) { m.flags = 0 }), opGet, before, near("reportable"))
	add("near 4: an authoritative engine ID", with(discovery(), func(m *msg) { m.engineID = engine }), opGet, before, near("engine_id"))
	add("near 5: nonzero boots", with(discovery(), func(m *msg) { m.boots = 1 }), opGet, before, near("boots"))
	add("near 6: nonzero time", with(discovery(), func(m *msg) { m.time = 1 }), opGet, before, near("time"))
	add("near 7: a user name", with(discovery(), func(m *msg) { m.user = user }), opGet, before, near("user_name"))
	add("near 8: authentication parameters", with(discovery(), func(m *msg) { m.authP = digest }), opGet, before, near("auth_params"))
	add("near 9: privacy parameters", with(discovery(), func(m *msg) { m.privP = salt }), opGet, before, near("priv_params"))
	add("near 10: a contextEngineID", with(discovery(), func(m *msg) { m.ctxEngine = engine }), opGet, before, near("context_engine_id"))
	add("near 11: a context name", with(discovery(), func(m *msg) { m.ctxName = []byte("c") }), opGet, before, near("context_name"))
	add("near 12: a GetNextRequest", with(discovery(), func(m *msg) { m.pdu = pduGetNext }), opGet, before, near("pdu_type"))
	add("near 13: one varbind", with(discovery(), func(m *msg) { m.oids = []string{sysName} }), opGet, before, near("varbinds"))

	// Beyond 2.7: the session, the scoped PDU and the encoding.
	add("session: another engine ID", with(get(), func(m *msg) { m.engineID = append([]byte{}, engine[:10]...) }), opGet, after, "engine_id")
	add("session: authPriv before discovery", get(), opGet, before, "engine_id")
	add("session: another user", with(get(), func(m *msg) { m.user = []byte("admin") }), opGet, after, "user_name")
	add("session: msgMaxSize not the register's", with(get(), func(m *msg) { m.maxSize = 65507 }), opGet, after, "max_size")
	add("scoped: a context name", with(get(), func(m *msg) { m.ctxName = []byte("vlan1") }), opGet, after, "context")
	add("scoped: another contextEngineID", with(get(), func(m *msg) { m.ctxEngine = engine[:10] }), opGet, after, "context")
	add("varbind: a value that is not NULL", with(get(), func(m *msg) { m.value = integer(1) }), opGet, after, "varbind_value")
	add("varbind: a get with none", with(get(), func(m *msg) { m.oids = nil }), opGet, after, "varbind_count")
	add("varbind: a walk request with two", with(continuation(), func(m *msg) { m.oids = []string{entity + ".2", entity + ".7"} }), opBulk, after, "varbind_count")
	add("pdu: a Get with error-status set", with(get(), func(m *msg) { m.f1 = 1 }), opGet, after, "pdu_fields")
	add("ber: bytes after the message", with(get(), func(m *msg) { m.afterMessage = []byte{0} }), opGet, after, "ber")
	add("ber: a second scoped PDU, a SetRequest, after the first inside the encryption", with(get(), func(m *msg) {
		m.afterScoped = tlv(0x30, str(engine), str(nil), tlv(pduSet, integer(4), integer(0), integer(0), tlv(0x30, tlv(0x30, oid(sysName), str([]byte("x"))))))
	}), opGet, after, "ber")
	return cs
}

func TestEgressDenyCorpus(t *testing.T) {
	for _, c := range corpus() {
		raw := c.m.encode()
		if c.m.version == 0 && c.m.model == 0 && c.m.afterMessage != nil && c.m.pdu == 0 {
			raw = c.m.afterMessage // a whole community-based message
		}
		if got := snmpegress.Check(raw, c.op, c.s); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestEgressBERForms: the strict-BER forms an encoder never writes, each
// applied to the outer SEQUENCE of a valid message: the discovery message,
// whose length fits one octet, and the system get, whose length takes the
// long form.
func TestEgressBERForms(t *testing.T) {
	disc, getMsg := discovery().encode(), get().encode()
	for _, v := range []struct {
		raw []byte
		s   snmpegress.Session
	}{{disc, before}, {getMsg, after}} {
		if r := snmpegress.Check(v.raw, opGet, v.s); r != snmpegress.Allowed {
			t.Fatalf("a valid message is refused: %q", r)
		}
	}
	if disc[1] >= 0x80 || getMsg[1] != 0x81 {
		t.Fatalf("length forms are not as the cases assume: %#x, %#x", disc[1], getMsg[1])
	}
	short, long := disc[2:], getMsg[3:]
	cases := []struct {
		name string
		raw  []byte
		s    snmpegress.Session
	}{
		{"a long-form length that fits the short form", append([]byte{0x30, 0x81, disc[1]}, short...), before},
		{"a long-form length with a leading zero octet", append([]byte{0x30, 0x82, 0x00, getMsg[2]}, long...), after},
		{"an indefinite length", append(append([]byte{0x30, 0x80}, short...), 0, 0), before},
		{"a length past the datagram", append([]byte{0x30, disc[1] + 1}, short...), before},
		{"a truncated message", getMsg[:len(getMsg)-1], after},
		{"an empty message", nil, after},
	}
	for _, c := range cases {
		if r := snmpegress.Check(c.raw, opGet, c.s); r != "ber" {
			t.Errorf("%s: got %q, want %q", c.name, r, "ber")
		}
	}
}
