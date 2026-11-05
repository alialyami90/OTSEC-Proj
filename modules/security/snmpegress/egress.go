// Package snmpegress is the collector's egress check for SNMPv3 (C11 section 4
// rules 1, 4 and 5; AP-5, AP-28; GT-MIB plan section 2.7). It decodes the
// final encoded message the SNMP client is about to send, with its own strict
// BER decoder and its own AES-128-CFB decryption of the scoped PDU, and
// refuses anything that is not a read the operation names. It is the second
// line after the register format, which cannot express a write.
//
// It is separate from the code that builds the message (modules/ied/snmpv3),
// imports nothing from it, and shares no encoder or decoder with it, so one
// bug cannot both build a wrong message and pass it (a test holds this). It
// sees the message exactly as it will leave, so whatever built it, a SET, a
// downgraded level, an OID outside the operation or a steered walk is refused
// before a byte is sent.
//
// Check returns "" for a message that may be sent, or the name of the rule
// that refused it. The names are stable, so GT-MIB's deny corpus can assert
// each one.
//
// Evidence class: simulated. The messages it has seen are the tests' own; no
// SNMP agent or device has been contacted.
package snmpegress

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"slices"
	"strings"
)

// Rule names a refusal. Closed list.
type Rule string

const (
	Allowed Rule = ""

	RuleBER            Rule = "ber"            // the message is not one strict BER SNMP message
	RuleVersion        Rule = "version"        // msgVersion is not 3: a v1 or v2c message, or anything else
	RuleSecurityModel  Rule = "security_model" // msgSecurityModel is not USM (3)
	RuleSecurityLevel  Rule = "security_level" // not authPriv, and not the exact discovery shape before the engine ID is known
	RuleEngineID       Rule = "engine_id"      // an authPriv message for an engine other than the pinned one
	RuleUserName       Rule = "user_name"      // an authPriv message for another user
	RuleMaxSize        Rule = "max_size"       // msgMaxSize is not the operation's max_reply_bytes
	RuleContext        Rule = "context"        // contextEngineID is not the engine, or contextName is not empty
	RulePDUType        Rule = "pdu_type"       // not the read PDU the operation names (a Set, Inform, Trap, Report or Response always)
	RulePDUFields      Rule = "pdu_fields"     // a Get or GetNext with a nonzero error-status or error-index
	RuleNonRepeaters   Rule = "non_repeaters"  // a GetBulk with non-repeaters other than 0
	RuleMaxRepetitions Rule = "max_repetitions"
	RuleVarbindValue   Rule = "varbind_value"       // a varbind whose value is not NULL
	RuleVarbindCount   Rule = "varbind_count"       // a walk request with other than one varbind, or a get with none
	RuleOIDNotNamed    Rule = "oid_not_named"       // a get with an OID its operation does not name
	RuleOIDOutside     Rule = "oid_outside_subtree" // a walk request outside its subtree
)

// discoveryPrefix starts every rule for a discovery-shaped message that is
// off in one field; the field follows, as in "discovery_shape.user_name".
const discoveryPrefix = "discovery_shape."

// PDU names the request PDU of an operation, as C3 0.4's register does.
type PDU string

const (
	Get     PDU = "get"
	GetNext PDU = "getnext"
	GetBulk PDU = "getbulk"
)

// Op is the operation a message is sent for: the register's SNMP operation,
// as the collector verified it.
type Op struct {
	PDU            PDU
	OIDs           []string // get only
	Subtree        string   // getnext and getbulk only
	MaxRepetitions int      // getbulk only
	MaxReplyBytes  int      // the msgMaxSize every request advertises
}

// Session is what the collector knows when it sends. Before discovery has
// answered, EngineKnown is false and only the discovery message may leave.
// After, EngineID is the pinned engine ID (the credential's, which discovery
// matched), and PrivKey the AES-128 key, so the check reads the scoped PDU
// itself.
type Session struct {
	EngineKnown bool
	EngineID    []byte
	UserName    string
	PrivKey     []byte
}

// msgFlags bits (RFC 3412).
const (
	flagAuth       = 0x01
	flagPriv       = 0x02
	flagReportable = 0x04
)

// PDU tags (RFC 3416).
const (
	tagGet     = 0xa0
	tagGetNext = 0xa1
	tagGetBulk = 0xa5
)

var pduTag = map[PDU]byte{Get: tagGet, GetNext: tagGetNext, GetBulk: tagGetBulk}

// header is a decoded SNMPv3 message up to its msgData.
type header struct {
	maxSize, model     int64
	flags              []byte
	engineID           []byte
	boots, time        int64
	user, authP, privP []byte
	data               []byte // the msgData element, tag included
}

// Check decides one encoded message. It is a pure function.
func Check(msg []byte, op Op, s Session) Rule {
	whole, rest, err := expect(msg, tagSequence)
	if err != nil || len(rest) != 0 {
		return RuleBER
	}
	version, rest, err := readInt(whole)
	if err != nil {
		return RuleBER
	}
	if version != 3 {
		return RuleVersion // a v1 (0) or v2c (1) message never reaches the rest
	}
	h, r := decodeHeader(rest)
	if r != Allowed {
		return r
	}
	if h.model != 3 {
		return RuleSecurityModel
	}
	if len(h.flags) != 1 {
		return RuleBER
	}
	switch f := h.flags[0] &^ flagReportable; {
	case f == flagAuth|flagPriv:
		return checkAuthPriv(h, op, s)
	case f == 0 && !s.EngineKnown:
		return checkDiscovery(h)
	default:
		return RuleSecurityLevel
	}
}

// decodeHeader reads msgGlobalData, msgSecurityParameters and msgData.
func decodeHeader(b []byte) (header, Rule) {
	var h header
	global, rest, err := expect(b, tagSequence)
	if err != nil {
		return h, RuleBER
	}
	var g []byte
	if _, g, err = readInt(global); err != nil { // msgID
		return h, RuleBER
	}
	if h.maxSize, g, err = readInt(g); err != nil {
		return h, RuleBER
	}
	if h.flags, g, err = expect(g, tagOctetString); err != nil {
		return h, RuleBER
	}
	if h.model, g, err = readInt(g); err != nil || len(g) != 0 {
		return h, RuleBER
	}
	secParams, rest, err := expect(rest, tagOctetString)
	if err != nil {
		return h, RuleBER
	}
	usm, extra, err := expect(secParams, tagSequence)
	if err != nil || len(extra) != 0 {
		return h, RuleBER
	}
	if h.engineID, usm, err = expect(usm, tagOctetString); err != nil {
		return h, RuleBER
	}
	if h.boots, usm, err = readInt(usm); err != nil {
		return h, RuleBER
	}
	if h.time, usm, err = readInt(usm); err != nil {
		return h, RuleBER
	}
	if h.user, usm, err = expect(usm, tagOctetString); err != nil {
		return h, RuleBER
	}
	if h.authP, usm, err = expect(usm, tagOctetString); err != nil {
		return h, RuleBER
	}
	if h.privP, usm, err = expect(usm, tagOctetString); err != nil || len(usm) != 0 {
		return h, RuleBER
	}
	if _, after, err := next(rest); err != nil || len(after) != 0 {
		return h, RuleBER
	}
	h.data = rest
	return h, Allowed
}

// checkDiscovery admits only RFC 3414 section 4's discovery message, every
// field fixed (C11 section 4 rule 1). Each field off names its own rule.
func checkDiscovery(h header) Rule {
	off := func(field string) Rule { return Rule(discoveryPrefix + field) }
	switch {
	case h.flags[0]&flagReportable == 0:
		return off("reportable")
	case len(h.engineID) != 0:
		return off("engine_id")
	case h.boots != 0:
		return off("boots")
	case h.time != 0:
		return off("time")
	case len(h.user) != 0:
		return off("user_name")
	case len(h.authP) != 0:
		return off("auth_params")
	case len(h.privP) != 0:
		return off("priv_params")
	}
	scoped, rest, err := expect(h.data, tagSequence)
	if err != nil || len(rest) != 0 {
		return RuleBER
	}
	ctxEngine, scoped, err := expect(scoped, tagOctetString)
	if err != nil {
		return RuleBER
	}
	ctxName, scoped, err := expect(scoped, tagOctetString)
	if err != nil {
		return RuleBER
	}
	switch {
	case len(ctxEngine) != 0:
		return off("context_engine_id")
	case len(ctxName) != 0:
		return off("context_name")
	}
	pdu, rest, err := next(scoped)
	if err != nil || len(rest) != 0 {
		return RuleBER
	}
	if pdu.tag != tagGet {
		return off("pdu_type")
	}
	binds, r := pduVarbinds(pdu.value, false)
	if r != Allowed {
		return r
	}
	if len(binds) != 0 {
		return off("varbinds")
	}
	return Allowed
}

// checkAuthPriv checks an authPriv request against the session and the
// operation, after decrypting its scoped PDU with the session's key.
func checkAuthPriv(h header, op Op, s Session) Rule {
	switch {
	case !s.EngineKnown || len(s.EngineID) == 0 || !bytes.Equal(h.engineID, s.EngineID):
		return RuleEngineID
	case string(h.user) != s.UserName:
		return RuleUserName
	case int(h.maxSize) != op.MaxReplyBytes:
		return RuleMaxSize
	case len(h.privP) != 8 || h.boots < 0 || h.boots > 1<<31-1 || h.time < 0 || h.time > 1<<31-1:
		return RuleBER
	}
	enc, rest, err := expect(h.data, tagOctetString)
	if err != nil || len(rest) != 0 || len(s.PrivKey) != 16 {
		return RuleBER
	}
	block, err := aes.NewCipher(s.PrivKey)
	if err != nil {
		return RuleBER
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:], uint32(h.boots))
	binary.BigEndian.PutUint32(iv[4:], uint32(h.time))
	copy(iv[8:], h.privP)
	plain := make([]byte, len(enc))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, enc) //nolint:staticcheck // RFC 3826 fixes CFB128
	scoped, _, err := expect(plain, tagSequence)               // RFC 3826 allows padding after the scoped PDU
	if err != nil {
		return RuleBER
	}
	ctxEngine, scoped, err := expect(scoped, tagOctetString)
	if err != nil {
		return RuleBER
	}
	ctxName, scoped, err := expect(scoped, tagOctetString)
	if err != nil {
		return RuleBER
	}
	if !bytes.Equal(ctxEngine, s.EngineID) || len(ctxName) != 0 {
		return RuleContext
	}
	pdu, rest, err := next(scoped)
	if err != nil || len(rest) != 0 {
		return RuleBER
	}
	want, ok := pduTag[op.PDU]
	if !ok || pdu.tag != want {
		return RulePDUType
	}
	binds, r := pduVarbinds(pdu.value, op.PDU == GetBulk)
	if r != Allowed {
		return r
	}
	if op.PDU == GetBulk {
		if r := checkBulkFields(pdu.value, op); r != Allowed {
			return r
		}
	}
	switch op.PDU {
	case Get:
		if len(binds) == 0 {
			return RuleVarbindCount
		}
		for _, o := range binds {
			if !slices.Contains(op.OIDs, o) {
				return RuleOIDNotNamed
			}
		}
	default:
		if len(binds) != 1 {
			return RuleVarbindCount
		}
		if binds[0] != op.Subtree && !strings.HasPrefix(binds[0], op.Subtree+".") || op.Subtree == "" {
			return RuleOIDOutside
		}
	}
	return Allowed
}

// pduVarbinds reads a request PDU's body: request-id, two integers and the
// varbind list, each varbind an OID with a NULL value. For a Get or GetNext
// the two integers must be 0 (error-status, error-index); a GetBulk's are
// checked by checkBulkFields.
func pduVarbinds(body []byte, bulk bool) ([]string, Rule) {
	_, b, err := readInt(body) // request-id
	if err != nil {
		return nil, RuleBER
	}
	a, b, err := readInt(b)
	if err != nil {
		return nil, RuleBER
	}
	c, b, err := readInt(b)
	if err != nil {
		return nil, RuleBER
	}
	if !bulk && (a != 0 || c != 0) {
		return nil, RulePDUFields
	}
	list, rest, err := expect(b, tagSequence)
	if err != nil || len(rest) != 0 {
		return nil, RuleBER
	}
	var oids []string
	for len(list) > 0 {
		var vb []byte
		if vb, list, err = expect(list, tagSequence); err != nil {
			return nil, RuleBER
		}
		name, vb, err := expect(vb, tagOID)
		if err != nil {
			return nil, RuleBER
		}
		o, err := oid(name)
		if err != nil {
			return nil, RuleBER
		}
		value, vb, err := next(vb)
		if err != nil || len(vb) != 0 {
			return nil, RuleBER
		}
		if value.tag != tagNull || len(value.value) != 0 {
			return nil, RuleVarbindValue
		}
		oids = append(oids, o)
	}
	return oids, Allowed
}

// checkBulkFields checks a GetBulk's non-repeaters (0) and max-repetitions
// (the register's value).
func checkBulkFields(body []byte, op Op) Rule {
	_, b, _ := readInt(body)
	nonRep, b, _ := readInt(b)
	maxRep, _, _ := readInt(b)
	switch {
	case nonRep != 0:
		return RuleNonRepeaters
	case maxRep != int64(op.MaxRepetitions):
		return RuleMaxRepetitions
	}
	return Allowed
}
