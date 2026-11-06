package snmpv3

import (
	"fmt"
)

// The SNMPv3 message (RFC 3412 §6) with the USM security parameters
// (RFC 3414 §2.4):
//
//	SEQUENCE {
//	  msgVersion INTEGER (3),
//	  msgGlobalData SEQUENCE { msgID, msgMaxSize, msgFlags OCTET STRING (1), msgSecurityModel (3) },
//	  msgSecurityParameters OCTET STRING containing
//	    SEQUENCE { engineID, boots, time, userName, authParams, privParams },
//	  msgData: ScopedPDU SEQUENCE { contextEngineID, contextName, PDU } | encryptedPDU OCTET STRING
//	}

const (
	version3 = 3
	modelUSM = 3

	flagAuth       = 0x01
	flagPriv       = 0x02
	flagReportable = 0x04
)

// usmParams are the USM security parameters.
type usmParams struct {
	EngineID   []byte
	Boots      int64
	Time       int64
	User       []byte
	AuthParams []byte
	PrivParams []byte
}

// message is one decoded SNMPv3 message. Offsets are in the wire bytes.
type message struct {
	MsgID   int64
	MaxSize int64
	Flags   byte
	USM     usmParams
	// AuthOff is the offset of msgAuthenticationParameters' contents, and
	// EngineIDOff of msgAuthoritativeEngineID's.
	AuthOff     int
	EngineIDOff int
	// Data is msgData: a SEQUENCE (plaintext) or an OCTET STRING
	// (encryptedPDU).
	Data elem
}

// encrypted reports whether msgData is the encryptedPDU choice.
func (m *message) encrypted() bool { return m.Data.Tag == tagOctetString }

// decodeMessage reads the header of an SNMPv3 message that fills b exactly.
// msgData is located but not decrypted or parsed.
func decodeMessage(b []byte) (*message, error) {
	top, err := decode(b, 0)
	if err != nil {
		return nil, err
	}
	if top.Tag != tagSequence || top.End() != len(b) {
		return nil, fmt.Errorf("%w: the message is not one SEQUENCE filling the datagram", errBER)
	}
	cs, err := children(b, top)
	if err != nil {
		return nil, err
	}
	if len(cs) != 4 || cs[0].Tag != tagInteger || cs[1].Tag != tagSequence || cs[2].Tag != tagOctetString ||
		(cs[3].Tag != tagSequence && cs[3].Tag != tagOctetString) {
		return nil, fmt.Errorf("%w: not an SNMPv3 message", errBER)
	}
	if v, err := integer(cs[0]); err != nil || v != version3 {
		return nil, fmt.Errorf("%w: msgVersion is not 3", errBER)
	}
	g, err := expect(b, cs[1], tagInteger, tagInteger, tagOctetString, tagInteger)
	if err != nil {
		return nil, err
	}
	m := &message{Data: cs[3]}
	if m.MsgID, err = integer(g[0]); err != nil || m.MsgID < 0 || m.MsgID > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: msgID", errBER)
	}
	if m.MaxSize, err = integer(g[1]); err != nil || m.MaxSize < 484 || m.MaxSize > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: msgMaxSize", errBER)
	}
	if len(g[2].Val) != 1 {
		return nil, fmt.Errorf("%w: msgFlags is not one octet", errBER)
	}
	m.Flags = g[2].Val[0]
	if m.Flags&flagPriv != 0 && m.Flags&flagAuth == 0 {
		return nil, fmt.Errorf("%w: privacy without authentication", errBER)
	}
	if v, err := integer(g[3]); err != nil || v != modelUSM {
		return nil, fmt.Errorf("%w: msgSecurityModel is not USM", errBER)
	}
	// The USM SEQUENCE is the whole contents of the OCTET STRING. Its
	// offsets are in b, because decode works on b.
	sp := cs[2]
	u, err := decode(b, sp.ValOff())
	if err != nil || u.Tag != tagSequence || u.End() != sp.End() {
		return nil, fmt.Errorf("%w: msgSecurityParameters is not one USM SEQUENCE", errBER)
	}
	us, err := expect(b, u, tagOctetString, tagInteger, tagInteger, tagOctetString, tagOctetString, tagOctetString)
	if err != nil {
		return nil, err
	}
	m.USM.EngineID, m.EngineIDOff = us[0].Val, us[0].ValOff()
	if m.USM.Boots, err = integer(us[1]); err != nil || m.USM.Boots < 0 || m.USM.Boots > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: msgAuthoritativeEngineBoots", errBER)
	}
	if m.USM.Time, err = integer(us[2]); err != nil || m.USM.Time < 0 || m.USM.Time > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: msgAuthoritativeEngineTime", errBER)
	}
	if len(us[0].Val) > 32 || len(us[3].Val) > 32 {
		return nil, fmt.Errorf("%w: engine ID or user name longer than 32 octets", errBER)
	}
	m.USM.User = us[3].Val
	m.USM.AuthParams, m.AuthOff = us[4].Val, us[4].ValOff()
	m.USM.PrivParams = us[5].Val
	return m, nil
}

// varbind is one variable binding. Value's offsets are in the buffer the
// scoped PDU was decoded from.
type varbind struct {
	OID   string
	Value elem
}

// pdu is a decoded PDU. For a GetBulkRequest, ErrStatus and ErrIndex hold
// non-repeaters and max-repetitions.
type pdu struct {
	Tag       byte
	RequestID int64
	ErrStatus int64
	ErrIndex  int64
	VarBinds  []varbind
}

// scoped is a decoded ScopedPDU.
type scoped struct {
	ContextEngineID []byte
	ContextName     []byte
	PDU             pdu
}

// decodeScoped reads a ScopedPDU that fills b exactly.
func decodeScoped(b []byte) (*scoped, error) {
	top, err := decode(b, 0)
	if err != nil {
		return nil, err
	}
	if top.Tag != tagSequence || top.End() != len(b) {
		return nil, fmt.Errorf("%w: the scoped PDU is not one SEQUENCE", errBER)
	}
	cs, err := children(b, top)
	if err != nil {
		return nil, err
	}
	if len(cs) != 3 || cs[0].Tag != tagOctetString || cs[1].Tag != tagOctetString {
		return nil, fmt.Errorf("%w: not a scoped PDU", errBER)
	}
	switch cs[2].Tag {
	case tagGetRequest, tagGetNextRequest, tagResponse, tagSetRequest, tagGetBulkRequest, tagInformRequest, tagTrap, tagReport:
	default:
		return nil, fmt.Errorf("%w: PDU tag 0x%02x", errBER, cs[2].Tag)
	}
	ps, err := expect(b, cs[2], tagInteger, tagInteger, tagInteger, tagSequence)
	if err != nil {
		return nil, err
	}
	s := &scoped{ContextEngineID: cs[0].Val, ContextName: cs[1].Val, PDU: pdu{Tag: cs[2].Tag}}
	for i, p := range []*int64{&s.PDU.RequestID, &s.PDU.ErrStatus, &s.PDU.ErrIndex} {
		if *p, err = integer(ps[i]); err != nil || *p < -0x80000000 || *p > 0x7FFFFFFF {
			return nil, fmt.Errorf("%w: PDU integer %d", errBER, i)
		}
	}
	vbs, err := children(b, ps[3])
	if err != nil {
		return nil, err
	}
	for _, v := range vbs {
		if v.Tag != tagSequence {
			return nil, fmt.Errorf("%w: varbind at %d is not a SEQUENCE", errBER, v.Off)
		}
		kv, err := children(b, v)
		if err != nil {
			return nil, err
		}
		if len(kv) != 2 || kv[0].Tag != tagOID {
			return nil, fmt.Errorf("%w: varbind at %d", errBER, v.Off)
		}
		o, err := oid(kv[0])
		if err != nil {
			return nil, err
		}
		if err := checkValue(kv[1]); err != nil {
			return nil, err
		}
		s.PDU.VarBinds = append(s.PDU.VarBinds, varbind{OID: o, Value: kv[1]})
	}
	return s, nil
}

// checkValue accepts the value types of RFC 3416 §3 and the three
// exceptions, each with contents of its type's form.
func checkValue(e elem) error {
	var err error
	switch e.Tag {
	case tagInteger:
		var n int64
		n, err = integer(e)
		if err == nil && (n < -0x80000000 || n > 0x7FFFFFFF) {
			err = fmt.Errorf("%w: Integer32 out of range at %d", errBER, e.Off)
		}
	case tagOctetString, tagOpaque:
		if len(e.Val) > 65535 {
			err = fmt.Errorf("%w: OCTET STRING above 65535 octets at %d", errBER, e.Off)
		}
	case tagOID:
		_, err = oid(e)
	case tagIPAddress:
		if len(e.Val) != 4 {
			err = fmt.Errorf("%w: IpAddress of %d octets at %d", errBER, len(e.Val), e.Off)
		}
	case tagCounter32, tagGauge32, tagTimeTicks:
		_, err = unsigned(e, 32)
	case tagCounter64:
		_, err = unsigned(e, 64)
	case tagNull, tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
		if len(e.Val) != 0 {
			err = fmt.Errorf("%w: NULL or exception with contents at %d", errBER, e.Off)
		}
	default:
		err = fmt.Errorf("%w: value tag 0x%02x at %d", errBER, e.Tag, e.Off)
	}
	return err
}

// --- encoding ----------------------------------------------------------------

// requestPDU encodes a read request. Only GetRequest, GetNextRequest and
// GetBulkRequest can be built: there is no encoder for any other PDU, so the
// client cannot write a SET (C3 0.4, V-M1 (b)). Every value is NULL.
func requestPDU(tag byte, requestID int64, a, b int64, oids []string) ([]byte, error) {
	switch tag {
	case tagGetRequest, tagGetNextRequest:
		if a != 0 || b != 0 {
			return nil, fmt.Errorf("snmpv3: a get or getnext has error-status and error-index 0")
		}
	case tagGetBulkRequest:
	default:
		return nil, fmt.Errorf("snmpv3: PDU tag 0x%02x is not a read request", tag)
	}
	var vbs [][]byte
	for _, o := range oids {
		ob, err := oidOf(o)
		if err != nil {
			return nil, err
		}
		vbs = append(vbs, seqOf(tagSequence, ob, tlvOf(tagNull, nil)))
	}
	return seqOf(tag, intOf(requestID), intOf(a), intOf(b), seqOf(tagSequence, vbs...)), nil
}

// scopedOf encodes a ScopedPDU.
func scopedOf(contextEngineID, contextName, p []byte) []byte {
	return seqOf(tagSequence, tlvOf(tagOctetString, contextEngineID), tlvOf(tagOctetString, contextName), p)
}

// messageOf encodes a message. data is the msgData element, already
// encoded: a scoped PDU or an encryptedPDU OCTET STRING. AuthParams holds
// the zeros the HMAC is computed over, or nothing.
func messageOf(msgID, maxSize int64, flags byte, u usmParams, data []byte) []byte {
	usm := seqOf(tagSequence, tlvOf(tagOctetString, u.EngineID), intOf(u.Boots), intOf(u.Time),
		tlvOf(tagOctetString, u.User), tlvOf(tagOctetString, u.AuthParams), tlvOf(tagOctetString, u.PrivParams))
	global := seqOf(tagSequence, intOf(msgID), intOf(maxSize), tlvOf(tagOctetString, []byte{flags}), intOf(modelUSM))
	return seqOf(tagSequence, intOf(version3), global, tlvOf(tagOctetString, usm), data)
}

// storedForm is the message as the transcript keeps it (C2 0.7, §2.4):
// msgData is the plaintext choice, the decrypted scoped PDU, in place of the
// encryptedPDU, and msgAuthenticationParameters is zero octets of the same
// length. Every other octet is the wire's, in the wire's encoding. It
// returns the stored bytes, the offset of the scoped PDU in them, and the
// offset and length of the zeroed digest (length 0 for none).
func storedForm(wire []byte, m *message, plain []byte) (out []byte, scopedOff, digestOff, digestLen int) {
	head := wire[:m.Data.Off]
	top, _ := decode(wire, 0)
	body := append(append([]byte(nil), head[top.Hdr:]...), plain...)
	out = tlvOf(tagSequence, body)
	shift := len(out) - len(body) - top.Hdr // the outer length may change size
	scopedOff = len(out) - len(plain)
	if n := len(m.USM.AuthParams); n > 0 {
		digestOff, digestLen = m.AuthOff+shift, n
		clear(out[digestOff : digestOff+n])
	}
	return out, scopedOff, digestOff, digestLen
}
