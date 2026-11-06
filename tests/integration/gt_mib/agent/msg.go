package agent

// The SNMPv3 message (RFC 3412 section 6), its USM security parameters (RFC
// 3414 section 2.4), the ScopedPDU (RFC 3412 section 6) and the PDUs (RFC
// 3416 section 3). Community-based messages (RFC 1157 section 4, RFC 1901
// section 3) are decoded only so the log can show one was received.

import (
	"fmt"
)

// Flags (RFC 3412 section 6, HeaderData.msgFlags).
const (
	FlagAuth       = 0x01
	FlagPriv       = 0x02
	FlagReportable = 0x04
)

// Bind is one varbind: its name, and its value's tag and contents.
type Bind struct {
	OID string
	Tag byte
	Val []byte
}

// PDU is a decoded PDU. For a GetBulkRequest F1 and F2 are non-repeaters
// and max-repetitions; otherwise error-status and error-index.
type PDU struct {
	Tag    byte
	ReqID  int64
	F1, F2 int64
	Binds  []Bind
}

// Scoped is a decoded ScopedPDU.
type Scoped struct {
	CtxEngine []byte
	CtxName   []byte
	PDU       PDU
}

// Msg is a decoded message as received. Byte slices point into Raw.
type Msg struct {
	Raw     []byte
	Version int64

	// Community-based (version 0 or 1).
	Community []byte
	CommPDU   *PDU

	// SNMPv3.
	MsgID, MaxSize int64
	Flags          byte
	Model          int64
	SecParams      []byte
	EngineID       []byte
	Boots, Time    int64
	User           []byte
	AuthParams     []byte
	PrivParams     []byte
	authOff        int    // offset of AuthParams' contents in Raw
	Plain          []byte // the plaintext ScopedPDU's encoding, if not encrypted
	Encrypted      []byte // the encryptedPDU's contents, if encrypted
}

// offset is where sub starts inside whole; sub must be a subslice of whole.
func offset(whole, sub []byte) int { return cap(whole) - cap(sub) }

// DecodeMsg decodes the outer layers of a received datagram: everything a
// receiver can read before authentication.
func DecodeMsg(raw []byte) (*Msg, error) {
	raw = raw[:len(raw):len(raw)]
	top, err := readOne(raw)
	if err != nil {
		return nil, err
	}
	parts, err := seq(top, TagSequence, -1)
	if err != nil {
		return nil, err
	}
	if len(parts) < 1 || parts[0].Tag != TagInteger {
		return nil, fmt.Errorf("%w: no msgVersion", errBER)
	}
	m := &Msg{Raw: raw}
	if m.Version, err = Int(parts[0]); err != nil {
		return nil, err
	}
	if m.Version == 0 || m.Version == 1 {
		// RFC 1157 section 4 and RFC 1901 section 3: version, community, PDU.
		if len(parts) != 3 || parts[1].Tag != TagOctets {
			return nil, fmt.Errorf("%w: community message of %d parts", errBER, len(parts))
		}
		m.Community = parts[1].Val
		p, err := decodePDU(parts[2])
		if err != nil {
			return m, err
		}
		m.CommPDU = &p
		return m, nil
	}
	if len(parts) != 4 {
		return m, fmt.Errorf("%w: SNMPv3Message of %d parts", errBER, len(parts))
	}
	g, err := seq(parts[1], TagSequence, 4)
	if err != nil {
		return m, err
	}
	if m.MsgID, err = intOf(g[0]); err != nil {
		return m, err
	}
	if m.MaxSize, err = intOf(g[1]); err != nil {
		return m, err
	}
	if g[2].Tag != TagOctets || len(g[2].Val) != 1 {
		return m, fmt.Errorf("%w: msgFlags", errBER)
	}
	m.Flags = g[2].Val[0]
	if m.Model, err = intOf(g[3]); err != nil {
		return m, err
	}
	if parts[2].Tag != TagOctets {
		return m, fmt.Errorf("%w: msgSecurityParameters", errBER)
	}
	m.SecParams = parts[2].Val
	switch parts[3].Tag {
	case TagSequence:
		m.Plain = parts[3].Raw
	case TagOctets:
		m.Encrypted = parts[3].Val
	default:
		return m, fmt.Errorf("%w: msgData tag 0x%02x", errBER, parts[3].Tag)
	}
	if m.Model != 3 {
		return m, nil
	}
	// RFC 3414 section 3.2 step 1: the parameters must be a
	// UsmSecurityParameters.
	sp, err := readOne(m.SecParams)
	if err != nil {
		return m, err
	}
	u, err := seq(sp, TagSequence, 6)
	if err != nil {
		return m, err
	}
	for _, i := range []int{0, 3, 4, 5} {
		if u[i].Tag != TagOctets {
			return m, fmt.Errorf("%w: USM field %d", errBER, i)
		}
	}
	m.EngineID, m.User, m.AuthParams, m.PrivParams = u[0].Val, u[3].Val, u[4].Val, u[5].Val
	if m.Boots, err = intOf(u[1]); err != nil {
		return m, err
	}
	if m.Time, err = intOf(u[2]); err != nil {
		return m, err
	}
	m.authOff = offset(raw, m.AuthParams)
	return m, nil
}

func intOf(t TLV) (int64, error) {
	if t.Tag != TagInteger {
		return 0, fmt.Errorf("%w: tag 0x%02x, want INTEGER", errBER, t.Tag)
	}
	return Int(t)
}

// DecodeScoped decodes a ScopedPDU's encoding.
func DecodeScoped(b []byte) (Scoped, error) {
	t, err := readOne(b)
	if err != nil {
		return Scoped{}, err
	}
	c, err := seq(t, TagSequence, 3)
	if err != nil {
		return Scoped{}, err
	}
	if c[0].Tag != TagOctets || c[1].Tag != TagOctets {
		return Scoped{}, fmt.Errorf("%w: context", errBER)
	}
	p, err := decodePDU(c[2])
	return Scoped{CtxEngine: c[0].Val, CtxName: c[1].Val, PDU: p}, err
}

func decodePDU(t TLV) (PDU, error) {
	if t.Tag < 0xa0 || t.Tag > 0xa8 {
		return PDU{}, fmt.Errorf("%w: PDU tag 0x%02x", errBER, t.Tag)
	}
	c, err := seq(t, t.Tag, -1)
	if err != nil {
		return PDU{Tag: t.Tag}, err
	}
	if t.Tag == 0xa4 { // the SNMPv1 Trap-PDU has another layout
		return PDU{Tag: t.Tag}, nil
	}
	if len(c) != 4 {
		return PDU{Tag: t.Tag}, fmt.Errorf("%w: PDU of %d fields", errBER, len(c))
	}
	p := PDU{Tag: t.Tag}
	if p.ReqID, err = intOf(c[0]); err != nil {
		return p, err
	}
	if p.F1, err = intOf(c[1]); err != nil {
		return p, err
	}
	if p.F2, err = intOf(c[2]); err != nil {
		return p, err
	}
	vbs, err := seq(c[3], TagSequence, -1)
	if err != nil {
		return p, err
	}
	for _, vb := range vbs {
		kv, err := seq(vb, TagSequence, 2)
		if err != nil {
			return p, err
		}
		if kv[0].Tag != TagOID {
			return p, fmt.Errorf("%w: varbind name tag 0x%02x", errBER, kv[0].Tag)
		}
		o, err := OIDString(kv[0].Val)
		if err != nil {
			return p, err
		}
		p.Binds = append(p.Binds, Bind{OID: o, Tag: kv[1].Tag, Val: kv[1].Val})
	}
	return p, nil
}

// EncodePDU encodes a PDU.
func EncodePDU(p PDU) []byte {
	var binds []byte
	for _, b := range p.Binds {
		binds = append(binds, Enc(TagSequence, EncOID(b.OID), Enc(b.Tag, b.Val))...)
	}
	return Enc(p.Tag, EncInt(TagInteger, p.ReqID), EncInt(TagInteger, p.F1), EncInt(TagInteger, p.F2), Enc(TagSequence, binds))
}

// EncodeScoped encodes a ScopedPDU.
func EncodeScoped(s Scoped) []byte {
	return Enc(TagSequence, EncOctets(s.CtxEngine), EncOctets(s.CtxName), EncodePDU(s.PDU))
}

// Out is one SNMPv3 message to send, field by field, so a case can change
// any of them before it is encoded.
type Out struct {
	MsgID, MaxSize int64
	Flags          byte
	Model          int64
	EngineID       []byte
	Boots, Time    int64
	User           []byte
	Scoped         Scoped
	ScopedRaw      []byte // when set, sent instead of Scoped's encoding
	Salt           []byte // privacy parameters; 8 octets when encrypted
	PrivField      []byte // when set, sent as msgPrivacyParameters instead of Salt (H16)
	AuthLen        int    // when set, the MAC field's length instead of N
	BadMAC         bool   // flip a MAC bit after computing it
	Version        int64  // 0 means 3
}

// Encode builds the message. Authentication and encryption follow the
// flags, with u's keys.
func (o Out) Encode(u User) []byte {
	scoped := o.ScopedRaw
	if scoped == nil {
		scoped = EncodeScoped(o.Scoped)
	}
	data := scoped
	salt := o.Salt
	if o.Flags&FlagPriv != 0 {
		if salt == nil {
			salt = make([]byte, 8)
		}
		enc, err := aesCFB(u.PrivKey, uint32(o.Boots), uint32(o.Time), salt, scoped, true)
		if err != nil {
			panic(err)
		}
		data = EncOctets(enc)
	}
	n := o.AuthLen
	if n == 0 && o.Flags&FlagAuth != 0 {
		n = u.Auth.MACLen()
	}
	authP := make([]byte, n)
	privP := salt
	if o.PrivField != nil {
		privP = o.PrivField
	}
	usm := Enc(TagSequence, EncOctets(o.EngineID), EncInt(TagInteger, o.Boots), EncInt(TagInteger, o.Time),
		EncOctets(o.User), EncOctets(authP), EncOctets(privP))
	v := o.Version
	if v == 0 {
		v = 3
	}
	model := o.Model
	if model == 0 {
		model = 3
	}
	global := Enc(TagSequence, EncInt(TagInteger, o.MsgID), EncInt(TagInteger, o.MaxSize), EncOctets([]byte{o.Flags}), EncInt(TagInteger, model))
	whole := Enc(TagSequence, EncInt(TagInteger, v), global, EncOctets(usm), data)
	if o.Flags&FlagAuth != 0 && n > 0 {
		m, err := DecodeMsg(whole)
		if err != nil {
			panic(err)
		}
		mac := MAC(u.Auth, u.AuthKey, whole)
		if len(mac) > n {
			mac = mac[:n]
		}
		copy(whole[m.authOff:], mac)
		if o.BadMAC {
			whole[m.authOff] ^= 0x01
		}
	}
	return whole
}

// CheckMAC verifies a received message's MAC with u's key (RFC 7860
// section 4.2.2): the field must be N octets, and the HMAC over the message
// with the field zeroed must equal it.
func (m *Msg) CheckMAC(u User) bool {
	n := u.Auth.MACLen()
	if len(m.AuthParams) != n {
		return false
	}
	whole := append([]byte(nil), m.Raw...)
	for i := 0; i < n; i++ {
		whole[m.authOff+i] = 0
	}
	return string(MAC(u.Auth, u.AuthKey, whole)) == string(m.AuthParams)
}

// Decrypt returns the ScopedPDU's encoding of an encrypted message (RFC 3826
// section 3.3.2).
func (m *Msg) Decrypt(u User) ([]byte, error) {
	if len(m.PrivParams) != 8 {
		return nil, fmt.Errorf("privParameters of %d octets", len(m.PrivParams))
	}
	return aesCFB(u.PrivKey, uint32(m.Boots), uint32(m.Time), m.PrivParams, m.Encrypted, false)
}
