package agent

// GT-MIB's own BER, written from the texts and from nothing in the client:
// RFC 3417 section 8 (definite lengths only, primitive simple types), RFC
// 2578 section 2 (the application types) and RFC 3416 section 3 (the PDU
// tags and the exceptions).

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Tags. Universal: INTEGER 0x02, OCTET STRING 0x04, NULL 0x05, OBJECT
// IDENTIFIER 0x06, SEQUENCE 0x30. Application (RFC 2578 section 2):
// IpAddress [0] 0x40, Counter32 [1] 0x41, Gauge32 [2] 0x42, TimeTicks [3]
// 0x43, Opaque [4] 0x44, Counter64 [6] 0x46. The PDUs (RFC 3416 section 3)
// are context-specific and constructed, [0] to [8]. The exceptions (RFC 3416
// section 3, VarBind) are context-specific primitive NULLs [0] to [2].
const (
	TagInteger   = 0x02
	TagOctets    = 0x04
	TagNull      = 0x05
	TagOID       = 0x06
	TagSequence  = 0x30
	TagIPAddress = 0x40
	TagCounter32 = 0x41
	TagGauge32   = 0x42
	TagTimeTicks = 0x43
	TagOpaque    = 0x44
	TagCounter64 = 0x46

	PDUGet      = 0xa0
	PDUGetNext  = 0xa1
	PDUResponse = 0xa2
	PDUSet      = 0xa3
	PDUGetBulk  = 0xa5
	PDUInform   = 0xa6
	PDUTrap     = 0xa7
	PDUReport   = 0xa8

	NoSuchObject   = 0x80
	NoSuchInstance = 0x81
	EndOfMibView   = 0x82
)

// PDUName names a PDU tag for the log.
func PDUName(tag byte) string {
	switch tag {
	case PDUGet:
		return "GetRequest"
	case PDUGetNext:
		return "GetNextRequest"
	case PDUResponse:
		return "Response"
	case PDUSet:
		return "SetRequest"
	case PDUGetBulk:
		return "GetBulkRequest"
	case PDUInform:
		return "InformRequest"
	case PDUTrap:
		return "SNMPv2-Trap"
	case PDUReport:
		return "Report"
	case 0xa4:
		return "Trap-v1"
	}
	return fmt.Sprintf("tag-0x%02x", tag)
}

var errBER = errors.New("ber")

// TLV is one decoded element.
type TLV struct {
	Tag byte
	Val []byte
	Raw []byte // the whole encoding, header included
}

// readTLV reads one element from b and returns it and the rest. Only the
// definite form is accepted (RFC 3417 section 8 (1)); a long-form length
// with more octets than needed is permitted by the same paragraph and is
// accepted.
func readTLV(b []byte) (TLV, []byte, error) {
	if len(b) < 2 {
		return TLV{}, nil, fmt.Errorf("%w: truncated", errBER)
	}
	tag := b[0]
	if tag&0x1f == 0x1f {
		return TLV{}, nil, fmt.Errorf("%w: multi-octet tag", errBER)
	}
	n, h := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 {
			return TLV{}, nil, fmt.Errorf("%w: indefinite length", errBER)
		}
		if k > 4 || len(b) < 2+k {
			return TLV{}, nil, fmt.Errorf("%w: length of %d octets", errBER, k)
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		h += k
	}
	if n < 0 || len(b)-h < n {
		return TLV{}, nil, fmt.Errorf("%w: length %d past the end", errBER, n)
	}
	return TLV{Tag: tag, Val: b[h : h+n], Raw: b[:h+n]}, b[h+n:], nil
}

// readAll reads the elements that fill b exactly.
func readAll(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		t, rest, err := readTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		b = rest
	}
	return out, nil
}

// readOne reads one element that fills b exactly.
func readOne(b []byte) (TLV, error) {
	t, rest, err := readTLV(b)
	if err == nil && len(rest) != 0 {
		err = fmt.Errorf("%w: %d bytes after the element", errBER, len(rest))
	}
	return t, err
}

// seq reads a constructed element's children, checking the tag and count.
func seq(t TLV, tag byte, n int) ([]TLV, error) {
	if t.Tag != tag {
		return nil, fmt.Errorf("%w: tag 0x%02x, want 0x%02x", errBER, t.Tag, tag)
	}
	c, err := readAll(t.Val)
	if err != nil {
		return nil, err
	}
	if n >= 0 && len(c) != n {
		return nil, fmt.Errorf("%w: %d elements in 0x%02x, want %d", errBER, len(c), tag, n)
	}
	return c, nil
}

// Int decodes a two's-complement INTEGER (or an application integer) of at
// most 9 octets into an int64, refusing values that do not fit.
func Int(t TLV) (int64, error) {
	v := t.Val
	if len(v) == 0 || len(v) > 8 {
		return 0, fmt.Errorf("%w: integer of %d octets", errBER, len(v))
	}
	n := int64(int8(v[0]))
	for _, c := range v[1:] {
		n = n<<8 | int64(c)
	}
	return n, nil
}

// Uint decodes an unsigned application integer (Counter32, Gauge32,
// TimeTicks, Counter64): up to 9 octets with a leading zero.
func Uint(t TLV) (uint64, error) {
	v := t.Val
	if len(v) == 9 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) == 0 || len(v) > 8 || (len(t.Val) < 9 && v[0]&0x80 != 0) {
		return 0, fmt.Errorf("%w: unsigned of %d octets", errBER, len(t.Val))
	}
	var n uint64
	for _, c := range v {
		n = n<<8 | uint64(c)
	}
	return n, nil
}

// OIDString decodes an OBJECT IDENTIFIER's contents to dotted form. The
// first subidentifier holds the first two arcs as X*40+Y.
func OIDString(v []byte) (string, error) {
	if len(v) == 0 {
		return "", fmt.Errorf("%w: empty OID", errBER)
	}
	var arcs []uint64
	var n uint64
	for i, c := range v {
		if n > 1<<56 {
			return "", fmt.Errorf("%w: OID arc too large", errBER)
		}
		n = n<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			arcs = append(arcs, n)
			n = 0
		} else if i == len(v)-1 {
			return "", fmt.Errorf("%w: OID ends inside an arc", errBER)
		}
	}
	first := arcs[0]
	var x uint64
	switch {
	case first < 40:
		x = 0
	case first < 80:
		x = 1
	default:
		x = 2
	}
	parts := []string{strconv.FormatUint(x, 10), strconv.FormatUint(first-40*x, 10)}
	for _, a := range arcs[1:] {
		parts = append(parts, strconv.FormatUint(a, 10))
	}
	return strings.Join(parts, "."), nil
}

// ParseOID parses a dotted OID.
func ParseOID(s string) ([]uint32, error) {
	ps := strings.Split(strings.TrimPrefix(s, "."), ".")
	if len(ps) < 2 {
		return nil, fmt.Errorf("OID %q: fewer than two arcs", s)
	}
	out := make([]uint32, len(ps))
	for i, p := range ps {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("OID %q: %v", s, err)
		}
		out[i] = uint32(v)
	}
	return out, nil
}

// CompareOID orders two dotted OIDs lexicographically by arc (RFC 3416
// section 4.2.2: the lexicographic successor).
func CompareOID(a, b string) int {
	x, _ := ParseOID(a)
	y, _ := ParseOID(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(x) < len(y):
		return -1
	case len(x) > len(y):
		return 1
	}
	return 0
}

// Under reports whether oid lies strictly under prefix.
func Under(oid, prefix string) bool { return strings.HasPrefix(oid, prefix+".") }

// --- encoding: always the minimal definite length ---

// Enc encodes one element.
func Enc(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	n := len(c)
	var h []byte
	switch {
	case n < 0x80:
		h = []byte{tag, byte(n)}
	case n < 0x100:
		h = []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		h = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		h = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(h, c...)
}

// EncInt encodes a minimal two's-complement integer under tag.
func EncInt(tag byte, n int64) []byte {
	b := []byte{byte(n)}
	for n >= 128 || n < -128 {
		n >>= 8
		b = append([]byte{byte(n)}, b...)
	}
	return Enc(tag, b)
}

// EncUint encodes an unsigned application integer, with a leading zero
// octet where the top bit is set (so a Counter64 of 2^63 or more takes 9).
func EncUint(tag byte, n uint64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
		if n == 0 {
			break
		}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return Enc(tag, b)
}

// EncOctets encodes an OCTET STRING.
func EncOctets(b []byte) []byte { return Enc(TagOctets, b) }

// EncOID encodes a dotted OID.
func EncOID(s string) []byte {
	arcs, err := ParseOID(s)
	if err != nil {
		panic(err)
	}
	subs := append([]uint64{uint64(arcs[0])*40 + uint64(arcs[1])}, u64(arcs[2:])...)
	var out []byte
	for _, v := range subs {
		e := []byte{byte(v & 0x7f)}
		for v >>= 7; v > 0; v >>= 7 {
			e = append([]byte{byte(v&0x7f) | 0x80}, e...)
		}
		out = append(out, e...)
	}
	return Enc(TagOID, out)
}

func u64(a []uint32) []uint64 {
	out := make([]uint64, len(a))
	for i, v := range a {
		out[i] = uint64(v)
	}
	return out
}

// Null is the encoded NULL.
var Null = []byte{TagNull, 0}
