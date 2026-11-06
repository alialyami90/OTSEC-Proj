package snmpv3

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The BER subset SNMPv3 uses (RFC 3416 §2 via X.690): single-octet tags,
// definite lengths of at most four length octets, and the universal,
// application and context types below. Anything else is a decode error.
// Elements are sub-slices of the input: the decoder copies nothing, and the
// message parser reads a fixed shape, so nesting is bounded by the shape.

const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30

	tagIPAddress = 0x40
	tagCounter32 = 0x41
	tagGauge32   = 0x42
	tagTimeTicks = 0x43
	tagOpaque    = 0x44
	tagCounter64 = 0x46

	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82

	tagGetRequest     = 0xA0
	tagGetNextRequest = 0xA1
	tagResponse       = 0xA2
	tagSetRequest     = 0xA3
	tagGetBulkRequest = 0xA5
	tagInformRequest  = 0xA6
	tagTrap           = 0xA7
	tagReport         = 0xA8
)

// maxOIDArcs matches C3 0.4's bound on an OID.
const maxOIDArcs = 128

var errBER = errors.New("snmpv3: malformed BER")

// elem is one decoded TLV. Off is the offset of its tag in the buffer it was
// decoded from, and Val its contents, a sub-slice of that buffer.
type elem struct {
	Tag byte
	Off int
	Hdr int // tag and length octets
	Val []byte
}

// End is the offset just past the element.
func (e elem) End() int { return e.Off + e.Hdr + len(e.Val) }

// ValOff is the offset of the contents.
func (e elem) ValOff() int { return e.Off + e.Hdr }

// decode reads one element of b starting at off.
func decode(b []byte, off int) (elem, error) {
	if off < 0 || off+2 > len(b) {
		return elem{}, fmt.Errorf("%w: truncated at %d", errBER, off)
	}
	tag := b[off]
	if tag&0x1F == 0x1F {
		return elem{}, fmt.Errorf("%w: multi-octet tag at %d", errBER, off)
	}
	n, hdr := int(b[off+1]), 2
	if n&0x80 != 0 {
		k := n & 0x7F
		if k == 0 || k > 4 {
			return elem{}, fmt.Errorf("%w: length form 0x%02x at %d", errBER, b[off+1], off)
		}
		if off+2+k > len(b) {
			return elem{}, fmt.Errorf("%w: truncated length at %d", errBER, off)
		}
		n = 0
		for _, c := range b[off+2 : off+2+k] {
			n = n<<8 | int(c)
		}
		hdr += k
	}
	if n < 0 || off+hdr+n > len(b) || off+hdr+n < off {
		return elem{}, fmt.Errorf("%w: length %d past the end at %d", errBER, n, off)
	}
	return elem{Tag: tag, Off: off, Hdr: hdr, Val: b[off+hdr : off+hdr+n]}, nil
}

// children decodes the contents of a constructed element as a sequence of
// elements that fill it exactly. Offsets are in the buffer b the element
// came from.
func children(b []byte, e elem) ([]elem, error) {
	if e.Tag&0x20 == 0 {
		return nil, fmt.Errorf("%w: tag 0x%02x at %d is not constructed", errBER, e.Tag, e.Off)
	}
	var out []elem
	for off := e.ValOff(); off < e.End(); {
		c, err := decode(b, off)
		if err != nil {
			return nil, err
		}
		if c.End() > e.End() {
			return nil, fmt.Errorf("%w: element at %d overruns its parent", errBER, off)
		}
		out = append(out, c)
		off = c.End()
	}
	return out, nil
}

// expect decodes the children of e and checks their count and tags.
func expect(b []byte, e elem, tags ...byte) ([]elem, error) {
	cs, err := children(b, e)
	if err != nil {
		return nil, err
	}
	if len(cs) != len(tags) {
		return nil, fmt.Errorf("%w: %d elements at %d, want %d", errBER, len(cs), e.Off, len(tags))
	}
	for i, c := range cs {
		if c.Tag != tags[i] {
			return nil, fmt.Errorf("%w: tag 0x%02x at %d, want 0x%02x", errBER, c.Tag, c.Off, tags[i])
		}
	}
	return cs, nil
}

// integer reads an INTEGER, at most 64 bits, two's complement.
func integer(e elem) (int64, error) {
	v := e.Val
	if len(v) == 0 || len(v) > 8 {
		return 0, fmt.Errorf("%w: integer of %d octets at %d", errBER, len(v), e.Off)
	}
	n := int64(int8(v[0]))
	for _, c := range v[1:] {
		n = n<<8 | int64(c)
	}
	return n, nil
}

// unsigned reads an unsigned value of at most bits bits: Counter32,
// Gauge32 and TimeTicks are 32, Counter64 is 64 and may take nine octets
// with a leading zero.
func unsigned(e elem, bits int) (uint64, error) {
	v := e.Val
	if len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) == 0 || len(v)*8 > bits || (len(e.Val) == len(v) && v[0]&0x80 != 0) {
		return 0, fmt.Errorf("%w: %d-bit unsigned of %d octets at %d", errBER, bits, len(e.Val), e.Off)
	}
	var n uint64
	for _, c := range v {
		n = n<<8 | uint64(c)
	}
	return n, nil
}

// oid reads an OBJECT IDENTIFIER as dotted decimal. Every arc is below 2^32
// and there are at most maxOIDArcs of them.
func oid(e elem) (string, error) {
	v := e.Val
	if len(v) == 0 {
		return "", fmt.Errorf("%w: empty OID at %d", errBER, e.Off)
	}
	var arcs []uint64
	var n uint64
	for i, c := range v {
		if n == 0 && c == 0x80 {
			return "", fmt.Errorf("%w: OID arc with a leading 0x80 at %d", errBER, e.Off+e.Hdr+i)
		}
		n = n<<7 | uint64(c&0x7F)
		if n > 0xFFFFFFFF+80 {
			return "", fmt.Errorf("%w: OID arc too large at %d", errBER, e.Off)
		}
		if c&0x80 == 0 {
			arcs = append(arcs, n)
			n = 0
		}
	}
	if v[len(v)-1]&0x80 != 0 {
		return "", fmt.Errorf("%w: OID ends inside an arc at %d", errBER, e.Off)
	}
	first := arcs[0]
	x, y := min(first/40, 2), first-40*min(first/40, 2)
	out := []string{strconv.FormatUint(x, 10), strconv.FormatUint(y, 10)}
	if y > 0xFFFFFFFF || len(arcs)+1 > maxOIDArcs {
		return "", fmt.Errorf("%w: OID out of bounds at %d", errBER, e.Off)
	}
	for _, a := range arcs[1:] {
		if a > 0xFFFFFFFF {
			return "", fmt.Errorf("%w: OID arc too large at %d", errBER, e.Off)
		}
		out = append(out, strconv.FormatUint(a, 10))
	}
	return strings.Join(out, "."), nil
}

// --- encoding ----------------------------------------------------------------

// tlvOf encodes one element with a minimal definite length.
func tlvOf(tag byte, val []byte) []byte {
	n := len(val)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n <= 0xFF:
		hdr = []byte{tag, 0x81, byte(n)}
	case n <= 0xFFFF:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		hdr = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(hdr, val...)
}

func seqOf(tag byte, parts ...[]byte) []byte {
	var v []byte
	for _, p := range parts {
		v = append(v, p...)
	}
	return tlvOf(tag, v)
}

// intOf encodes an INTEGER in the fewest octets.
func intOf(n int64) []byte {
	var v []byte
	for {
		v = append([]byte{byte(n)}, v...)
		if (n >= -128 && n < 128) || len(v) == 8 {
			break
		}
		n >>= 8
	}
	return tlvOf(tagInteger, v)
}

// oidOf encodes a dotted-decimal OID. It is called only with OIDs that
// register.ValidOID accepted or that the decoder produced.
func oidOf(s string) ([]byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > maxOIDArcs {
		return nil, fmt.Errorf("snmpv3: OID %q has %d arcs", s, len(parts))
	}
	arcs := make([]uint64, len(parts))
	for i, p := range parts {
		a, err := strconv.ParseUint(p, 10, 32)
		if err != nil || (len(p) > 1 && p[0] == '0') {
			return nil, fmt.Errorf("snmpv3: OID %q arc %q", s, p)
		}
		arcs[i] = a
	}
	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
		return nil, fmt.Errorf("snmpv3: OID %q first arcs", s)
	}
	var v []byte
	for _, a := range append([]uint64{arcs[0]*40 + arcs[1]}, arcs[2:]...) {
		var b []byte
		b = append(b, byte(a&0x7F))
		for a >>= 7; a > 0; a >>= 7 {
			b = append([]byte{byte(a&0x7F) | 0x80}, b...)
		}
		v = append(v, b...)
	}
	return tlvOf(tagOID, v), nil
}
