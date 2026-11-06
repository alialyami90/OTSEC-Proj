package snmpegress

import (
	"errors"
	"strconv"
	"strings"
)

// BER tags this check reads (RFC 3416, X.690).
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30
)

var errBER = errors.New("snmpegress: not strict BER")

// tlv is one decoded element: its tag and the bytes of its contents.
type tlv struct {
	tag   byte
	value []byte
}

// next reads one element from b and returns it and the rest. It accepts only
// what an SNMP encoder needs to write: a one-byte tag, a definite length in
// its shortest form, and contents inside b. Indefinite lengths, long-form
// lengths that fit the short form, leading zero length octets and lengths
// past the buffer are errors.
func next(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, errBER
	}
	tag, l := b[0], int(b[1])
	if tag&0x1f == 0x1f { // multi-byte tag
		return tlv{}, nil, errBER
	}
	b = b[2:]
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(b) < n || b[0] == 0 { // indefinite, too long, or not minimal
			return tlv{}, nil, errBER
		}
		l = 0
		for _, c := range b[:n] {
			l = l<<8 | int(c)
		}
		if l < 0x80 {
			return tlv{}, nil, errBER
		}
		b = b[n:]
	}
	if l > len(b) {
		return tlv{}, nil, errBER
	}
	return tlv{tag: tag, value: b[:l]}, b[l:], nil
}

// expect reads one element with the given tag.
func expect(b []byte, tag byte) ([]byte, []byte, error) {
	t, rest, err := next(b)
	if err != nil || t.tag != tag {
		return nil, nil, errBER
	}
	return t.value, rest, nil
}

// integer decodes a minimal two's-complement INTEGER of at most 8 bytes.
func integer(v []byte) (int64, error) {
	if len(v) == 0 || len(v) > 8 {
		return 0, errBER
	}
	if len(v) > 1 && ((v[0] == 0 && v[1]&0x80 == 0) || (v[0] == 0xff && v[1]&0x80 != 0)) {
		return 0, errBER
	}
	n := int64(int8(v[0]))
	for _, c := range v[1:] {
		n = n<<8 | int64(c)
	}
	return n, nil
}

// readInt reads one INTEGER element.
func readInt(b []byte) (int64, []byte, error) {
	v, rest, err := expect(b, tagInteger)
	if err != nil {
		return 0, nil, err
	}
	n, err := integer(v)
	return n, rest, err
}

// maxArcs is RFC 2578 section 3.5's most sub-identifiers in an OID.
const maxArcs = 128

// oid decodes an OBJECT IDENTIFIER into dotted decimal. Each sub-identifier
// is in its shortest base-128 form, every arc is below 2^32, and there are at
// most maxArcs arcs (RFC 2578 section 3.5).
func oid(v []byte) (string, error) {
	if len(v) == 0 {
		return "", errBER
	}
	var arcs []string
	var cur uint64
	start := true
	for i, c := range v {
		if start && c == 0x80 { // a leading 0x80 is not minimal
			return "", errBER
		}
		start = false
		cur = cur<<7 | uint64(c&0x7f)
		limit := uint64(1) << 32 // every arc is below 2^32
		if len(arcs) == 0 {
			limit += 80 // the first sub-identifier holds two arcs
		}
		if cur >= limit {
			return "", errBER
		}
		if c&0x80 != 0 {
			if i == len(v)-1 {
				return "", errBER
			}
			continue
		}
		if len(arcs) == 0 {
			first := uint64(2)
			if cur < 80 {
				first = cur / 40
			}
			arcs = append(arcs, strconv.FormatUint(first, 10), strconv.FormatUint(cur-first*40, 10))
		} else {
			arcs = append(arcs, strconv.FormatUint(cur, 10))
		}
		cur, start = 0, true
	}
	if len(arcs) > maxArcs {
		return "", errBER
	}
	return strings.Join(arcs, "."), nil
}
