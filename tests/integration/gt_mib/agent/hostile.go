package agent

// The hostile corpus (the plan's section 2.6; ../cases.json "hostile"),
// written into the agent's replies at two layers:
//
//   - outer: the discovery Report, which is noAuthNoPriv with a plaintext
//     ScopedPDU (RFC 3414 section 4), so the client parses all of it before
//     any authentication and any host on the LAN can send it. H15 and H16
//     are fields of an authenticated message, so they go on the Responses
//     after the time-window round instead. The client must discard each
//     one; the run ends failed.timeout.
//   - scoped: the ScopedPDU of an authPriv Response, encrypted and
//     authenticated with the user's keys, so only a key holder can send it.
//     The run ends failed.snmp_scoped_pdu_unreadable.
//
// Every malformed reply is sent again for each retransmission. H12 (a
// long-form length with more octets than needed) is not hostile: RFC 3417
// section 8 (1) permits it, so it is a positive case at both layers.

import (
	"bytes"
	"encoding/binary"
	"strings"
)

type hostileDef struct {
	layers []string
	hook   func(layer string) Hook
}

var both = []string{"outer", "scoped"}

// hostile maps each corpus ID to where it is written. Defects that are
// ScopedPDU-shaped (H4, H6 to H10, H14) sit in the discovery Report's
// plaintext ScopedPDU at the outer layer; message-shaped ones (H1 to H3,
// H5, H11, H13) are cut into the whole message there.
var hostile = map[string]hostileDef{
	"H1": {both, layered(func(b []byte) []byte { return b[:len(b)-5] }, scopedBytes(func(s []byte) []byte { return s[:len(s)-5] }))},
	"H2": {both, layered(longer, scopedBytes(longer))},
	"H3": {both, layered(indefinite, scopedBytes(indefinite))},
	"H4": {both, scopedDefect(func(s Scoped) []byte { return withBind(s, Enc(TagSequence, EncOID(outside), nest(70))) })},
	"H5": {both, layered(bigMsgID, scopedDefect(func(s Scoped) []byte { return scopedRaw(s, Enc(TagInteger, bytes.Repeat([]byte{1}, 10)), nil) }))},
	"H6": {both, scopedDefect(func(s Scoped) []byte { return withValue(s, Enc(TagCounter64, bytes.Repeat([]byte{1}, 10))) })},
	"H7": {both, scopedDefect(func(s Scoped) []byte {
		return withValue(s, Enc(TagCounter64, append([]byte{0x80}, make([]byte, 8)...)))
	})},
	"H8": {both, scopedDefect(func(s Scoped) []byte { return withName(s, rawOID(EntPhysicalEntry, base128(1<<32))) })},
	"H9": {both, scopedDefect(func(s Scoped) []byte {
		return withName(s, EncOID("1.3"+strings.Repeat(".1", 127))) // 129 arcs
	})},
	"H10": {both, scopedDefect(func(s Scoped) []byte { return withName(s, Enc(TagOID, nil)) })},
	"H11": {both, layered(longEngineID, scopedDefect(func(s Scoped) []byte { return withValue(s, append([]byte{TagOctets, 0x81, 0xc8}, "short"...)) }))},
	"H12": {both, layered(longForm, scopedBytes(longForm))},
	"H13": {both, layered(func(b []byte) []byte { return append(b, 0, 0) }, scopedBytes(func(s []byte) []byte { return append(s, 0, 0) }))},
	"H14": {both, scopedDefect(func(s Scoped) []byte { return withName(s, rawOID(EntPhysicalEntry, []byte{0x80, 0x01})) })},
	"H15": {[]string{"outer"}, after(func(o *Out, x *Exchange) { o.AuthLen = x.User.Auth.MACLen() - 4 })},
	"H16": {[]string{"outer"}, after(func(o *Out, x *Exchange) {
		if o.Flags&FlagPriv != 0 {
			o.PrivField = o.Salt[:7]
		}
	})},
	"H17": {[]string{"scoped"}, func(string) Hook {
		// A SetRequest, then an SNMPv2-Trap, then an InformRequest, each
		// in place of the Response.
		return onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
			var out []Send
			for _, tag := range []byte{PDUSet, PDUTrap, PDUInform} {
				o := copyOut(a, x)
				o.Scoped.PDU.Tag = tag
				out = append(out, send(x, o))
			}
			return out
		})()
	}},
}

// layered uses outer on the whole encoded discovery Report at the outer
// layer, and scoped at the scoped layer.
func layered(outer func([]byte) []byte, scoped func(string) Hook) func(string) Hook {
	return func(layer string) Hook {
		if layer == "scoped" {
			return scoped(layer)
		}
		return func(a *Agent, x *Exchange) []Send {
			if x.Stage != "discovery" {
				return a.DefaultSend(x)
			}
			return []Send{{Bytes: outer(x.Out.Encode(x.User))}}
		}
	}
}

// parts splits an SNMPv3 message into its four elements' encodings.
func parts(b []byte) [][]byte {
	_, c := header(b)
	ts, err := readAll(c)
	if err != nil || len(ts) != 4 {
		panic("gt-mib: not an SNMPv3 message")
	}
	out := make([][]byte, 4)
	for i, t := range ts {
		out[i] = t.Raw
	}
	return out
}

// bigMsgID rewrites msgID as a 10-octet INTEGER (H5 at the outer layer).
func bigMsgID(b []byte) []byte {
	p := parts(b)
	_, g := header(p[1])
	ts, _ := readAll(g)
	global := Enc(TagSequence, Enc(TagInteger, bytes.Repeat([]byte{1}, 10)), ts[1].Raw, ts[2].Raw, ts[3].Raw)
	return Enc(TagSequence, p[0], global, p[2], p[3])
}

// longEngineID makes the security parameters' engine ID an OCTET STRING
// that claims 200 octets, more than its message holds (H11 at the outer
// layer); every enclosing length is the true one.
func longEngineID(b []byte) []byte {
	p := parts(b)
	_, sp := header(p[2])
	_, usm := header(sp)
	ts, _ := readAll(usm)
	var rest []byte
	for _, t := range ts[1:] {
		rest = append(rest, t.Raw...)
	}
	bad := append([]byte{TagOctets, 0x81, 0xc8}, ts[0].Val...)
	return Enc(TagSequence, p[0], p[1], EncOctets(Enc(TagSequence, bad, rest)), p[3])
}

// scopedDefect writes raw(s) as the ScopedPDU: at the outer layer in the
// discovery Report (plaintext), at the scoped layer in every authPriv
// Response (encrypted and authenticated).
func scopedDefect(raw func(Scoped) []byte) func(string) Hook {
	return func(layer string) Hook {
		if layer == "outer" {
			return func(a *Agent, x *Exchange) []Send {
				if x.Stage != "discovery" {
					return a.DefaultSend(x)
				}
				o := *x.Out
				o.ScopedRaw = raw(o.Scoped)
				return []Send{send(x, &o)}
			}
		}
		return onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
			o := copyOut(a, x)
			o.ScopedRaw = raw(o.Scoped)
			return []Send{send(x, o)}
		})()
	}
}

// scopedBytes cuts the encoded ScopedPDU of every authPriv Response.
func scopedBytes(cut func([]byte) []byte) func(string) Hook {
	return scopedDefect(func(s Scoped) []byte { return cut(EncodeScoped(s)) })
}

// after changes every Response after the time-window round. The
// time-window Report itself is left intact: an unauthenticated one would
// end the run as usm_not_in_time_window (U9), not as the discard H15 and
// H16 test.
func after(change func(o *Out, x *Exchange)) func(string) Hook {
	return func(string) Hook {
		return onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
			o := copyOut(a, x)
			change(o, x)
			return []Send{send(x, o)}
		})()
	}
}

// --- byte surgery ---

// header splits an element's encoding into tag, contents and the rest.
func header(b []byte) (tag byte, content []byte) {
	t, _, err := readTLV(b)
	if err != nil {
		panic(err)
	}
	return t.Tag, t.Val
}

// longer rewrites the outermost length to claim 20 more octets than there
// are (H2).
func longer(b []byte) []byte {
	tag, c := header(b)
	n := len(c) + 20
	return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, c...)
}

// indefinite rewrites the outermost element in the indefinite form, with
// its end-of-contents octets (H3).
func indefinite(b []byte) []byte {
	tag, c := header(b)
	return append(append([]byte{tag, 0x80}, c...), 0, 0)
}

// longForm rewrites the outermost length with four length octets, more
// than it needs (H12, permitted by RFC 3417 section 8 (1)).
func longForm(b []byte) []byte {
	tag, c := header(b)
	h := []byte{tag, 0x84, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[2:], uint32(len(c)))
	return append(h, c...)
}

// nest is a NULL inside n SEQUENCEs (H4).
func nest(n int) []byte {
	b := Null
	for i := 0; i < n; i++ {
		b = Enc(TagSequence, b)
	}
	return b
}

// base128 is one sub-identifier in base 128.
func base128(v uint64) []byte {
	b := []byte{byte(v & 0x7f)}
	for v >>= 7; v > 0; v >>= 7 {
		b = append([]byte{byte(v&0x7f) | 0x80}, b...)
	}
	return b
}

// rawOID is prefix's encoding with extra contents appended (H8, H14).
func rawOID(prefix string, extra []byte) []byte {
	return Enc(TagOID, append(append([]byte(nil), EncOID(prefix)[2:]...), extra...))
}

// scopedRaw encodes s with reqID (nil: s's) and extra appended to the
// varbind list (nil: none).
func scopedRaw(s Scoped, reqID, extra []byte) []byte {
	p := s.PDU
	if reqID == nil {
		reqID = EncInt(TagInteger, p.ReqID)
	}
	var vbs []byte
	for _, b := range p.Binds {
		vbs = append(vbs, Enc(TagSequence, EncOID(b.OID), Enc(b.Tag, b.Val))...)
	}
	vbs = append(vbs, extra...)
	pdu := Enc(p.Tag, reqID, EncInt(TagInteger, p.F1), EncInt(TagInteger, p.F2), Enc(TagSequence, vbs))
	return Enc(TagSequence, EncOctets(s.CtxEngine), EncOctets(s.CtxName), pdu)
}

// withBind appends one raw varbind.
func withBind(s Scoped, vb []byte) []byte { return scopedRaw(s, nil, vb) }

// withValue appends a varbind with a raw value.
func withValue(s Scoped, v []byte) []byte {
	return withBind(s, Enc(TagSequence, EncOID(EntCol(2, 1)), v))
}

// withName appends a varbind with a raw name and a NULL value.
func withName(s Scoped, name []byte) []byte {
	return withBind(s, Enc(TagSequence, name, Null))
}
