package snmpv3

import (
	"encoding/hex"
	"regexp"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
)

// The identity parse of the SEL-2730M and SEL-2731M family
// (docs/phase4/C2-snmp-family.md; C1 0.3 §1.5). Values are kept as printed
// and nothing is mapped.

const (
	oidSysDescr     = "1.3.6.1.2.1.1.1.0"
	oidSysName      = "1.3.6.1.2.1.1.5.0"
	entPhysicalTree = "1.3.6.1.2.1.47.1.1.1"
)

// fid27x1 is the family's FID grammar. No manual names the Entity MIB
// column that holds it, so it is found by its form: the whole value of
// sysDescr.0 or of an entPhysicalTable object.
var fid27x1 = regexp.MustCompile(`^(SEL-27[34]1M)-([RX][0-9]{3}-V[0-9]+)-Z[0-9]{6}-D[0-9]{8}$`)

// Observation is one identity attribute a session read: its value, where
// its bytes are, and the varbind OID or header field that held them.
type Observation struct {
	Name    string
	Value   string
	Segment int
	Offset  int
	Length  int
	OID     string // the varbind, or "" for a header field
	Header  string // asset.HeaderEngineID, or ""
}

// Identity is the family's parse of a completed session. Missing says why
// an attribute the family reads is absent: no FID, or more than one.
func Identity(o Outcome) (obs []Observation, missing []string) {
	at := func(v Value, name string, from, to int) Observation {
		return Observation{Name: name, Value: string(v.Content[from:to]), Segment: v.Segment,
			Offset: v.Offset + from, Length: to - from, OID: v.OID}
	}
	var fid *Value
	distinct := map[string]bool{}
	for i := range o.Values {
		v := &o.Values[i]
		if v.Tag != tagOctetString {
			continue
		}
		if v.OID == oidSysName && printable(v.Content) {
			obs = append(obs, at(*v, c1.AttrHostname, 0, len(v.Content)))
		}
		if (v.OID == oidSysDescr || register.InSubtree(v.OID, entPhysicalTree)) && fid27x1.Match(v.Content) {
			if !distinct[string(v.Content)] && fid == nil {
				fid = v
			}
			distinct[string(v.Content)] = true
		}
	}
	switch {
	case len(distinct) == 1:
		g := fid27x1.FindSubmatchIndex(fid.Content)
		obs = append(obs, at(*fid, c1.AttrFirmwareID, 0, len(fid.Content)),
			at(*fid, c1.AttrModel, g[2], g[3]), at(*fid, c1.AttrFirmwareVersion, g[4], g[5]))
	case len(distinct) == 0:
		missing = append(missing, "no value matches the FID grammar")
	default:
		missing = append(missing, "more than one distinct value matches the FID grammar")
	}
	// The engine ID of the first authenticated response, from its header.
	for i, sg := range o.Segments {
		if sg.Dir == adapter.Received && sg.ScopedOff >= 0 && sg.EngineIDOff >= 0 && authenticatedResponse(sg) {
			e := sg.Bytes[sg.EngineIDOff : sg.EngineIDOff+sg.EngineIDLen]
			obs = append(obs, Observation{Name: c1.AttrSNMPEngineID, Value: hex.EncodeToString(e), Segment: i,
				Offset: sg.EngineIDOff, Length: sg.EngineIDLen, Header: c1.HeaderEngineID})
			break
		}
	}
	return obs, missing
}

// authenticatedResponse reports whether a stored segment is a Response
// that came authPriv: only those are kept with their plaintext.
func authenticatedResponse(sg Segment) bool {
	m, err := decodeMessage(sg.Bytes)
	if err != nil || m.Flags&(flagAuth|flagPriv) != flagAuth|flagPriv {
		return false
	}
	sc, err := decodeScoped(sg.Bytes[sg.ScopedOff:])
	return err == nil && sc.PDU.Tag == tagResponse
}

// printable is C1's value form for a device string: printable ASCII, no
// space at either end, at most MaxValueBytes.
func printable(b []byte) bool {
	if len(b) == 0 || len(b) > c1.MaxValueBytes || b[0] == ' ' || b[len(b)-1] == ' ' {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
