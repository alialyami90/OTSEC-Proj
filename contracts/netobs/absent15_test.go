package netobs

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// C13 0.3 §15 (P4-4-C13-ABS, D4-117 item 3.9): the absent and ambiguous
// keys of the 0.2 and 0.3 channels, in code. Every value is illustrative:
// no sensor produced them and no device was contacted.

// optional15 are the key paths a 0.2 or 0.3 channel record may leave out
// (§15.1's optional rows), a list index written []. It is a constant: a
// key added to a record without a decision is not here, so the sweep
// refuses it (§15.9).
var optional15 = []string{
	"function.sub", "citation.frames[].lan", "citation.frames[].redactions",
	"insecure.login", "insecure.login.user", "insecure.login.why", "insecure.redirect_only",
	"service.version", "encrypted.tls", "encrypted.tls.sni",
	"egress_check", "flow.password_lines", "ring_oldest_utc", "l2.inner_vlans",
}

// new15 are the keys §15 adds to a record. A stored record written before
// it carries none of them.
var new15 = []string{"function.objects_unread", "l2.inner_vlans", "encrypted.snmpv3.usm_parsed", "node.dnp3_sa_unknown"}

// sweepDNP3 is a DNP3 first sight on stacked tags, its headers read to the
// end and no SA seen: sa none beside objects_unread false (D6's N3).
func sweepDNP3(schema string) *Observation {
	o := nullFunction(schema)
	o.L2.InnerVLANs = []int{20}
	o.Function.SA, o.Function.ObjectsUnread = SANone, ptr(false)
	return o
}

// sweepFailed is a DNP3 function whose SA failed, seen again.
func sweepFailed(schema string) *Observation {
	o := nullRepeat(schema)
	o.Function.SA, o.Function.SAErrorFrom = SAFailed, "outstation"
	return o
}

func sweepFlow(schema string) *Observation {
	return nullOther(schema, KindFlow, "dnp3", func(o *Observation) { o.Flow = &Flow{Phase: "start", Packets: 3, Bytes: 222} })
}

func sweepEnd(l4 string) func(string) *Observation {
	return func(schema string) *Observation {
		if schema == Identifier02 {
			return clear03(fxEnd03(l4), Identifier02)
		}
		return fxEnd03(l4)
	}
}

// sweepRecords are the full records of the sweep, by name: one of each
// kind and form §15 names.
func sweepRecords() map[string]func(string) *Observation {
	return map[string]func(string) *Observation{
		"dnp3": sweepDNP3, "dnp3-failed": sweepFailed, "modbus-8": nullModbus, "flow-start": sweepFlow,
		"end-tcp": sweepEnd("tcp"), "end-udp": sweepEnd("udp"), "service": nullService,
		"telnet-placed": nullTelnet, "telnet-not-placed": nullTelnetNotPlaced, "http": nullHTTP,
		"snmpv3": nullSNMPv3, "tls": nullTLS, "identity": nullIdentity, "undecoded": nullUndecoded,
	}
}

// sweepStored is o as the node stores it: not a first sight, with node set
// as the intake would set it for these records.
func sweepStored(o *Observation) *Observation {
	o = asStored(o)
	o.FirstSight, o.Frames = false, nil
	if o.IP == nil {
		o.Node.SrcAsset, o.Node.DstAsset, o.Node.ResolvedBy = AssetUnresolved, AssetUnresolved, "none"
	}
	if o.Function != nil {
		o.Node.FunctionClass, o.Node.FunctionTable = ClassControl, FunctionTable
		if o.Function.SA == SANone {
			o.Node.DNP3NoSA = ptr(true)
		}
	}
	return o
}

// keyPathsOf lists every key of doc by its path as setPath takes it,
// list elements walked but not listed.
func keyPathsOf(doc map[string]any) [][]any {
	var all, out [][]any
	nullPaths(doc, nil, &all)
	for _, p := range all {
		if _, ok := p[len(p)-1].(string); ok {
			out = append(out, p)
		}
	}
	return out
}

var listIndex = regexp.MustCompile(`\[\d+\]`)

func docOf(t *testing.T, v any) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustJSON(t, v), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestKeySweep15 (§15.9, D6): from a full record of each kind and of the
// heartbeat, each key is deleted in turn. On the 0.2 and 0.3 channels the
// deletion is refused as missing unless the key is in optional15, and a
// deletion of an optional key is never refused as missing. schema and type
// are read before the record has a type, and are left out. Mutant: drop
// one required check (c.required("l2.vlan") in L2.check, or requireKeys'
// call in validateChannel); the sweep fails at that key.
func TestKeySweep15(t *testing.T) {
	recs := map[string]func(string) any{"heartbeat": hbRec}
	for name, f := range sweepRecords() {
		recs[name] = obs(f)
	}
	swept := map[string]map[string]bool{"heartbeat": {}, "observation": {}}
	for _, schema := range channelIdentifiers {
		for name, rec := range recs {
			if _, err := DecodeFromSensorIn(mustJSON(t, rec(schema)), schema); err != nil {
				t.Errorf("control, %s %s as built: %v", schema, name, err)
				continue
			}
			for _, p := range keyPathsOf(docOf(t, rec(schema))) {
				f := field(p)
				kind := "observation"
				if name == "heartbeat" {
					kind = name
				}
				swept[kind][listIndex.ReplaceAllString(f, "[]")] = true
				if f == "schema" || f == "type" {
					continue
				}
				b := encodeWith(t, rec(schema), func(m map[string]any) { deletePath(m, p) })
				_, err := DecodeFromSensorIn(b, schema)
				opt := slices.Contains(optional15, listIndex.ReplaceAllString(f, "[]"))
				switch {
				case !opt && !hasCode(err, CodeMissing):
					t.Errorf("%s %s, %s deleted: %v, want missing", schema, name, f, err)
				case opt && hasCode(err, CodeMissing):
					t.Errorf("%s %s, optional %s deleted: %v, want no missing", schema, name, f, err)
				}
			}
		}
	}
	// The records carry every key path of the two types, so a key added
	// later is swept (D6's N2 on #760). node is never on the channel, and
	// sweptExempt names each other path left out, with its reason.
	for kind, typ := range map[string]reflect.Type{"heartbeat": reflect.TypeFor[Heartbeat](), "observation": reflect.TypeFor[Observation]()} {
		for _, p := range jsonPaths(typ, "") {
			if p != "node" && !strings.HasPrefix(p, "node.") && !slices.Contains(sweptExempt, p) && !swept[kind][p] {
				t.Errorf("%s: no sweep record carries %s", kind, p)
			}
		}
	}
}

// sweptExempt are the channel key paths no sweep record carries:
// flow.incomplete is optional by design (CH-53) and in no record of the
// sweep.
var sweptExempt = []string{"flow.incomplete"}

// jsonPaths lists every JSON key path of t as field gives it, a list of
// structs walked with [].
func jsonPaths(t reflect.Type, at string) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		if t.Kind() == reflect.Slice {
			if e := t.Elem(); e.Kind() != reflect.Struct && !(e.Kind() == reflect.Pointer && e.Elem().Kind() == reflect.Struct) {
				return nil
			}
			at += "[]"
		}
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		p := name
		if at != "" {
			p = at + "." + name
		}
		out = append(out, p)
		out = append(out, jsonPaths(f.Type, p)...)
	}
	return out
}

// The deletions of the sweep's stored records that DecodeStored accepted
// at the commit before this change (main at d48b2f0a), read from those
// records with §15's new keys taken out, at 0.2 and 0.3 (desk, the owner's
// PC; the 0.2 set is the 0.3 set less the 0.3 counts, which a 0.2 record
// does not carry). storedAcceptedAny holds for every record that carries
// the key, storedAcceptedBy for the record named. Every other deletion of
// a key those records carried was refused there.
var (
	storedAcceptedAny = []string{
		"made_utc", "first_sight", "l2.vlan",
		"citation.frames[0].lan", "citation.frames[1].lan", "citation.frames[1].redactions", "citation.frames[1].redactions[0].offset",
		"coverage.config_digest", "coverage.settings.prp_window_ms", "coverage.prp", "coverage.prp.lans_seen",
		"coverage.prp.duplicates_discarded", "coverage.vlans_seen", "coverage.vlans_overflow", "coverage.untagged_seen",
		"coverage.degraded", "coverage.decodes",
	}
	storedAcceptedBy = map[string][]string{
		"dnp3":        {"function.objects"},
		"dnp3-failed": {"function.objects"},
		"modbus-8":    {"function.objects", "function.sub"},
		"end-tcp": {"flow.orig_payload", "flow.orig_pkts", "flow.resp_payload", "flow.resp_pkts", "flow.password_lines",
			"flow.rexmit_inconsistent", "flow.to_device_overlap_octets"},
		"end-udp":           {"flow.orig_payload", "flow.orig_pkts", "flow.resp_payload", "flow.resp_pkts"},
		"http":              {"insecure.redirect_only"},
		"identity":          {"identity.value", "identity.value.truncated"},
		"service":           {"service.version", "service.version.truncated"},
		"snmpv3":            {"encrypted.snmpv3.boots", "encrypted.snmpv3.time", "encrypted.snmpv3.user", "encrypted.snmpv3.user.truncated"},
		"telnet-not-placed": {"insecure.login", "insecure.login.attempts", "insecure.login.why"},
		"telnet-placed":     {"insecure.login", "insecure.login.attempts", "insecure.login.user", "insecure.login.user.truncated"},
		"tls":               {"encrypted.tls", "encrypted.tls.sni", "encrypted.tls.sni.truncated"},
	}
)

// TestKeySweep15Stored (§15.9; D3's B2, D1's ruling 1 on #735):
// DecodeStored refuses nothing it accepted before §15. Each deletion that
// it accepted at the commit before still decodes; a key required on both
// paths then, insecure.login.slot, stays refused as form; and deleting a
// key §15 adds decodes, since the stored path reads it absent. Mutant: the
// c.need >= 2 gate removed from a channel-only check fails here.
func TestKeySweep15Stored(t *testing.T) {
	for _, schema := range channelIdentifiers {
		for name, f := range sweepRecords() {
			s := sweepStored(f(schema))
			if _, err := DecodeStored(mustJSON(t, s)); err != nil {
				t.Errorf("control, stored %s %s as built: %v", schema, name, err)
				continue
			}
			for _, p := range keyPathsOf(docOf(t, s)) {
				k := field(p)
				b := encodeWith(t, s, func(m map[string]any) { deletePath(m, p) })
				_, err := DecodeStored(b)
				switch {
				case slices.Contains(new15, k) && err != nil:
					t.Errorf("stored %s %s, new key %s deleted: %v, want accepted", schema, name, k, err)
				case (slices.Contains(storedAcceptedAny, k) || slices.Contains(storedAcceptedBy[name], k)) && err != nil:
					t.Errorf("stored %s %s, %s deleted: %v, accepted before §15", schema, name, k, err)
				case k == "insecure.login.slot" && !hasCode(err, CodeForm):
					t.Errorf("stored %s %s, slot deleted: %v, want form", schema, name, err)
				}
			}
		}
	}
}

// storedToday15 are records that DecodeStored accepted before §15 and that
// §15's channel-only checks refuse on the channel (§15.9; D3's B2, D3's N2
// and D6's N1 on #741).
func storedToday15(schema string) map[string]*Observation {
	login := func(l *Login) *Observation {
		o := nullTelnet(schema)
		o.Insecure.Login = l
		return o
	}
	snmp := func(set func(s *SNMPv3)) *Observation {
		o := nullSNMPv3(schema)
		set(o.Encrypted.SNMPv3)
		return o
	}
	ipOn := func(ethertype string) *Observation {
		o := sweepFlow(schema)
		o.L2.EtherType = ethertype
		return o
	}
	undecoded := func(basis string, withIP bool) *Observation {
		o := nullUndecoded(schema)
		o.Undecoded.Basis = basis
		if !withIP {
			o.IP, o.Direction, o.L2.EtherType = nil, DirectionNone, "0x88b8"
		}
		return o
	}
	return map[string]*Observation{
		"user with not-placed":       login(&Login{User: nullText("operator"), Attempts: 1, Slot: "not-placed", Why: "no-prompt"}),
		"boots 2147483648":           snmp(func(s *SNMPv3) { s.Boots = ptr(int64(MaxUSMInteger) + 1) }),
		"time 2147483648":            snmp(func(s *SNMPv3) { s.Time = ptr(int64(MaxUSMInteger) + 1) }),
		"no usm_parsed, boots, time": snmp(func(s *SNMPv3) { s.UsmParsed, s.Boots, s.Time = nil, nil, nil }),
		"why with placed":            login(&Login{User: nullText("operator"), Attempts: 1, Slot: "placed", Why: "no-prompt"}),
		"not-placed without why":     login(&Login{Attempts: 1, Slot: "not-placed"}),
		"ip on a non-IP ethertype":   ipOn("0x88b8"),
		"undecoded ethertype, ip":    undecoded("ethertype", true),
		"undecoded port, no ip":      undecoded("port", false),
	}
}

// TestStoredAcceptsToday15 (§15.9, D3's B2): each record of storedToday15
// decodes through DecodeStored and is refused through DecodeFromSensorIn.
// The SNMPv3 record without usm_parsed is refused on the channel for that
// key, which is new; the others for the check named. Mutant: the c.need
// >= 2 gate removed from any one of these checks fails the stored leg for
// its record.
func TestStoredAcceptsToday15(t *testing.T) {
	for _, schema := range channelIdentifiers {
		for name, o := range storedToday15(schema) {
			if _, err := DecodeFromSensorIn(mustJSON(t, o), schema); err == nil {
				t.Errorf("%s, %s on the channel: accepted", schema, name)
			}
			s := sweepStored(o)
			if s.Encrypted != nil && name == "no usm_parsed, boots, time" {
				// A record stored today, before usm_parsed existed.
				s.Encrypted.SNMPv3.UsmParsed = nil
			}
			if _, err := DecodeStored(mustJSON(t, s)); err != nil {
				t.Errorf("%s, %s stored: %v", schema, name, err)
			}
		}
	}
}

// §15.4, §15.9 (D6's point 1): l2.vlan and l2.inner_vlans.
func TestVLAN15(t *testing.T) {
	for _, schema := range channelIdentifiers {
		set := func(f func(l *L2)) *Observation {
			o := sweepFlow(schema)
			f(&o.L2)
			return o
		}
		for _, c := range []struct {
			name string
			o    *Observation
			code Code
		}{
			{"vlan 4095", set(func(l *L2) { l.VLAN = ptr(4095) }), CodeRange},
			{"four inner VIDs", set(func(l *L2) { l.InnerVLANs = []int{1, 2, 3, 4} }), CodeRange},
			{"inner VID 4095", set(func(l *L2) { l.InnerVLANs = []int{4095} }), CodeRange},
			{"inner VID -1", set(func(l *L2) { l.InnerVLANs = []int{-1} }), CodeRange},
		} {
			if _, err := DecodeFromSensorIn(mustJSON(t, c.o), schema); !hasCode(err, c.code) {
				t.Errorf("%s, %s: %v, want %s", schema, c.name, err, c.code)
			}
		}
		// inner_vlans [] is refused: encoded by hand, as omitempty leaves
		// an empty list out.
		b := encodeWith(t, sweepFlow(schema), func(m map[string]any) { setPath(m, []any{}, "l2", "inner_vlans") })
		if _, err := DecodeFromSensorIn(b, schema); !refusedOnly(err, CodeConflict, "l2.inner_vlans") {
			t.Errorf("%s, inner_vlans []: %v, want conflict", schema, err)
		}
		// A tagged IPv4 frame without ip (0x8100 then 0x0800) is refused.
		b = encodeWith(t, sweepFlow(schema), func(m map[string]any) { delete(m, "ip"); delete(m, "flow") })
		if _, err := DecodeFromSensorIn(b, schema); !hasCode(err, CodeMissing) {
			t.Errorf("%s, a tagged IPv4 frame without ip: %v, want missing", schema, err)
		}
		// Controls: the bounds' edges decode.
		for _, c := range []struct {
			name string
			o    *Observation
		}{
			{"vlan 4094, three inner 4094", set(func(l *L2) { l.VLAN, l.InnerVLANs = ptr(4094), []int{4094, 4094, 4094} })},
			{"inner VID 0", set(func(l *L2) { l.InnerVLANs = []int{0} })},
			{"outer 0 with an inner VID", set(func(l *L2) { l.VLAN, l.InnerVLANs = ptr(0), []int{7} })},
		} {
			if _, err := DecodeFromSensorIn(mustJSON(t, c.o), schema); err != nil {
				t.Errorf("control, %s, %s: %v", schema, c.name, err)
			}
		}
		// vlan 0 is the null VID: decoded to nil, so the stored record and
		// every reader see an untagged frame.
		m, err := DecodeFromSensorIn(mustJSON(t, set(func(l *L2) { l.VLAN = ptr(0) })), schema)
		if err != nil || m.Observation.L2.VLAN != nil {
			t.Errorf("%s, vlan 0: %v, VLAN %v, want nil", schema, err, m.Observation.L2.VLAN)
		}
		// Control: vlan 1 stays 1.
		m, err = DecodeFromSensorIn(mustJSON(t, set(func(l *L2) { l.VLAN = ptr(1) })), schema)
		if err != nil || m.Observation.L2.VLAN == nil || *m.Observation.L2.VLAN != 1 {
			t.Errorf("control, %s, vlan 1: %v, %v", schema, err, m.Observation.L2.VLAN)
		}
	}
	// A stored record never carries 0, and inner_vlans [] is refused there
	// too: it needs the new key (§15.8).
	for name, v := range map[string]any{"vlan": 0, "inner_vlans": []any{}} {
		b := encodeWith(t, sweepStored(sweepFlow(Identifier03)), func(m map[string]any) { setPath(m, v, "l2", name) })
		if _, err := DecodeStored(b); err == nil {
			t.Errorf("stored l2.%s %v: accepted", name, v)
		}
	}
	// Four inner VIDs are refused on the stored path too (D6's N1 on
	// #760). Control: three decode.
	for n, ok := range map[int]bool{3: true, 4: false} {
		s := sweepStored(sweepFlow(Identifier03))
		s.L2.InnerVLANs = []int{1, 2, 3, 4}[:n]
		if _, err := DecodeStored(mustJSON(t, s)); (ok && err != nil) || (!ok && !refusedOnly(err, CodeRange, "l2.inner_vlans")) {
			t.Errorf("stored, %d inner VIDs: %v, want accepted %v", n, err, ok)
		}
	}
}

// §15.4 (D1's 6993015611, D2's N1): a frame with five or more tags, and a
// frame whose type after its tags is 0x9100, is refused as conflict when
// Zeek gives it an ip. Control: the same record with ethertype 0x0800.
func TestRefusedTagForms15(t *testing.T) {
	for _, schema := range channelIdentifiers {
		for _, c := range []struct {
			name, ethertype string
			inner           []int
		}{
			{"five tags, 0x8100", "0x8100", []int{2, 3, 4}},
			{"five tags, 0x88a8", "0x88a8", []int{2, 3, 4}},
			{"0x9100", "0x9100", nil},
		} {
			o := sweepFlow(schema)
			o.L2.EtherType, o.L2.InnerVLANs = c.ethertype, c.inner
			if _, err := DecodeFromSensorIn(mustJSON(t, o), schema); !refusedOnly(err, CodeConflict, "ip") {
				t.Errorf("%s, %s: %v, want conflict at ip", schema, c.name, err)
			}
			o.L2.EtherType = "0x0800"
			if _, err := DecodeFromSensorIn(mustJSON(t, o), schema); err != nil {
				t.Errorf("control, %s, %s as 0x0800: %v", schema, c.name, err)
			}
		}
	}
}

// §15.2, §15.3 (D6's points 3 and 4, D6's N3): sa, objects_unread and the
// node's dnp3_sa_unknown in the contract. The class each gets, and the
// node's setting of the flags, are tested where they are made
// (netdetect.ClassifyFunction, sensorlink's nodeObject).
func TestSA15(t *testing.T) {
	for _, schema := range channelIdentifiers {
		b := encodeWith(t, sweepDNP3(schema), func(m map[string]any) { delete(m["function"].(map[string]any), "sa") })
		if _, err := DecodeFromSensorIn(b, schema); !refusedOnly(err, CodeMissing, "function.sa") {
			t.Errorf("%s, DNP3 without sa: %v, want only missing", schema, err)
		}
		u := sweepDNP3(schema)
		u.Function.SA = SAUnknown
		if _, err := DecodeFromSensorIn(mustJSON(t, u), schema); err != nil {
			t.Errorf("%s, sa unknown: %v", schema, err)
		}
		// sa none never beside objects_unread true, on the channel.
		n := sweepDNP3(schema)
		n.Function.ObjectsUnread = ptr(true)
		if _, err := DecodeFromSensorIn(mustJSON(t, n), schema); !refusedOnly(err, CodeConflict, "function.objects_unread") {
			t.Errorf("%s, sa none with objects_unread true: %v, want conflict", schema, err)
		}
		// Control: unknown beside true decodes.
		n.Function.SA = SAUnknown
		if _, err := DecodeFromSensorIn(mustJSON(t, n), schema); err != nil {
			t.Errorf("control, %s, sa unknown with objects_unread true: %v", schema, err)
		}
		// objects_unread is DNP3 only.
		mb := nullModbus(schema)
		mb.Function.ObjectsUnread = ptr(false)
		if _, err := DecodeFromSensorIn(mustJSON(t, mb), schema); !refusedOnly(err, CodeConflict, "function.objects_unread") {
			t.Errorf("%s, Modbus with objects_unread: %v, want conflict", schema, err)
		}
	}
	stored := func(sa string, unread *bool, class string, noSA, unknown bool) *Observation {
		s := sweepStored(sweepDNP3(Identifier03))
		s.Function.SA, s.Function.ObjectsUnread = sa, unread
		s.Node.FunctionClass, s.Node.DNP3NoSA, s.Node.DNP3SAUnknown = class, nil, nil
		if noSA {
			s.Node.DNP3NoSA = ptr(true)
		}
		if unknown {
			s.Node.DNP3SAUnknown = ptr(true)
		}
		return s
	}
	for _, c := range []struct {
		name string
		s    *Observation
		ok   bool
	}{
		{"unknown, write, dnp3_sa_unknown", stored(SAUnknown, ptr(false), ClassWrite, false, true), true},
		{"unknown, write, no flag", stored(SAUnknown, ptr(false), ClassWrite, false, false), false},
		// Control: unknown read as none sets dnp3_no_sa, and is refused.
		{"unknown, write, dnp3_no_sa", stored(SAUnknown, ptr(false), ClassWrite, true, false), false},
		{"unknown, read, no flag", stored(SAUnknown, ptr(false), ClassRead, false, false), true},
		{"unknown, read, dnp3_sa_unknown", stored(SAUnknown, ptr(false), ClassRead, false, true), false},
		{"none, control, dnp3_sa_unknown", stored(SANone, ptr(false), ClassControl, true, true), false},
		{"sa absent, no flag", stored("", nil, ClassControl, false, false), true},
		{"sa absent, dnp3_sa_unknown", stored("", nil, ClassControl, false, true), false},
		{"none without objects_unread", stored(SANone, nil, ClassControl, true, false), true},
		{"none, objects_unread true", stored(SANone, ptr(true), ClassControl, true, false), false},
	} {
		if _, err := DecodeStored(mustJSON(t, c.s)); (err == nil) != c.ok {
			t.Errorf("stored %s: %v, want accepted %v", c.name, err, c.ok)
		}
	}
	// The flag on a record of another kind is refused.
	s := sweepStored(sweepFlow(Identifier03))
	s.Node.DNP3SAUnknown = ptr(true)
	if _, err := DecodeStored(mustJSON(t, s)); !hasCode(err, CodeConflict) {
		t.Errorf("stored flow with dnp3_sa_unknown: %v, want conflict", err)
	}
}

// §15.5 (D2's B3 and B4, D6's point 11 and N1): SNMPv3.
func TestSNMPv315(t *testing.T) {
	snmp := func(schema string, set func(s *SNMPv3)) *Observation {
		o := nullSNMPv3(schema)
		set(o.Encrypted.SNMPv3)
		return o
	}
	for _, schema := range channelIdentifiers {
		for _, c := range []struct {
			name string
			o    *Observation
			code Code // "" decodes
		}{
			{"discovery", snmp(schema, func(s *SNMPv3) {
				s.EngineID, s.User, s.Boots, s.Time = ptr(""), nullText(""), ptr(int64(0)), ptr(int64(0))
			}), ""},
			{"engine ID of 1 octet", snmp(schema, func(s *SNMPv3) { s.EngineID = ptr("80") }), ""},
			{"engine ID of 32 octets", snmp(schema, func(s *SNMPv3) { s.EngineID = ptr(strings.Repeat("ab", 32)) }), ""},
			{"engine ID of 33 octets", snmp(schema, func(s *SNMPv3) { s.EngineID = ptr(strings.Repeat("ab", 33)) }), CodeForm},
			{"boots 2147483647", snmp(schema, func(s *SNMPv3) { s.Boots = ptr(int64(MaxUSMInteger)) }), ""},
			{"boots 2147483648", snmp(schema, func(s *SNMPv3) { s.Boots = ptr(int64(MaxUSMInteger) + 1) }), CodeRange},
			{"time 2147483648", snmp(schema, func(s *SNMPv3) { s.Time = ptr(int64(MaxUSMInteger) + 1) }), CodeRange},
			{"usm_parsed false, none of the four", snmp(schema, func(s *SNMPv3) {
				s.UsmParsed, s.EngineID, s.User, s.Boots, s.Time = ptr(false), nil, nil, nil, nil
			}), ""},
			{"usm_parsed false, engine_id", snmp(schema, func(s *SNMPv3) { s.UsmParsed, s.User, s.Boots, s.Time = ptr(false), nil, nil, nil }), CodeConflict},
			{"usm_parsed false, user", snmp(schema, func(s *SNMPv3) { s.UsmParsed, s.EngineID, s.Boots, s.Time = ptr(false), nil, nil, nil }), CodeConflict},
			{"usm_parsed false, boots", snmp(schema, func(s *SNMPv3) { s.UsmParsed, s.EngineID, s.User, s.Time = ptr(false), nil, nil, nil }), CodeConflict},
			{"usm_parsed false, time", snmp(schema, func(s *SNMPv3) { s.UsmParsed, s.EngineID, s.User, s.Boots = ptr(false), nil, nil, nil }), CodeConflict},
			{"usm_parsed true, time absent", snmp(schema, func(s *SNMPv3) { s.Time = nil }), CodeMissing},
			{"usm_parsed absent", snmp(schema, func(s *SNMPv3) { s.UsmParsed = nil }), CodeMissing},
		} {
			_, err := DecodeFromSensorIn(mustJSON(t, c.o), schema)
			if (c.code == "" && err != nil) || (c.code != "" && !hasCode(err, c.code)) {
				t.Errorf("%s, %s: %v, want %q", schema, c.name, err, c.code)
			}
		}
	}
	// usm_parsed false with any of the four is refused on the stored path
	// too; with none of them it decodes.
	for i, set := range []func(s *SNMPv3){
		func(s *SNMPv3) { s.User, s.Boots, s.Time = nil, nil, nil },
		func(s *SNMPv3) { s.EngineID, s.Boots, s.Time = nil, nil, nil },
		func(s *SNMPv3) { s.EngineID, s.User, s.Time = nil, nil, nil },
		func(s *SNMPv3) { s.EngineID, s.User, s.Boots = nil, nil, nil },
	} {
		s := sweepStored(snmp(Identifier03, func(s *SNMPv3) { s.UsmParsed = ptr(false); set(s) }))
		if _, err := DecodeStored(mustJSON(t, s)); !hasCode(err, CodeConflict) {
			t.Errorf("stored, usm_parsed false with field %d: %v, want conflict", i, err)
		}
	}
	s := sweepStored(snmp(Identifier03, func(s *SNMPv3) { s.UsmParsed, s.EngineID, s.User, s.Boots, s.Time = ptr(false), nil, nil, nil, nil }))
	if _, err := DecodeStored(mustJSON(t, s)); err != nil {
		t.Errorf("control, stored, usm_parsed false alone: %v", err)
	}
}

// §15.1, §15.6: the login's user only with slot placed, and why exactly
// with not-placed, on the channel.
func TestLogin15(t *testing.T) {
	for _, schema := range channelIdentifiers {
		for _, c := range []struct {
			name  string
			l     *Login
			field string // "" decodes
		}{
			{"placed with user", &Login{User: nullText("operator"), Attempts: 1, Slot: "placed"}, ""},
			{"placed without user", &Login{Attempts: 1, Slot: "placed"}, ""},
			{"none, no user, no why", &Login{Attempts: 0, Slot: "none"}, ""},
			{"not-placed with why", &Login{Attempts: 1, Slot: "not-placed", Why: "no-prompt"}, ""},
			{"none with user", &Login{User: nullText("operator"), Attempts: 1, Slot: "none"}, "insecure.login.user"},
			{"not-placed with user and why", &Login{User: nullText("operator"), Attempts: 1, Slot: "not-placed", Why: "no-prompt"}, "insecure.login.user"},
			{"not-placed without why", &Login{Attempts: 1, Slot: "not-placed"}, "insecure.login.why"},
			{"none with why", &Login{Attempts: 1, Slot: "none", Why: "no-prompt"}, "insecure.login.why"},
		} {
			o := nullTelnet(schema)
			o.Insecure.Login = c.l
			_, err := DecodeFromSensorIn(mustJSON(t, o), schema)
			if (c.field == "" && err != nil) || (c.field != "" && !refusedOnly(err, CodeConflict, c.field)) {
				t.Errorf("%s, %s: %v, want conflict at %q", schema, c.name, err, c.field)
			}
		}
	}
}

// errAt reports whether err holds a failure of code at field.
func errAt(err error, code Code, field string) bool {
	all := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		all = j.Unwrap()
	}
	for _, e := range all {
		var x *Error
		if errors.As(e, &x) && x.Code == code && x.Field == field {
			return true
		}
	}
	return false
}

// snmp01 is an SNMPv3 record on the 0.1 channel, without usm_parsed.
func snmp01() *Observation { return as01(nullSNMPv3(Identifier02)) }

// D3's F1 on #760: an absent usm_parsed reads as true, and true requires
// engine_id on the 0.1 channel and on the stored path, as before §15. A
// record with neither key is refused there; with engine_id it decodes.
// usm_parsed true without engine_id is refused when stored too. Mutant:
// the engine_id requirement made channel-only again (c.need >= 2 alone).
func TestUSMAbsentEngineID15(t *testing.T) {
	const f = "encrypted.snmpv3.engine_id"
	for _, withID := range []bool{false, true} {
		o := snmp01()
		if !withID {
			o.Encrypted.SNMPv3.EngineID = nil
		}
		if _, err := DecodeChannel(mustJSON(t, o)); withID != (err == nil) || (!withID && !refusedOnly(err, CodeMissing, f)) {
			t.Errorf("0.1 channel, engine_id %v: %v", withID, err)
		}
		for _, s := range []*Observation{sweepStored(snmp01()), sweepStored(nullSNMPv3(Identifier02)), sweepStored(nullSNMPv3(Identifier03))} {
			s.Encrypted.SNMPv3.UsmParsed = nil
			if !withID {
				s.Encrypted.SNMPv3.EngineID = nil
			}
			if _, err := DecodeStored(mustJSON(t, s)); withID != (err == nil) || (!withID && !refusedOnly(err, CodeMissing, f)) {
				t.Errorf("stored %s, no usm_parsed, engine_id %v: %v", s.Schema, withID, err)
			}
		}
	}
	for _, schema := range channelIdentifiers {
		s := sweepStored(nullSNMPv3(schema))
		s.Encrypted.SNMPv3.EngineID = nil
		if _, err := DecodeStored(mustJSON(t, s)); !refusedOnly(err, CodeMissing, f) {
			t.Errorf("stored %s, usm_parsed true, no engine_id: %v, want missing", schema, err)
		}
	}
}

// D3's F2 on #760: sa unknown and node.dnp3_sa_unknown are new in 0.2,
// and a 0.1 record refuses them as the 0.1 reader did (D4-103 ruling 2).
// Controls: the 0.1 records with sa challenged, and a 0.2 stored record
// with unknown and the flag, decode. Mutants: either gate removed.
func TestSAUnknown01(t *testing.T) {
	o := fxFunction()
	if _, err := DecodeChannel(mustJSON(t, o)); err != nil {
		t.Errorf("control, 0.1 channel, sa challenged: %v", err)
	}
	o.Function.SA = SAUnknown
	if _, err := DecodeChannel(mustJSON(t, o)); !refusedOnly(err, CodeForm, "function.sa") {
		t.Errorf("0.1 channel, sa unknown: %v, want form", err)
	}
	s := fxStored()
	if _, err := DecodeStored(mustJSON(t, s)); err != nil {
		t.Errorf("control, 0.1 stored, sa challenged: %v", err)
	}
	s.Function.SA, s.Node.DNP3SAUnknown = SAUnknown, ptr(true)
	_, err := DecodeStored(mustJSON(t, s))
	if !errAt(err, CodeForm, "function.sa") {
		t.Errorf("0.1 stored, sa unknown: %v, want form at function.sa", err)
	}
	if !errAt(err, CodeDecode, "node.dnp3_sa_unknown") {
		t.Errorf("0.1 stored, dnp3_sa_unknown: %v, want decode at the flag", err)
	}
	c := sweepStored(sweepDNP3(Identifier02))
	c.Function.SA, c.Node.DNP3NoSA, c.Node.DNP3SAUnknown = SAUnknown, nil, ptr(true)
	if _, err := DecodeStored(mustJSON(t, c)); err != nil {
		t.Errorf("control, 0.2 stored, sa unknown with the flag: %v", err)
	}
}

// D6's N1 on #760: inner_vlans, objects_unread and usm_parsed are new in
// 0.2, refused as decode in a 0.1 record on the channel and when stored.
// Controls: the same records without the key decode. Mutant: any one of
// the three new02 calls made newAt(1, ...).
func TestNew15At01(t *testing.T) {
	channel := func(b []byte) (*Observation, error) { _, err := DecodeChannel(b); return nil, err }
	for _, c := range []struct {
		field string
		rec   func() *Observation
		set   func(o *Observation)
	}{
		{"l2.inner_vlans", fxFlow, func(o *Observation) { o.L2.InnerVLANs = []int{20} }},
		{"function.objects_unread", fxFunction, func(o *Observation) { o.Function.ObjectsUnread = ptr(false) }},
		{"encrypted.snmpv3.usm_parsed", snmp01, func(o *Observation) { o.Encrypted.SNMPv3.UsmParsed = ptr(true) }},
	} {
		for path, decode := range map[string]func([]byte) (*Observation, error){"channel": channel, "stored": DecodeStored} {
			o := c.rec()
			if path == "stored" {
				o = sweepStored(o)
			}
			if _, err := decode(mustJSON(t, o)); err != nil {
				t.Errorf("control, 0.1 %s, without %s: %v", path, c.field, err)
			}
			c.set(o)
			if _, err := decode(mustJSON(t, o)); !refusedOnly(err, CodeDecode, c.field) {
				t.Errorf("0.1 %s with %s: %v, want decode", path, c.field, err)
			}
		}
	}
}
