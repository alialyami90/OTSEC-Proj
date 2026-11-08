package netobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// Record types on the channel. The channel carries only these two; any
// other type, an alert's included, is refused (C13 §1, AP-34).
const (
	TypeObservation = "observation"
	TypeHeartbeat   = "heartbeat"
)

// Kind is an observation's kind (C13 §4.1). Closed.
type Kind string

const (
	KindFlow      Kind = "flow"
	KindService   Kind = "service"
	KindFunction  Kind = "function"
	KindInsecure  Kind = "insecure"
	KindEncrypted Kind = "encrypted"
	KindIdentity  Kind = "identity"
	KindUndecoded Kind = "undecoded"
)

// Kinds lists every Kind.
var Kinds = []Kind{KindFlow, KindService, KindFunction, KindInsecure, KindEncrypted, KindIdentity, KindUndecoded}

// Observation is one C13 observation: as the sensor sends it on the
// channel (Frames set on a first sight, Node absent), or as the node
// stores it in a C4 event's netobs (Frames absent, Node set).
type Observation struct {
	Schema       string   `json:"schema"`
	Type         string   `json:"type"`
	SensorID     string   `json:"sensor_id"`
	RunID        string   `json:"run_id"`
	Seq          string   `json:"seq"`
	Kind         Kind     `json:"kind"`
	FirstSight   bool     `json:"first_sight"`
	FirstUTC     string   `json:"first_utc"`
	LastUTC      string   `json:"last_utc"`
	ResolutionNS int64    `json:"resolution_ns"`
	L2           L2       `json:"l2"`
	IP           *IP      `json:"ip,omitempty"`
	Direction    string   `json:"direction"`
	Protocol     string   `json:"protocol"`
	Citation     Citation `json:"citation"`
	Coverage     Coverage `json:"coverage"`

	Flow      *Flow      `json:"flow,omitempty"`
	Service   *Service   `json:"service,omitempty"`
	Function  *Function  `json:"function,omitempty"`
	Insecure  *Insecure  `json:"insecure,omitempty"`
	Encrypted *Encrypted `json:"encrypted,omitempty"`
	Identity  *Identity  `json:"identity,omitempty"`
	Undecoded *Undecoded `json:"undecoded,omitempty"`

	// Frames are the cited frames' bytes, on a first sight only, on the
	// channel only.
	Frames []Frame `json:"frames,omitempty"`
	// Node is what the node adds before it stores the observation (C13 §5).
	// A channel record with Node set is refused.
	Node *Node `json:"node,omitempty"`
}

// L2 is the frame's link layer. EtherType is the inner type after any
// 802.1Q tag, as "0x" and four lowercase hex digits.
type L2 struct {
	SrcMAC    string `json:"src_mac"`
	DstMAC    string `json:"dst_mac"`
	VLAN      *int   `json:"vlan,omitempty"`
	EtherType string `json:"ethertype"`
}

// IP is absent for a layer-2-only frame. Ports are present exactly for TCP
// and UDP.
type IP struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	L4    string `json:"l4"`
	Sport *int   `json:"sport,omitempty"`
	Dport *int   `json:"dport,omitempty"`
}

// Directions. Closed.
const (
	DirectionClientServer = "client-server"
	DirectionMidstream    = "midstream"
	DirectionNone         = "none"
)

// Flow is a flow's start or end (C13 §4.3). End is set exactly on the end,
// and SynOnly exactly on a TCP end: true only when SynOnly(segments) holds
// for the flow (C13 §14 item 10).
type Flow struct {
	Phase   string `json:"phase"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	End     string `json:"end,omitempty"`
	SynOnly *bool  `json:"syn_only,omitempty"`
}

// Service is a server seen on a port. The server is ip.dst.
type Service struct {
	Basis   string `json:"basis"`
	Version *Text  `json:"version,omitempty"`
}

// Function is a request's application function (C13 §4.3). Sub is Modbus
// 8's sub-function or 43's MEI type (C13 §14). SA and SAErrorFrom are DNP3
// only; SA absent means not known.
type Function struct {
	Code        int      `json:"code"`
	Sub         *int     `json:"sub,omitempty"`
	Objects     []string `json:"objects"`
	Unit        *int     `json:"unit,omitempty"`
	SA          string   `json:"sa,omitempty"`
	SAErrorFrom string   `json:"sa_error_from,omitempty"`
}

// SA outcomes. Closed.
const (
	SAChallenged = "challenged"
	SAAggressive = "aggressive"
	SAFailed     = "failed"
	SANone       = "none"
)

// Insecure is a use of a protocol on V-M6's insecure list.
type Insecure struct {
	Reason       string `json:"reason"`
	Login        *Login `json:"login,omitempty"`
	RedirectOnly *bool  `json:"redirect_only,omitempty"`
}

// Login is what is kept of a login in clear: never the secret.
type Login struct {
	User     *Text  `json:"user,omitempty"`
	Attempts int64  `json:"attempts"`
	Slot     string `json:"slot"`
	Why      string `json:"why,omitempty"`
}

// Encrypted is what a handshake or header shows in clear.
type Encrypted struct {
	Scheme string  `json:"scheme"`
	TLS    *TLS    `json:"tls,omitempty"`
	SNMPv3 *SNMPv3 `json:"snmpv3,omitempty"`
}

// TLS is a TLS handshake's version and SNI.
type TLS struct {
	Version string `json:"version"`
	SNI     *Text  `json:"sni,omitempty"`
}

// SNMPv3 is an SNMPv3 message header's fields in clear.
type SNMPv3 struct {
	EngineID string `json:"engine_id"`
	User     Text   `json:"user"`
	Level    string `json:"level"`
	Boots    *int64 `json:"boots,omitempty"`
	Time     *int64 `json:"time,omitempty"`
}

// Identity is a value read in clear from the server end.
type Identity struct {
	Attribute string `json:"attribute"`
	Value     Text   `json:"value"`
	Via       string `json:"via"`
}

// Undecoded is traffic seen and not decoded.
type Undecoded struct {
	Basis   string `json:"basis"`
	Packets int64  `json:"packets"`
}

// Frame is one cited frame's stored bytes, base64.
type Frame struct {
	N    int64  `json:"n"`
	TS   string `json:"ts"`
	Data string `json:"data"`
}

// Node is what the node adds (C13 §5).
type Node struct {
	SrcAsset        string           `json:"src_asset"`
	DstAsset        string           `json:"dst_asset"`
	ResolvedBy      string           `json:"resolved_by"`
	PlatformSession *PlatformSession `json:"platform_session,omitempty"`
	EvidenceClass   string           `json:"evidence_class"`
	StoredCapture   string           `json:"stored_capture,omitempty"`
	FunctionClass   string           `json:"function_class,omitempty"`
	FunctionTable   string           `json:"function_table,omitempty"`
	DNP3NoSA        *bool            `json:"dnp3_no_sa,omitempty"`
}

// PlatformSession ties an observation to one of the node's own sessions.
type PlatformSession struct {
	InvocationID string `json:"invocation_id"`
	Tie          string `json:"tie"`
}

// AssetUnresolved is a Node end that resolves to no asset.
const AssetUnresolved = "asset-unresolved"

// Function classes (fc-classes, baseline note §4). Closed.
const (
	ClassRead         = "read"
	ClassWrite        = "write"
	ClassControl      = "control"
	ClassSessionSetup = "session-setup"
	ClassTimeSync     = "time-sync"
	ClassOther        = "other"
)

// FunctionClasses lists every function class.
var FunctionClasses = []string{ClassRead, ClassWrite, ClassControl, ClassSessionSetup, ClassTimeSync, ClassOther}

// FunctionTable is the class table this version of C13 names.
const FunctionTable = "fc-classes/1"

// NoSAClasses are the classes whose DNP3 function with sa none sets
// dnp3_no_sa (C13 §5).
var NoSAClasses = []string{ClassWrite, ClassControl, ClassSessionSetup}

var (
	macForm       = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
	etherTypeForm = regexp.MustCompile(`^0x[0-9a-f]{4}$`)
	objectForm    = regexp.MustCompile(`^g(?:0|[1-9][0-9]{0,2})v(?:0|[1-9][0-9]{0,2})$`)
	engineIDForm  = regexp.MustCompile(`^(?:[0-9a-f]{2}){5,32}$`)
)

// Validate checks a channel observation: every rule of C13 that holds on
// one record, including the frame bytes against their hashes and the
// redactions applied. It refuses a record with Node set.
func (o *Observation) Validate() error {
	c := &checker{}
	c.strictSchema(o.Schema)
	o.check(c)
	if o.Node != nil {
		c.fail(CodeConflict, "node", "a sensor's record never carries node")
	}
	o.checkFrames(c)
	return c.err()
}

// ValidateStored checks a stored observation: Frames absent, Node set and
// consistent with the body. A later 0.x minor is read forward.
func (o *Observation) ValidateStored() error {
	c := &checker{}
	c.storedSchema(o.Schema)
	o.check(c)
	if len(o.Frames) > 0 {
		c.fail(CodeConflict, "frames", "stored as the record's capture, never in the body")
	}
	if o.Node == nil {
		c.fail(CodeMissing, "node", "a stored observation carries node")
	} else {
		o.checkNode(c)
	}
	return c.err()
}

func (o *Observation) check(c *checker) {
	if o.Type != TypeObservation {
		c.fail(CodeType, "type", "%q is not %s", o.Type, TypeObservation)
	}
	c.uuid("sensor_id", o.SensorID)
	c.uuid("run_id", o.RunID)
	c.seq("seq", o.Seq)
	first, ok1 := c.utc("first_utc", o.FirstUTC)
	last, ok2 := c.utc("last_utc", o.LastUTC)
	if ok1 && ok2 && last.Before(first) {
		c.fail(CodeOrder, "last_utc", "before first_utc")
	}
	if o.ResolutionNS < 1 || o.ResolutionNS > 1e9 {
		c.fail(CodeRange, "resolution_ns", "%d not in [1, 1e9]", o.ResolutionNS)
	}
	o.L2.check(c)
	l4 := ""
	if o.IP != nil {
		l4 = o.IP.check(c)
	}
	switch {
	case l4 == "tcp" && o.Direction != DirectionClientServer && o.Direction != DirectionMidstream:
		c.fail(CodeConflict, "direction", "%q: a TCP observation is client-server or midstream", o.Direction)
	case l4 != "tcp" && o.Direction != DirectionNone:
		c.fail(CodeConflict, "direction", "%q: only TCP has a direction", o.Direction)
	}
	c.token("protocol", o.Protocol)
	o.Citation.check(c, "citation")
	if run := captureRun(o.Citation.CaptureID); run != "" && run != o.RunID {
		c.fail(CodeConflict, "citation.capture_id", "a ring of run %s, not this record's run", run)
	}
	o.Coverage.check(c, "coverage")
	o.checkKind(c, l4)
}

func (l *L2) check(c *checker) {
	if !macForm.MatchString(l.SrcMAC) {
		c.fail(CodeForm, "l2.src_mac", "%q is not a lowercase MAC", l.SrcMAC)
	}
	if !macForm.MatchString(l.DstMAC) {
		c.fail(CodeForm, "l2.dst_mac", "%q is not a lowercase MAC", l.DstMAC)
	}
	if l.VLAN != nil && (*l.VLAN < 1 || *l.VLAN > 4094) {
		c.fail(CodeRange, "l2.vlan", "%d not in [1, 4094]", *l.VLAN)
	}
	if !etherTypeForm.MatchString(l.EtherType) {
		c.fail(CodeForm, "l2.ethertype", "%q is not 0x and four lowercase hex digits", l.EtherType)
	}
}

// check returns l4 when it is valid.
func (p *IP) check(c *checker) string {
	c.addr("ip.src", p.Src)
	c.addr("ip.dst", p.Dst)
	switch p.L4 {
	case "tcp", "udp":
		for _, port := range []struct {
			f string
			v *int
		}{{"ip.sport", p.Sport}, {"ip.dport", p.Dport}} {
			switch {
			case port.v == nil:
				c.fail(CodeMissing, port.f, "required for %s", p.L4)
			case *port.v < 0 || *port.v > 65535:
				c.fail(CodeRange, port.f, "%d not in [0, 65535]", *port.v)
			}
		}
	case "other":
		if p.Sport != nil || p.Dport != nil {
			c.fail(CodeConflict, "ip.sport", "ports only for tcp and udp")
		}
	default:
		c.fail(CodeForm, "ip.l4", "%q is not tcp, udp or other", p.L4)
		return ""
	}
	return p.L4
}

func (o *Observation) checkKind(c *checker, l4 string) {
	bodies := map[Kind]bool{
		KindFlow: o.Flow != nil, KindService: o.Service != nil, KindFunction: o.Function != nil,
		KindInsecure: o.Insecure != nil, KindEncrypted: o.Encrypted != nil,
		KindIdentity: o.Identity != nil, KindUndecoded: o.Undecoded != nil,
	}
	if !contains(Kinds, o.Kind) {
		c.fail(CodeForm, "kind", "%q is not a kind", o.Kind)
	}
	for _, k := range Kinds {
		switch {
		case k == o.Kind && !bodies[k]:
			c.fail(CodeMissing, string(k), "required on a %s observation", k)
		case k != o.Kind && bodies[k]:
			c.fail(CodeConflict, string(k), "only on a %s observation", k)
		}
	}
	needsIP := func(f string, l4s ...string) {
		if !contains(l4s, l4) {
			c.fail(CodeConflict, f, "needs ip with l4 %v", l4s)
		}
	}
	switch {
	case o.Flow != nil:
		f := o.Flow
		needsIP("flow", "tcp", "udp")
		switch f.Phase {
		case "start":
			if f.End != "" {
				c.fail(CodeConflict, "flow.end", "only on the end phase")
			}
			if f.SynOnly != nil {
				c.fail(CodeConflict, "flow.syn_only", "only on the end phase")
			}
		case "end":
			if !contains([]string{"fin", "rst", "idle", "sensor-stop"}, f.End) {
				c.fail(CodeForm, "flow.end", "%q is not fin, rst, idle or sensor-stop", f.End)
			}
			switch {
			case l4 == "tcp" && f.SynOnly == nil:
				c.fail(CodeMissing, "flow.syn_only", "required on a tcp end")
			case l4 != "tcp" && f.SynOnly != nil:
				c.fail(CodeConflict, "flow.syn_only", "only on a tcp end")
			case f.SynOnly != nil && *f.SynOnly && o.Direction != DirectionClientServer:
				c.fail(CodeConflict, "flow.syn_only", "true needs direction client-server: a syn-only flow starts with the client's SYN")
			}
		default:
			c.fail(CodeForm, "flow.phase", "%q is not start or end", f.Phase)
		}
		if f.Packets < 1 || f.Bytes < f.Packets {
			c.fail(CodeRange, "flow.packets", "packets %d, bytes %d: at least one frame of at least one byte each", f.Packets, f.Bytes)
		}
	case o.Service != nil:
		needsIP("service", "tcp", "udp")
		if o.Service.Basis != "content" && o.Service.Basis != "port" {
			c.fail(CodeForm, "service.basis", "%q is not content or port", o.Service.Basis)
		}
		if o.Service.Version != nil {
			o.Service.Version.check(c, "service.version")
		}
	case o.Function != nil:
		needsIP("function", "tcp", "udp")
		o.Function.check(c, o.Protocol)
	case o.Insecure != nil:
		needsIP("insecure", "tcp", "udp")
		o.Insecure.check(c)
	case o.Encrypted != nil:
		needsIP("encrypted", "tcp", "udp")
		o.Encrypted.check(c)
	case o.Identity != nil:
		needsIP("identity", "tcp", "udp")
		id := o.Identity
		if !contains([]string{"fid", "partno", "devid", "engine-id", "banner", "http-server", "snmp-sysdescr", "ssh-ident"}, id.Attribute) {
			c.fail(CodeForm, "identity.attribute", "%q is not an identity attribute", id.Attribute)
		}
		id.Value.check(c, "identity.value")
		c.token("identity.via", id.Via)
	case o.Undecoded != nil:
		if !contains([]string{"port", "ethertype", "none"}, o.Undecoded.Basis) {
			c.fail(CodeForm, "undecoded.basis", "%q is not port, ethertype or none", o.Undecoded.Basis)
		}
		if o.Undecoded.Packets < 1 {
			c.fail(CodeRange, "undecoded.packets", "%d: at least one", o.Undecoded.Packets)
		}
	}
}

func (f *Function) check(c *checker, protocol string) {
	if f.Code < 0 || f.Code > 255 {
		c.fail(CodeRange, "function.code", "%d not in [0, 255]", f.Code)
	}
	if len(f.Objects) > MaxObjects {
		c.fail(CodeRange, "function.objects", "%d, above %d", len(f.Objects), MaxObjects)
	}
	for i, ob := range f.Objects {
		if !objectForm.MatchString(ob) {
			c.fail(CodeForm, fmt.Sprintf("function.objects[%d]", i), "%q is not g<group>v<variation>", ob)
		}
		if i > 0 && ob <= f.Objects[i-1] {
			c.fail(CodeOrder, "function.objects", "sorted, without repeats")
		}
	}
	switch protocol {
	case "dnp3":
		if contains([]int{0, 129, 130, 131}, f.Code) {
			c.fail(CodeConflict, "function.code", "DNP3 %d is never a function observation", f.Code)
		}
		if f.Unit != nil || f.Sub != nil {
			c.fail(CodeConflict, "function.unit", "unit and sub are Modbus only")
		}
		if f.SA != "" && !contains([]string{SAChallenged, SAAggressive, SAFailed, SANone}, f.SA) {
			c.fail(CodeForm, "function.sa", "%q is not an SA outcome", f.SA)
		}
		switch {
		case f.SA == SAFailed && f.SAErrorFrom != "master" && f.SAErrorFrom != "outstation":
			c.fail(CodeForm, "function.sa_error_from", "%q is not master or outstation", f.SAErrorFrom)
		case f.SA != SAFailed && f.SAErrorFrom != "":
			c.fail(CodeConflict, "function.sa_error_from", "only with sa failed")
		}
	case "modbus":
		if len(f.Objects) > 0 {
			c.fail(CodeConflict, "function.objects", "empty for Modbus")
		}
		if f.Unit == nil || *f.Unit < 0 || *f.Unit > 255 {
			c.fail(CodeRange, "function.unit", "required for Modbus, in [0, 255]")
		}
		// sub is absent when the request is too short to hold it; the node
		// then classes 8 as control and 43 as write (C13 §4.3, D1 on #543).
		switch {
		case f.Sub == nil:
		case f.Code == 8 && (*f.Sub < 0 || *f.Sub > 65535):
			c.fail(CodeRange, "function.sub", "Modbus 8's sub-function, in [0, 65535]")
		case f.Code == 43 && (*f.Sub < 0 || *f.Sub > 255):
			c.fail(CodeRange, "function.sub", "Modbus 43's MEI type, in [0, 255]")
		case f.Code != 8 && f.Code != 43:
			c.fail(CodeConflict, "function.sub", "only on Modbus 8 and 43")
		}
		if f.SA != "" || f.SAErrorFrom != "" {
			c.fail(CodeConflict, "function.sa", "DNP3 only")
		}
	default:
		c.fail(CodeConflict, "protocol", "%q: function observations are dnp3 or modbus", protocol)
	}
}

func (in *Insecure) check(c *checker) {
	if !contains([]string{"telnet", "ftp", "http-plain", "snmp-v1", "snmp-v2c", "modbus-tcp"}, in.Reason) {
		c.fail(CodeForm, "insecure.reason", "%q is not on the insecure list", in.Reason)
	}
	if l := in.Login; l != nil {
		if !contains([]string{"telnet", "ftp", "http-plain"}, in.Reason) {
			c.fail(CodeConflict, "insecure.login", "only for Telnet, FTP and HTTP")
		}
		if l.User != nil {
			l.User.check(c, "insecure.login.user")
		}
		if l.Attempts < 0 {
			c.fail(CodeRange, "insecure.login.attempts", "%d is negative", l.Attempts)
		}
		if !contains([]string{"placed", "not-placed", "none"}, l.Slot) {
			c.fail(CodeForm, "insecure.login.slot", "%q is not placed, not-placed or none", l.Slot)
		}
		if l.Why != "" {
			c.token("insecure.login.why", l.Why)
		}
	}
	if in.RedirectOnly != nil && (!*in.RedirectOnly || in.Reason != "http-plain") {
		c.fail(CodeConflict, "insecure.redirect_only", "present only as true, on http-plain")
	}
}

func (e *Encrypted) check(c *checker) {
	switch e.Scheme {
	case "tls", "snmpv3", "ssh":
	default:
		c.fail(CodeForm, "encrypted.scheme", "%q is not tls, snmpv3 or ssh", e.Scheme)
	}
	if e.TLS != nil {
		if e.Scheme != "tls" {
			c.fail(CodeConflict, "encrypted.tls", "only with scheme tls")
		}
		c.token("encrypted.tls.version", e.TLS.Version)
		if e.TLS.SNI != nil {
			e.TLS.SNI.check(c, "encrypted.tls.sni")
		}
	}
	switch s := e.SNMPv3; {
	case s == nil && e.Scheme == "snmpv3":
		c.fail(CodeMissing, "encrypted.snmpv3", "an SNMPv3 header's fields are always in clear")
	case s != nil && e.Scheme != "snmpv3":
		c.fail(CodeConflict, "encrypted.snmpv3", "only with scheme snmpv3")
	case s != nil:
		if !engineIDForm.MatchString(s.EngineID) {
			c.fail(CodeForm, "encrypted.snmpv3.engine_id", "%q is not 5 to 32 octets in lowercase hex", s.EngineID)
		}
		s.User.check(c, "encrypted.snmpv3.user")
		if !contains([]string{"noAuthNoPriv", "authNoPriv", "authPriv"}, s.Level) {
			c.fail(CodeForm, "encrypted.snmpv3.level", "%q is not a security level", s.Level)
		}
		if (s.Boots != nil && *s.Boots < 0) || (s.Time != nil && *s.Time < 0) {
			c.fail(CodeRange, "encrypted.snmpv3.boots", "boots and time are not negative")
		}
	}
}

// checkFrames checks a channel record's frames: present exactly on a first
// sight, one per cited frame in citation order, each the cited length,
// hashing to the cited SHA-256, with every byte inside a redaction
// RedactionByte (C13 §3.2, §4.2).
func (o *Observation) checkFrames(c *checker) {
	if !o.FirstSight {
		if len(o.Frames) > 0 {
			c.fail(CodeConflict, "frames", "bytes travel only with a first sight")
		}
		return
	}
	if len(o.Frames) != len(o.Citation.Frames) {
		c.fail(CodeConflict, "frames", "%d frames for %d cited", len(o.Frames), len(o.Citation.Frames))
		return
	}
	for i, f := range o.Frames {
		ff := fmt.Sprintf("frames[%d]", i)
		cf := o.Citation.Frames[i]
		if f.N != cf.N {
			c.fail(CodeConflict, ff+".n", "%d, but the citation lists %d", f.N, cf.N)
		}
		if t, ok := c.utc(ff+".ts", f.TS); ok && (t.Unix() < 0 || t.Unix() > math.MaxUint32) {
			c.fail(CodeRange, ff+".ts", "%s is outside the stored capture's 32-bit seconds, 1970 to 2106 (C13 §4.2)", f.TS)
		}
		b, err := base64.StdEncoding.Strict().DecodeString(f.Data)
		if err != nil {
			c.fail(CodeForm, ff+".data", "not base64: %v", err)
			continue
		}
		if len(b) != cf.CapturedLen {
			c.fail(CodeConflict, ff+".data", "%d bytes, but captured_len is %d", len(b), cf.CapturedLen)
			continue
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != cf.SHA256 {
			c.fail(CodeHash, ff+".data", "does not hash to the cited sha256")
		}
		for j, r := range cf.Redactions {
			if r.Offset < 0 || r.Length < 1 || r.Offset+r.Length > len(b) {
				continue // failed in the citation's own check
			}
			if bytes.Count(b[r.Offset:r.Offset+r.Length], []byte{RedactionByte}) != r.Length {
				c.fail(CodeHash, fmt.Sprintf("%s.redactions[%d]", ff, j), "a byte inside the redaction is not 0x2a: listed and not applied")
			}
		}
	}
}

func (o *Observation) checkNode(c *checker) {
	n := o.Node
	for _, e := range []struct{ f, v string }{{"node.src_asset", n.SrcAsset}, {"node.dst_asset", n.DstAsset}} {
		if e.v != AssetUnresolved && !ValidUUID(e.v) {
			c.fail(CodeForm, e.f, "%q is not an asset ID or %s", e.v, AssetUnresolved)
		}
	}
	// Each end resolves on its own (C13 §5, D1 in D4-70): ip-ambiguous
	// when at least one end's address is shared, so that end is
	// unresolved and the other may name its asset; ip when an end resolved
	// and none is ambiguous; none when neither end matched.
	unresolved := n.SrcAsset == AssetUnresolved && n.DstAsset == AssetUnresolved
	switch n.ResolvedBy {
	case "ip":
		if unresolved {
			c.fail(CodeConflict, "node.resolved_by", "ip, but neither end resolved")
		}
		if o.IP == nil {
			c.fail(CodeConflict, "node.resolved_by", "ip, but the observation has no ip")
		}
	case "ip-ambiguous":
		if n.SrcAsset != AssetUnresolved && n.DstAsset != AssetUnresolved {
			c.fail(CodeConflict, "node.resolved_by", "ip-ambiguous, but both ends resolved")
		}
		if o.IP == nil {
			c.fail(CodeConflict, "node.resolved_by", "ip-ambiguous, but the observation has no ip")
		}
	case "none":
		if !unresolved {
			c.fail(CodeConflict, "node.resolved_by", "none, but an end resolved")
		}
	default:
		c.fail(CodeForm, "node.resolved_by", "%q is not ip, ip-ambiguous or none", n.ResolvedBy)
	}
	if ps := n.PlatformSession; ps != nil {
		c.uuid("node.platform_session.invocation_id", ps.InvocationID)
		if ps.Tie != "connection" && ps.Tie != "window" {
			c.fail(CodeForm, "node.platform_session.tie", "%q is not connection or window", ps.Tie)
		}
	}
	if n.EvidenceClass != "device-observed" && n.EvidenceClass != "simulated" {
		c.fail(CodeForm, "node.evidence_class", "%q is not device-observed or simulated", n.EvidenceClass)
	}
	switch {
	case o.FirstSight && n.StoredCapture == "":
		c.fail(CodeMissing, "node.stored_capture", "a first sight's bytes are its capture")
	case !o.FirstSight && n.StoredCapture != "":
		c.fail(CodeConflict, "node.stored_capture", "only a first sight has a capture")
	case n.StoredCapture != "":
		c.sha256("node.stored_capture", n.StoredCapture)
	}
	isFunc := o.Kind == KindFunction
	switch {
	case isFunc && !contains(FunctionClasses, n.FunctionClass):
		c.fail(CodeForm, "node.function_class", "%q is not a function class", n.FunctionClass)
	case !isFunc && n.FunctionClass != "":
		c.fail(CodeConflict, "node.function_class", "only on a function observation")
	}
	if (n.FunctionClass != "") != (n.FunctionTable != "") {
		c.fail(CodeConflict, "node.function_table", "present exactly with function_class")
	} else if n.FunctionTable != "" {
		c.table("node.function_table", n.FunctionTable)
	}
	want := isFunc && o.Function != nil && o.Protocol == "dnp3" && o.Function.SA == SANone && contains(NoSAClasses, n.FunctionClass)
	switch {
	case n.DNP3NoSA != nil && !*n.DNP3NoSA:
		c.fail(CodeForm, "node.dnp3_no_sa", "present only as true")
	case want != (n.DNP3NoSA != nil):
		c.fail(CodeConflict, "node.dnp3_no_sa", "set exactly on a DNP3 %v function with sa none", NoSAClasses)
	}
}

// DecodeStored reads a stored observation, a C4 event's netobs, and
// validates it. This minor or an earlier one is read strictly; a later 0.x
// minor's added fields are ignored.
func DecodeStored(b []byte) (*Observation, error) {
	if len(b) > event.MaxNetobsBytes {
		return nil, &Error{Code: CodeRange, Field: "netobs", Detail: fmt.Sprintf("%d bytes, above %d", len(b), event.MaxNetobsBytes)}
	}
	var o Observation
	if err := strictjson.Forward(b, &o); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "netobs", Detail: err.Error()}
	}
	if got, err := version.Parse(o.Schema); err == nil && got.Name == self.Name && got.Minor <= self.Minor {
		o = Observation{}
		if err := strictjson.Decode(b, &o); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "netobs", Detail: err.Error()}
		}
	}
	return &o, o.ValidateStored()
}

// ObservationFromEvent reads the stored observation of a C4
// network-observation event, and checks that the event's asset is the
// observation's destination asset (C13 §5).
func ObservationFromEvent(e *event.Event) (*Observation, error) {
	if e.Kind != event.KindNetworkObservation {
		return nil, &Error{Code: CodeType, Field: "kind", Detail: fmt.Sprintf("%q is not %s", e.Kind, event.KindNetworkObservation)}
	}
	o, err := DecodeStored(e.Netobs)
	if err != nil || o.Node == nil {
		return o, err
	}
	var asset string
	if e.Source.Asset != nil {
		asset = e.Source.Asset.ID
	}
	switch {
	case o.Node.DstAsset == AssetUnresolved && (asset != "" || !slices.Contains(e.Flags, "asset-unresolved")):
		return o, &Error{Code: CodeConflict, Field: "source.asset", Detail: "the destination is unresolved: no asset, and flag asset-unresolved"}
	case o.Node.DstAsset != AssetUnresolved && asset != o.Node.DstAsset:
		return o, &Error{Code: CodeConflict, Field: "source.asset", Detail: fmt.Sprintf("%q, but the destination asset is %s", asset, o.Node.DstAsset)}
	}
	return o, nil
}
