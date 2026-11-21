package netobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
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
	// MadeUTC is the sensor's clock when the agent numbered the record and
	// wrote it to its buffer (new in 0.2, CH-21): required in a 0.2
	// channel record, optional in a stored record of 0.2 or later.
	MadeUTC string `json:"made_utc,omitempty"`

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

// L2 is the frame's link layer. EtherType is the type after every 802.1Q,
// 802.1ad and HSR tag, as "0x" and four lowercase hex digits (C13 0.3
// §15.4). VLAN is the outermost tag's VID, nil for an untagged frame: on
// the 0.2 and 0.3 channels the key is required and 0, the null VID, is
// decoded to nil, so it is never stored. InnerVLANs are the VIDs of the
// tags after the outer one, in wire order, present exactly when the frame
// carried more than one tag; only the spoofing check reads them (§15.4).
type L2 struct {
	SrcMAC     string `json:"src_mac"`
	DstMAC     string `json:"dst_mac"`
	VLAN       *int   `json:"vlan,omitempty"`
	InnerVLANs []int  `json:"inner_vlans,omitempty"`
	EtherType  string `json:"ethertype"`
}

// MaxInnerVLANs bounds l2.inner_vlans: the frame stage reads at most four
// tags (C13 0.3 §15.4).
const MaxInnerVLANs = 3

// MaxUSMInteger is the upper bound of the USM's msgAuthoritativeEngineBoots
// and msgAuthoritativeEngineTime, INTEGER (0..2147483647) (RFC 3414 §2.4;
// C13 0.3 §15.5).
const MaxUSMInteger = 2147483647

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

	// New in 0.3, on an end only, each a delta since the connection's
	// previous end. Each is a pointer, so that absent, 0 and false stay
	// apart through a decode and re-encode, the node's tie path included
	// (C13 0.3 §1.1): nil is absent, and omitempty leaves out nil only.
	//
	// OrigPayload and RespPayload are the payload octets, and OrigPkts and
	// RespPkts the packets, that the record's ip.src and ip.dst ends sent
	// (CH-52): required on a 0.3 channel end, TCP or UDP.
	OrigPayload *int64 `json:"orig_payload,omitempty"`
	RespPayload *int64 `json:"resp_payload,omitempty"`
	OrigPkts    *int64 `json:"orig_pkts,omitempty"`
	RespPkts    *int64 `json:"resp_pkts,omitempty"`
	// ToDeviceOverlapOctets is the overlap count toward the device, and
	// Incomplete, present only as true, says that it and PasswordLines
	// cannot be read as complete (CH-53). TCP only. A 0.3 channel TCP end
	// carries one or both.
	ToDeviceOverlapOctets *int64 `json:"to_device_overlap_octets,omitempty"`
	Incomplete            *bool  `json:"incomplete,omitempty"`
	// RexmitInconsistent counts the engine's rexmit_inconsistency events,
	// over both directions (CH-54): required on a 0.3 channel TCP end.
	RexmitInconsistent *int64 `json:"rexmit_inconsistent,omitempty"`
	// PasswordLines counts the password lines the client sent, present
	// only when every credential slot was placed (CH-55). TCP only, never
	// required, never beside Incomplete.
	PasswordLines *int64 `json:"password_lines,omitempty"`
}

// counts03 lists the end's counts new in 0.3 by their field names, the
// four of CH-52 first.
func (f *Flow) counts03() []struct {
	name string
	v    *int64
} {
	return []struct {
		name string
		v    *int64
	}{
		{"flow.orig_payload", f.OrigPayload}, {"flow.resp_payload", f.RespPayload},
		{"flow.orig_pkts", f.OrigPkts}, {"flow.resp_pkts", f.RespPkts},
		{"flow.to_device_overlap_octets", f.ToDeviceOverlapOctets},
		{"flow.rexmit_inconsistent", f.RexmitInconsistent}, {"flow.password_lines", f.PasswordLines},
	}
}

// Service is a server seen on a port. The server is ip.dst.
type Service struct {
	Basis   string `json:"basis"`
	Version *Text  `json:"version,omitempty"`
}

// Function is a request's application function (C13 §4.3). Sub is Modbus
// 8's sub-function or 43's MEI type (C13 §14). SA, SAErrorFrom and
// ObjectsUnread are DNP3 only. On the 0.2 and 0.3 channels a DNP3 function
// carries SA and ObjectsUnread; in a stored record an absent SA reads as
// not determined, and an absent ObjectsUnread as true (C13 0.3 §15.2,
// §15.3).
type Function struct {
	Code    int      `json:"code"`
	Sub     *int     `json:"sub,omitempty"`
	Objects []string `json:"objects"`
	// ObjectsUnread says that Objects holds only the headers read before
	// the first one that could not be read (§15.3).
	ObjectsUnread *bool  `json:"objects_unread,omitempty"`
	Unit          *int   `json:"unit,omitempty"`
	SA            string `json:"sa,omitempty"`
	SAErrorFrom   string `json:"sa_error_from,omitempty"`
}

// ObjectsRead reports whether a DNP3 function's object headers were read to
// the end of the request: objects_unread present as false. Present as true,
// or absent in a stored record, they may not have been, and every reader
// takes the record fail-closed (C13 0.3 §15.3).
func (f *Function) ObjectsRead() bool { return f.ObjectsUnread != nil && !*f.ObjectsUnread }

// SA outcomes. Closed. SAUnknown is a DNP3 request whose SA the sensor
// could not determine (C13 0.3 §15.2).
const (
	SAChallenged = "challenged"
	SAAggressive = "aggressive"
	SAFailed     = "failed"
	SANone       = "none"
	SAUnknown    = "unknown"
)

// SAOutcomes lists every SA outcome.
var SAOutcomes = []string{SAChallenged, SAAggressive, SAFailed, SANone, SAUnknown}

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

// SNMPv3 is an SNMPv3 message header's fields in clear. UsmParsed says the
// UsmSecurityParameters were parsed and the engine ID is at most 32
// octets: with true, EngineID, User, Boots and Time are its fields; with
// false, all four are absent. On the 0.2 and 0.3 channels UsmParsed is
// required; in a stored record an absent one reads as true (C13 0.3
// §15.5).
type SNMPv3 struct {
	UsmParsed *bool   `json:"usm_parsed,omitempty"`
	EngineID  *string `json:"engine_id,omitempty"`
	User      *Text   `json:"user,omitempty"`
	Level     string  `json:"level"`
	Boots     *int64  `json:"boots,omitempty"`
	Time      *int64  `json:"time,omitempty"`
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
	// DNP3SAUnknown is set exactly on a DNP3 function of a NoSAClasses
	// class whose sa is unknown: not shown protected, and never a
	// dnp3_no_sa (C13 0.3 §15.2).
	DNP3SAUnknown *bool `json:"dnp3_sa_unknown,omitempty"`
	// The node's marks, new in 0.2, each absent in a 0.1 record (C13 0.2
	// §11): Late, a record later than late_bound_s (CH-23); Backlog, a
	// backlog record committed untied (CH-39); Skewed, committed while no
	// tie was made for skew (CH-41); Lost, the declared losses' unjudged
	// windows, at most MaxLostSpans (CH-40).
	Late    bool   `json:"late,omitempty"`
	Backlog bool   `json:"backlog,omitempty"`
	Skewed  bool   `json:"skewed,omitempty"`
	Lost    []Span `json:"lost,omitempty"`
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
// dnp3_no_sa, and with sa unknown dnp3_sa_unknown (C13 §5, 0.3 §15.2).
var NoSAClasses = []string{ClassWrite, ClassControl, ClassSessionSetup}

var (
	macForm       = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
	etherTypeForm = regexp.MustCompile(`^0x[0-9a-f]{4}$`)
	objectForm    = regexp.MustCompile(`^g(?:0|[1-9][0-9]{0,2})v(?:0|[1-9][0-9]{0,2})$`)
	engineIDForm  = regexp.MustCompile(`^(?:[0-9a-f]{2}){0,32}$`)
	// engineIDForm01 is 0.1's form, kept for a 0.1 record (D4-103 ruling
	// 2; D6's finding 2 on #762).
	engineIDForm01 = regexp.MustCompile(`^(?:[0-9a-f]{2}){5,32}$`)
)

// Validate checks an observation of the 0.1 channel, the one main's intake
// reads: every rule of C13 that holds on one record, including the frame
// bytes against their hashes and the redactions applied. It refuses a
// record with Node set, and any field new in 0.2.
func (o *Observation) Validate() error { return o.validateChannel(Identifier, nil, nil) }

// validateChannel checks a channel observation of the minor want; keys are
// the decoded document's key paths and nulls those whose value is null,
// each nil for a Go value.
func (o *Observation) validateChannel(want string, keys, nulls map[string]bool) error {
	c := &checker{keys: keys, nulls: nulls}
	c.strictSchema(o.Schema, want)
	o.check(c)
	c.requireKeys("", reflect.ValueOf(o).Elem())
	if o.Node != nil {
		c.fail(CodeConflict, "node", "a sensor's record never carries node")
	}
	o.checkFrames(c)
	c.refuseNulls()
	// The null VID is read as untagged, so no reader and no stored record
	// sees 0 (C13 0.3 §15.4).
	if c.need >= 2 && o.L2.VLAN != nil && *o.L2.VLAN == 0 {
		o.L2.VLAN = nil
	}
	return c.err()
}

// ValidateStored checks a stored observation: Frames absent, Node set and
// consistent with the body. A later 0.x minor is read forward.
func (o *Observation) ValidateStored() error { return o.validateStored(nil) }

// validateStored is ValidateStored; keys are the decoded document's key
// paths, nil for a Go value.
func (o *Observation) validateStored(keys map[string]bool) error {
	c := &checker{keys: keys}
	c.storedSchema(o.Schema)
	if c.later {
		// A later C13 minor is refused at judging, alone (D4-c4-0.6
		// §3.2): its forward read may have dropped keys this reader
		// does not know, so nothing else in it is judged.
		return &Error{Code: CodeSchema, Field: "schema", Detail: fmt.Sprintf("%q is a later minor than this reader's %s", o.Schema, self), err: ErrLaterMinor}
	}
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
	// No order is checked between made_utc and the capture times: the
	// sensor's clock may step (CH-21).
	if c.new02("made_utc", o.MadeUTC != "") {
		c.utc("made_utc", o.MadeUTC)
	}
	if o.ResolutionNS < 1 || o.ResolutionNS > 1e9 {
		c.fail(CodeRange, "resolution_ns", "%d not in [1, 1e9]", o.ResolutionNS)
	}
	o.L2.check(c)
	l4 := ""
	if o.IP != nil {
		l4 = o.IP.check(c)
	}
	// ip is required exactly on an IP frame: the type after every tag is
	// IPv4 or IPv6. Channel only, so a stored record reads as it did (C13
	// 0.3 §15.1, §15.4).
	if c.need >= 2 {
		isIP := o.L2.EtherType == "0x0800" || o.L2.EtherType == "0x86dd"
		switch {
		case isIP && o.IP == nil && !c.keys["ip"]:
			c.fail(CodeMissing, "ip", "required on an IP frame, ethertype %s", o.L2.EtherType)
		case !isIP && o.IP != nil:
			c.fail(CodeConflict, "ip", "on a frame whose type after its tags is %s, not IPv4 or IPv6", o.L2.EtherType)
		}
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
	// On the 0.2 and 0.3 channels vlan is required, and 0, the null VID,
	// is untagged; a stored record never carries 0 (C13 0.3 §15.4).
	low := 1
	if c.need >= 2 {
		low = 0
		c.required("l2.vlan")
	}
	if l.VLAN != nil && (*l.VLAN < low || *l.VLAN > 4094) {
		c.fail(CodeRange, "l2.vlan", "%d not in [%d, 4094]", *l.VLAN, low)
	}
	if (l.InnerVLANs != nil || c.keys["l2.inner_vlans"]) && c.new02("l2.inner_vlans", true) {
		switch n := len(l.InnerVLANs); {
		case n == 0 && !c.nulls["l2.inner_vlans"]:
			c.fail(CodeConflict, "l2.inner_vlans", "present only for a frame with more than one tag, so never []")
		case n > MaxInnerVLANs:
			c.fail(CodeRange, "l2.inner_vlans", "%d inner VIDs, above %d", n, MaxInnerVLANs)
		}
		for i, v := range l.InnerVLANs {
			if v < 0 || v > 4094 {
				c.fail(CodeRange, fmt.Sprintf("l2.inner_vlans[%d]", i), "%d not in [0, 4094]", v)
			}
		}
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
			c.required("flow.end")
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
		f.check03(c, l4)
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
		c.required("identity.value")
		id.Value.check(c, "identity.value")
		c.token("identity.via", id.Via)
	case o.Undecoded != nil:
		if !contains([]string{"port", "ethertype", "none"}, o.Undecoded.Basis) {
			c.fail(CodeForm, "undecoded.basis", "%q is not port, ethertype or none", o.Undecoded.Basis)
		}
		// Channel only (C13 0.3 §15.1).
		switch {
		case c.need < 2:
		case o.Undecoded.Basis == "port" && o.IP == nil:
			c.fail(CodeConflict, "undecoded.basis", "port needs ip")
		case o.Undecoded.Basis == "ethertype" && o.IP != nil:
			c.fail(CodeConflict, "undecoded.basis", "ethertype never with ip")
		}
		if o.Undecoded.Packets < 1 {
			c.fail(CodeRange, "undecoded.packets", "%d: at least one", o.Undecoded.Packets)
		}
	}
}

// check03 applies the placement and range rules of the end's counts new
// in 0.3 (C13 0.3 §3 to §6). Each is from 0 to 2^63 - 1, the int64's
// range, so 2^63 fails the decode. None is on a start. The overlap count,
// incomplete, rexmit_inconsistent and password_lines are on a TCP end
// only. incomplete is present only as true, and never beside
// password_lines. On a syn-only end both payload counts are 0. On the 0.3
// channel an end carries the four counts of CH-52, and a TCP end
// rexmit_inconsistent and the overlap count, incomplete or both: no TCP
// end carries neither (CH-53).
func (f *Flow) check03(c *checker, l4 string) {
	counts := f.counts03()
	// A key present with null is refused below 0.3 as new, and at 0.3 as
	// null: it is never read as absent.
	for _, x := range counts {
		if x.v == nil && !c.keys[x.name] {
			continue
		}
		if c.new03(x.name, true) {
			c.null(x.name, x.v == nil)
		}
		if x.v != nil && *x.v < 0 {
			c.fail(CodeRange, x.name, "%d not in [0, 2^63 - 1]", *x.v)
		}
	}
	if f.Incomplete != nil || c.keys["flow.incomplete"] {
		if c.new03("flow.incomplete", true) {
			c.null("flow.incomplete", f.Incomplete == nil)
		}
		if f.Incomplete != nil && !*f.Incomplete {
			c.fail(CodeForm, "flow.incomplete", "present only as true")
		}
	}
	if f.Phase != "end" {
		for _, x := range counts {
			if x.v != nil {
				c.fail(CodeConflict, x.name, "only on the end phase")
			}
		}
		if f.Incomplete != nil {
			c.fail(CodeConflict, "flow.incomplete", "only on the end phase")
		}
		return
	}
	for _, x := range counts[:4] {
		c.new03(x.name, x.v != nil)
	}
	if l4 != "tcp" {
		for _, x := range counts[4:] {
			if x.v != nil {
				c.fail(CodeConflict, x.name, "only on a tcp end")
			}
		}
		if f.Incomplete != nil {
			c.fail(CodeConflict, "flow.incomplete", "only on a tcp end")
		}
		return
	}
	c.new03("flow.rexmit_inconsistent", f.RexmitInconsistent != nil)
	if c.need >= 3 && f.ToDeviceOverlapOctets == nil && f.Incomplete == nil {
		c.fail(CodeMissing, "flow.to_device_overlap_octets", "a 0.3 channel tcp end carries the overlap count, incomplete, or both")
	}
	if f.PasswordLines != nil && f.Incomplete != nil {
		c.fail(CodeConflict, "flow.password_lines", "never beside incomplete")
	}
	if f.SynOnly != nil && *f.SynOnly {
		for _, x := range counts[:2] {
			if x.v != nil && *x.v != 0 {
				c.fail(CodeConflict, x.name, "%d, but a syn-only flow carries no payload", *x.v)
			}
		}
	}
}

func (f *Function) check(c *checker, protocol string) {
	c.required("function.code")
	c.required("function.objects")
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
		// sa is required on the 0.2 and 0.3 channels, unknown when not
		// determined (C13 0.3 §15.2); a stored record may leave it out.
		c.required("function.sa")
		if (f.SA != "" || (c.need >= 2 && c.keys["function.sa"])) && !contains(SAOutcomes, f.SA) {
			c.fail(CodeForm, "function.sa", "%q is not an SA outcome", f.SA)
		}
		// unknown is new in 0.2 (§15.2), refused in a 0.1 record as the
		// 0.1 reader refused it (D4-103 ruling 2; D3's F2 on #760).
		if f.SA == SAUnknown && c.minor < 2 {
			c.fail(CodeForm, "function.sa", "%q is not an SA outcome in a 0.%d record", f.SA, c.minor)
		}
		// objects_unread is required on the 0.2 and 0.3 channels (§15.3).
		// sa none says every header was read and none was SA's, so it is
		// never beside true, on both paths: only a record carrying the new
		// key is refused.
		if c.new02("function.objects_unread", f.ObjectsUnread != nil || c.keys["function.objects_unread"]) &&
			f.ObjectsUnread != nil && *f.ObjectsUnread && f.SA == SANone {
			c.fail(CodeConflict, "function.objects_unread", "true never beside sa none")
		}
		switch {
		case f.SA == SAFailed && f.SAErrorFrom == "" && c.need >= 2 && !c.keys["function.sa_error_from"]:
			c.fail(CodeMissing, "function.sa_error_from", "required with sa failed")
		case f.SA == SAFailed && f.SAErrorFrom != "master" && f.SAErrorFrom != "outstation":
			c.fail(CodeForm, "function.sa_error_from", "%q is not master or outstation", f.SAErrorFrom)
		case f.SA != SAFailed && f.SAErrorFrom != "":
			c.fail(CodeConflict, "function.sa_error_from", "only with sa failed")
		}
	case "modbus":
		if len(f.Objects) > 0 {
			c.fail(CodeConflict, "function.objects", "empty for Modbus")
		}
		c.required("function.unit")
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
		if f.ObjectsUnread != nil || c.keys["function.objects_unread"] {
			c.fail(CodeConflict, "function.objects_unread", "DNP3 only")
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
		// An absent count decodes as 0 too. On the 0.2 and 0.3 channels it
		// is refused, not read as 0 (D1's ruling on #726); the 0.1 channel
		// and stored records read as they did.
		if c.need >= 2 && c.keys != nil && !c.keys["insecure.login.attempts"] {
			c.fail(CodeMissing, "insecure.login.attempts", "required")
		}
		if !contains([]string{"placed", "not-placed", "none"}, l.Slot) {
			c.fail(CodeForm, "insecure.login.slot", "%q is not placed, not-placed or none", l.Slot)
		}
		if l.Why != "" {
			c.token("insecure.login.why", l.Why)
		}
		// Channel only, so a stored record reads as it did (C13 0.3 §15.6):
		// a user name only where the slot was placed, and why exactly where
		// it was not.
		if c.need >= 2 {
			if (l.User != nil || c.keys["insecure.login.user"]) && l.Slot != "placed" {
				c.fail(CodeConflict, "insecure.login.user", "only with slot placed, not %q", l.Slot)
			}
			if (l.Why != "" || c.keys["insecure.login.why"]) != (l.Slot == "not-placed") {
				c.fail(CodeConflict, "insecure.login.why", "present exactly with slot not-placed, not %q", l.Slot)
			}
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
		s.check(c)
	}
}

// check applies C13 0.3 §15.5. usm_parsed is required on the 0.2 and 0.3
// channels, and absent reads as true. With true, the channel requires the
// four USM fields and bounds boots and time at MaxUSMInteger; a stored
// record reads as it did, so engine_id, which every record needed before
// §15, stays required on every path unless usm_parsed is false (D3's F1
// on #760). With false, the four are refused if present, on
// both paths, since only a record carrying the new key can be refused.
func (s *SNMPv3) check(c *checker) {
	const p = "encrypted.snmpv3."
	c.new02(p+"usm_parsed", s.UsmParsed != nil || c.keys[p+"usm_parsed"])
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"engine_id", s.EngineID != nil}, {"user", s.User != nil},
		{"boots", s.Boots != nil}, {"time", s.Time != nil},
	} {
		switch present := f.set || c.keys[p+f.name]; {
		case s.UsmParsed != nil && !*s.UsmParsed && present:
			c.fail(CodeConflict, p+f.name, "absent with usm_parsed false: the USM block was not parsed")
		case (s.UsmParsed == nil || *s.UsmParsed) && !present && (c.need >= 2 || f.name == "engine_id"):
			c.fail(CodeMissing, p+f.name, "required with usm_parsed true")
		}
	}
	switch {
	case s.EngineID == nil:
	case c.minor < 2 && !engineIDForm01.MatchString(*s.EngineID):
		c.fail(CodeForm, p+"engine_id", "%q is not 5 to 32 octets in lowercase hex in a 0.1 record", *s.EngineID)
	case !engineIDForm.MatchString(*s.EngineID):
		c.fail(CodeForm, p+"engine_id", "%q is not 0 to 32 octets in lowercase hex", *s.EngineID)
	}
	if s.User != nil {
		s.User.check(c, p+"user")
	}
	if !contains([]string{"noAuthNoPriv", "authNoPriv", "authPriv"}, s.Level) {
		c.fail(CodeForm, p+"level", "%q is not a security level", s.Level)
	}
	for _, f := range []struct {
		name string
		v    *int64
	}{{"boots", s.Boots}, {"time", s.Time}} {
		switch {
		case f.v == nil:
		case *f.v < 0:
			c.fail(CodeRange, p+f.name, "%d is negative", *f.v)
		case *f.v > MaxUSMInteger && c.need >= 2:
			c.fail(CodeRange, p+f.name, "%d above %d", *f.v, MaxUSMInteger)
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
	if len(o.Frames) == 0 && c.need >= 2 && !c.keys["frames"] {
		c.fail(CodeMissing, "frames", "required on a first sight")
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
	// dnp3_sa_unknown is new in 0.2, as sa unknown is (D3's F2 on #760).
	c.new02("node.dnp3_sa_unknown", n.DNP3SAUnknown != nil)
	for _, x := range []struct {
		field, sa string
		flag      *bool
	}{{"node.dnp3_no_sa", SANone, n.DNP3NoSA}, {"node.dnp3_sa_unknown", SAUnknown, n.DNP3SAUnknown}} {
		want := isFunc && o.Function != nil && o.Protocol == "dnp3" && o.Function.SA == x.sa && contains(NoSAClasses, n.FunctionClass)
		switch {
		case x.flag != nil && !*x.flag:
			c.fail(CodeForm, x.field, "present only as true")
		case want != (x.flag != nil):
			c.fail(CodeConflict, x.field, "set exactly on a DNP3 %v function with sa %s", NoSAClasses, x.sa)
		}
	}
	c.new02("node.late", n.Late)
	c.new02("node.backlog", n.Backlog)
	c.new02("node.skewed", n.Skewed)
	c.new02("node.lost", n.Lost != nil)
	c.spans("node.lost", n.Lost)
}

// DecodeStored reads a stored observation, a C4 event's netobs, and
// validates it. This minor or an earlier one is read strictly. A later 0.x
// minor is read forward and then refused with ErrLaterMinor, alone, and the
// observation returned is nil (D4-c4-0.6 §3.1 and §3.2).
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
	err := o.validateStored(keyPaths(b))
	if errors.Is(err, ErrLaterMinor) {
		return nil, err
	}
	return &o, err
}

// ObservationFromEvent reads the stored observation of a C4
// network-observation event, and checks that the event's asset is the
// observation's destination asset (C13 §5). An event of a later C4 minor
// is refused by CheckEventMinor before its body is read. Each Field of the
// body's errors is prefixed "netobs.", so the C13 stamp reads netobs.schema
// and the C4 stamp schema; the whole-body Field netobs is kept (D4-c4-0.6
// §3.1, "The Field split"). A refused later minor returns a nil
// observation.
func ObservationFromEvent(e *event.Event) (*Observation, error) {
	if e.Kind != event.KindNetworkObservation {
		return nil, &Error{Code: CodeType, Field: "kind", Detail: fmt.Sprintf("%q is not %s", e.Kind, event.KindNetworkObservation)}
	}
	if err := CheckEventMinor(e); err != nil {
		return nil, err
	}
	o, err := DecodeStored(e.Netobs)
	if err != nil || o.Node == nil {
		return o, bodyFields(err)
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

// bodyFields prefixes "netobs." to the Field of each *Error in err, a
// DecodeStored error that may be a join, except the whole-body Field
// "netobs". Each *Error is copied, so the sentinel it carries is kept.
func bodyFields(err error) error {
	switch x := err.(type) {
	case *Error:
		if x.Field == "netobs" {
			return x
		}
		y := *x
		y.Field = "netobs." + x.Field
		return &y
	case interface{ Unwrap() []error }:
		var out []error
		for _, e := range x.Unwrap() {
			out = append(out, bodyFields(e))
		}
		return errors.Join(out...)
	}
	return err
}
