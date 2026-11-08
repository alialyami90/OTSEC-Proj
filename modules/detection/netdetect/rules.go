package netdetect

import (
	"fmt"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/netobs"
)

// rule is one detector rule (baseline note §4): when it applies to a stored
// observation, and the alert's words for it. applies is a variable's field
// so that the mutation test can swap a rule's condition for a mutant.
type rule struct {
	rule netobs.Rule
	// base says the rule judges against the acknowledged baseline: it runs
	// only once one is, and never on an observation tied to the node's own
	// session, which the tie rule judges (§2.1, §5).
	base    bool
	applies func(d *Detector, o *netobs.Observation) bool
	// explain gives the alert's baseline_value and observation, the node's
	// own words, with no device text (C13 §7.1).
	explain func(d *Detector, o *netobs.Observation) (string, string)
}

// rules are the rules this version runs, in netobs.Rules order. Each one
// is called only on an observation with an IP header.
var rules = []rule{
	{netobs.RuleUnknownPair, true, unknownPair, explainUnknownPair},
	{netobs.RuleNewService, true, newService, explainNewService},
	{netobs.RuleNewFunction, true, newFunction, explainNewFunction},
	{netobs.RuleUnauthorizedWrite, true, unauthorizedWrite, explainUnauthorizedWrite},
	{netobs.RuleUnresolvedAddress, true, unresolvedAddress, explainUnresolvedAddress},
	{netobs.RuleSAFailed, false, saFailed, explainSAFailed},
}

func flowStart(o *netobs.Observation) bool {
	return o.Kind == netobs.KindFlow && o.Flow != nil && o.Flow.Phase == "start"
}

// pairOf is o's pair as the client sent it: src to dst's port. ok is false
// with no destination port.
func pairOf(o *netobs.Observation) (netobs.Pair, bool) {
	if o.IP.Dport == nil {
		return netobs.Pair{}, false
	}
	return netobs.Pair{Client: endpoint(o.Node.SrcAsset, o.IP.Src), Server: endpoint(o.Node.DstAsset, o.IP.Dst),
		L4: o.IP.L4, Port: *o.IP.Dport, Protocol: o.Protocol}, true
}

func writeClass(class string) bool { return class == netobs.ClassWrite || class == netobs.ClassControl }

// unknownPair: a flow start whose pair is not in pairs. A midstream TCP
// flow or a UDP flow raises it only when neither orientation is in pairs,
// because its src is only the first frame's sender (C13 §4.1): either way
// stays within the same two endpoints, with the learned port at the end
// that had it (§2.2, §4; D1 in D4-71).
func unknownPair(d *Detector, o *netobs.Observation) bool {
	p, ok := pairOf(o)
	if !flowStart(o) || !ok {
		return false
	}
	switch {
	case o.Direction == netobs.DirectionClientServer:
		return !d.pairs[p]
	case o.Direction == netobs.DirectionMidstream || o.IP.L4 == "udp":
		if d.pairs[p] {
			return false
		}
		if o.IP.Sport == nil {
			return true
		}
		return !d.pairs[netobs.Pair{Client: p.Server, Server: p.Client, L4: p.L4, Port: *o.IP.Sport, Protocol: p.Protocol}]
	}
	return false
}

// newService: a service whose server, transport, port and protocol are not
// in services, by either basis.
func newService(d *Detector, o *netobs.Observation) bool {
	p, ok := pairOf(o)
	return o.Kind == netobs.KindService && o.Service != nil && ok &&
		!d.services[serviceKey{p.Server, p.L4, p.Port, p.Protocol}]
}

// newFunction: a function on a known pair whose code, sub and objects are
// not in functions for that pair, and whose class is not write or control,
// which the writer list judges (§4).
func newFunction(d *Detector, o *netobs.Observation) bool {
	p, ok := pairOf(o)
	return o.Kind == netobs.KindFunction && o.Function != nil && ok && !writeClass(o.Node.FunctionClass) &&
		d.pairs[p] && !d.functions[functionKey(functionOf(p, o.Function))]
}

// unauthorizedWrite: a write-class or control-class function whose client,
// server and class are not in authorized_writers. Whether the pair or the
// function was learned doesn't matter (§2.3).
func unauthorizedWrite(d *Detector, o *netobs.Observation) bool {
	return o.Kind == netobs.KindFunction && o.Function != nil && writeClass(o.Node.FunctionClass) &&
		!d.writers[netobs.Writer{Client: endpoint(o.Node.SrcAsset, o.IP.Src), Server: endpoint(o.Node.DstAsset, o.IP.Dst), Class: o.Node.FunctionClass}]
}

// unresolvedAddress: a flow start with an end that resolves to no asset at
// an address not in addresses. Any transport and direction.
func unresolvedAddress(d *Detector, o *netobs.Observation) bool {
	return flowStart(o) && (len(unknownEnds(d, o)) > 0)
}

func unknownEnds(d *Detector, o *netobs.Observation) []string {
	var out []string
	for _, e := range [][2]string{{o.Node.SrcAsset, o.IP.Src}, {o.Node.DstAsset, o.IP.Dst}} {
		if e[0] == netobs.AssetUnresolved && !d.addresses[addrKey{e[1], endpoint(e[0], e[1])}] {
			out = append(out, e[1])
		}
	}
	return out
}

// saFailed: a DNP3 function whose SA exchange failed, of any class.
func saFailed(_ *Detector, o *netobs.Observation) bool {
	return o.Kind == netobs.KindFunction && o.Function != nil && o.Protocol == "dnp3" && o.Function.SA == netobs.SAFailed
}

// The words. Each is at most netobs.ExplainMax bytes at its longest: two
// unresolved IPv6 endpoints and a 64-byte protocol token
// (TestExplainFits).

func hostPort(ip string, port *int) string {
	if port == nil {
		return ip
	}
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return ip + ":" + strconv.Itoa(*port)
}

func (d *Detector) inBaseline() string { return "in baseline v" + strconv.FormatInt(d.version, 10) }

func flowText(o *netobs.Observation) string {
	return fmt.Sprintf("%s flow from %s to %s, %s", o.IP.L4, hostPort(o.IP.Src, o.IP.Sport), hostPort(o.IP.Dst, o.IP.Dport), o.Direction)
}

func codeText(f *netobs.Function) string {
	if f.Sub == nil {
		return strconv.Itoa(f.Code)
	}
	return strconv.Itoa(f.Code) + "/" + strconv.Itoa(*f.Sub)
}

// classText says what a function did by its class, never by its code: a
// write alert says it wrote to the device, never "a settings write",
// because Modbus 06h and 10h also operate outputs (§4).
var classText = map[string]string{
	netobs.ClassRead: "read from the device", netobs.ClassWrite: "wrote to the device",
	netobs.ClassControl: "sent a control to the device", netobs.ClassSessionSetup: "changed event reporting",
	netobs.ClassTimeSync: "set or measured the device's time", netobs.ClassOther: "sent another request",
}

func functionText(o *netobs.Observation) string {
	return fmt.Sprintf("%s function %s from %s %s at %s", o.Protocol, codeText(o.Function), o.IP.Src,
		classText[o.Node.FunctionClass], hostPort(o.IP.Dst, o.IP.Dport))
}

func explainUnknownPair(d *Detector, o *netobs.Observation) (string, string) {
	p, _ := pairOf(o)
	if o.Direction == netobs.DirectionMidstream {
		return fmt.Sprintf("no pair of %s and %s %s %s either way %s", p.Client, p.Server, p.L4, p.Protocol, d.inBaseline()), flowText(o)
	}
	return fmt.Sprintf("no pair %s to %s %s/%d %s %s", p.Client, p.Server, p.L4, p.Port, p.Protocol, d.inBaseline()), flowText(o)
}

func explainNewService(d *Detector, o *netobs.Observation) (string, string) {
	p, _ := pairOf(o)
	return fmt.Sprintf("no service %s %s/%d %s %s", p.Server, p.L4, p.Port, p.Protocol, d.inBaseline()),
		fmt.Sprintf("%s service at %s, found by %s", o.Protocol, hostPort(o.IP.Dst, o.IP.Dport), o.Service.Basis)
}

func explainNewFunction(d *Detector, o *netobs.Observation) (string, string) {
	p, _ := pairOf(o)
	return fmt.Sprintf("function %s with %d object types not seen on %s to %s %s/%d %s", codeText(o.Function), len(o.Function.Objects),
		p.Client, p.Server, p.L4, p.Port, d.inBaseline()), functionText(o)
}

func explainUnauthorizedWrite(d *Detector, o *netobs.Observation) (string, string) {
	p, _ := pairOf(o)
	return fmt.Sprintf("%s is not an authorized %s writer to %s %s", p.Client, o.Node.FunctionClass, p.Server, d.inBaseline()), functionText(o)
}

func explainUnresolvedAddress(d *Detector, o *netobs.Observation) (string, string) {
	return fmt.Sprintf("%s not in the addresses %s", strings.Join(unknownEnds(d, o), " and "), d.inBaseline()),
		flowText(o) + ", resolving to no asset"
}

func explainSAFailed(_ *Detector, o *netobs.Observation) (string, string) {
	by := "the master"
	if o.Function.SAErrorFrom == "outstation" {
		by = "the outstation"
	}
	return "DNP3 SA in use: authentication is expected to pass",
		fmt.Sprintf("SA authentication failed, error sent by %s, on function %d from %s to %s", by, o.Function.Code, o.IP.Src, hostPort(o.IP.Dst, o.IP.Dport))
}
