package netdetect

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/netobs"
)

// The rules on the platform's own traffic (baseline note §5, AP-35). The
// node's intake ties each of the node's own flows to its session record
// before it commits the observation (D1 in D4-72), so here a tie is only
// node.platform_session: the detector judges its absence, and never holds
// a flow itself.

// MaxNodeAddresses and MaxNodeMACs bound the install configuration's lists
// (D1 in D4-72).
const (
	MaxNodeAddresses = 8
	MaxNodeMACs      = 8
)

// ownConfig is the node's own identity as the detector compares it:
// addresses parsed and unmapped, MACs lowercase.
type ownConfig struct {
	addrs     map[netip.Addr]bool
	macs      map[string]bool
	vlans     map[int]bool
	untagged  bool
	excluded  map[destKey]bool
	endpoints map[destKey]string // to the asset
	// recorded are the endpoint addresses the coverage record keeps, the
	// first MaxDetectorEndpoints by address; endpointList is every
	// endpoint, in the configuration's order.
	recorded     map[netip.Addr]bool
	endpointList []configEndpoint
	// untracked counts the endpoint addresses past MaxDetectorEndpoints.
	untracked int
}

type configEndpoint struct {
	Endpoint
	addr netip.Addr
}

var macForm = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)

type destKey struct {
	addr netip.Addr
	l4   string
	port int
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func newOwnConfig(cfg DetectorConfig) (ownConfig, error) {
	o := ownConfig{addrs: map[netip.Addr]bool{}, macs: map[string]bool{}, vlans: map[int]bool{}, untagged: cfg.NodeUntagged,
		excluded: map[destKey]bool{}, endpoints: map[destKey]string{}}
	switch {
	case len(cfg.NodeAddresses) < 1 || len(cfg.NodeAddresses) > MaxNodeAddresses:
		return o, fmt.Errorf("netdetect: %d node addresses, not 1 to %d", len(cfg.NodeAddresses), MaxNodeAddresses)
	case len(cfg.NodeMACs) < 1 || len(cfg.NodeMACs) > MaxNodeMACs:
		return o, fmt.Errorf("netdetect: %d node MACs, not 1 to %d", len(cfg.NodeMACs), MaxNodeMACs)
	case len(cfg.NodeVLANs) == 0 && !cfg.NodeUntagged:
		return o, fmt.Errorf("netdetect: no node segment")
	}
	for _, s := range cfg.NodeAddresses {
		a, ok := parseAddr(s)
		if !ok {
			return o, fmt.Errorf("netdetect: node address %q is not an IP literal", s)
		}
		o.addrs[a] = true
	}
	for _, m := range cfg.NodeMACs {
		if !macForm.MatchString(m) {
			return o, fmt.Errorf("netdetect: node MAC %q is not a lowercase MAC", m)
		}
		o.macs[m] = true
	}
	for _, v := range cfg.NodeVLANs {
		if v < 1 || v > 4094 {
			return o, fmt.Errorf("netdetect: node VLAN %d is not 1 to 4094", v)
		}
		o.vlans[v] = true
	}
	for _, x := range cfg.Exclusions {
		k, err := newDestKey(x)
		if err != nil {
			return o, err
		}
		o.excluded[k] = true
	}
	for _, e := range cfg.Endpoints {
		k, err := newDestKey(e.Destination)
		if err != nil {
			return o, err
		}
		if !netobs.ValidUUID(e.AssetID) {
			return o, fmt.Errorf("netdetect: endpoint asset %q is not a UUID", e.AssetID)
		}
		o.endpoints[k] = e.AssetID
		o.endpointList = append(o.endpointList, configEndpoint{e, k.addr})
	}
	var addrs []netip.Addr
	for _, e := range o.endpointList {
		addrs = append(addrs, e.addr)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return strings.Compare(a.String(), b.String()) })
	addrs = slices.Compact(addrs)
	o.recorded = map[netip.Addr]bool{}
	for _, a := range addrs[:min(len(addrs), netobs.MaxDetectorEndpoints)] {
		o.recorded[a] = true
	}
	o.untracked = len(addrs) - len(o.recorded)
	return o, nil
}

func newDestKey(dst Destination) (destKey, error) {
	a, ok := parseAddr(dst.Addr)
	if !ok || (dst.L4 != "tcp" && dst.L4 != "udp") || dst.Port < 1 || dst.Port > 65535 {
		return destKey{}, fmt.Errorf("netdetect: %q %s %d is not an exact destination", dst.Addr, dst.L4, dst.Port)
	}
	return destKey{a, dst.L4, dst.Port}, nil
}

// fromNode reports whether o's source is one of the node's addresses.
func (d *Detector) fromNode(o *netobs.Observation) bool {
	a, ok := parseAddr(o.IP.Src)
	return ok && d.own.addrs[a]
}

// dest is o's destination as an exact destination.
func dest(o *netobs.Observation) (destKey, bool) {
	a, ok := parseAddr(o.IP.Dst)
	if !ok || o.IP.Dport == nil {
		return destKey{}, false
	}
	return destKey{a, o.IP.L4, *o.IP.Dport}, true
}

// ownSessionOutsideRecord: a flow start from a node address to an asset,
// or to an enrolled asset's run endpoint, that intake did not tie to a
// session record, and whose destination is not one the node excludes.
func ownSessionOutsideRecord(d *Detector, o *netobs.Observation) bool {
	if !flowStart(o) || !d.fromNode(o) || o.Node.PlatformSession != nil {
		return false
	}
	k, ok := dest(o)
	if ok && d.own.excluded[k] {
		return false
	}
	return o.Node.DstAsset != netobs.AssetUnresolved || (ok && d.own.endpoints[k] != "")
}

func explainOwnSessionOutsideRecord(_ *Detector, o *netobs.Observation) (string, string) {
	return "the node's own sessions: each flow tied to a session record",
		fmt.Sprintf("%s flow from the node's address %s to %s, tied to no session record", strings.ToUpper(o.IP.L4), o.IP.Src, hostPort(o.IP.Dst, o.IP.Dport))
}

// nodeAddressSpoofed: a flow start from a node address, on one of the
// node's own layer-2 segments, whose source MAC is not one of the node's.
// Its first frame is the source's, so the MAC is the sender's (C13 §4.1).
// Across a router a frame carries the router's MAC, so only the node's own
// segments are judged (§4).
func nodeAddressSpoofed(d *Detector, o *netobs.Observation) bool {
	if !flowStart(o) || !d.fromNode(o) {
		return false
	}
	onSegment := (o.L2.VLAN == nil && d.own.untagged) || (o.L2.VLAN != nil && d.own.vlans[*o.L2.VLAN])
	return onSegment && !d.own.macs[o.L2.SrcMAC]
}

func explainNodeAddressSpoofed(_ *Detector, o *netobs.Observation) (string, string) {
	seg := "untagged"
	if o.L2.VLAN != nil {
		seg = fmt.Sprintf("VLAN %d", *o.L2.VLAN)
	}
	return "the node's own addresses are sent only from the node's MACs",
		fmt.Sprintf("flow from the node's address %s sent from MAC %s on %s, to %s", o.IP.Src, o.L2.SrcMAC, seg, hostPort(o.IP.Dst, o.IP.Dport))
}

// Session is a session record of the node's own, as the node hands it over
// from its committed collection.run record (D1 in D4-72).
type Session struct {
	// Seq is the collection.run record's seq on the node's health stream.
	Seq          uint64
	InvocationID string
	AssetID      string
	Endpoint     Destination
	// Connected is the C2 result's: a session that never connected expects
	// no flow, so it is never judged.
	Connected bool
	// StartedUTC and EndedUTC are the run's window on the collector host's
	// clock.
	StartedUTC string
	EndedUTC   string
}

var (
	// ErrOrdering is a session handed over after observations it says it
	// precedes: the node's ordering fault. The detector counts it and
	// changes nothing else; the node raises the alarm.
	ErrOrdering = errors.New("netdetect: a session handed over after_seq below through")
	// ErrNotJudged is a session the detector has no room to judge
	// (MaxPendingSessions). It is counted; the node raises the alarm.
	ErrNotJudged = errors.New("netdetect: a session not judged, the pending sessions are full")
)

// tiedHorizon is how long, on the capture clock, an invocation ID tied
// with no session record taken stays known: twice the longest a run's
// flows can wait for their record, its deadline and the largest grace.
// Dropping one later is quiet, because the session it would mark seen then
// alerts, which fails loud.
const tiedHorizon = 2 * (adapter.MaxDeadlineMS*time.Millisecond + netobs.MaxTieGraceS*time.Second)

// Session takes the session record s, handed over once every observation
// to after_seq of the observation stream had committed, and returns the
// alerts it raises. A session whose flow was already seen is done; a
// connected one not seen is pending, and is judged once the detector has
// taken after_seq and its capture clock has passed the session's end plus
// tie_grace_s. Sessions are judged in the order taken, so the node hands
// them over in health-stream seq order, live and on restore. A seq at or
// below the last one taken was taken already and raises nothing. A
// malformed record is refused with an error, and its seq is taken.
func (d *Detector) Session(s Session, afterSeq uint64) ([]netobs.Alert, error) {
	if s.Seq <= d.sessionThrough {
		return nil, nil
	}
	if afterSeq < d.through {
		d.orderingFaults++
		return nil, ErrOrdering
	}
	d.sessionThrough = s.Seq
	k, err := newDestKey(s.Endpoint)
	start, err1 := time.Parse(time.RFC3339Nano, s.StartedUTC)
	end, err2 := time.Parse(time.RFC3339Nano, s.EndedUTC)
	switch {
	case !netobs.ValidUUID(s.InvocationID) || !netobs.ValidUUID(s.AssetID):
		return nil, fmt.Errorf("netdetect: session %q of asset %q", s.InvocationID, s.AssetID)
	case err != nil:
		return nil, err
	case err1 != nil || err2 != nil || end.Before(start):
		return nil, fmt.Errorf("netdetect: session window %q to %q", s.StartedUTC, s.EndedUTC)
	}
	if i := slices.IndexFunc(d.tied, func(t netobs.TiedSession) bool { return t.InvocationID == s.InvocationID }); i >= 0 {
		d.tied = slices.Delete(d.tied, i, i+1)
		return nil, nil
	}
	if !s.Connected {
		return nil, nil
	}
	if len(d.sessions) >= netobs.MaxPendingSessions {
		d.notJudged++
		return nil, ErrNotJudged
	}
	d.sessions = append(d.sessions, netobs.PendingSession{InvocationID: s.InvocationID, AssetID: s.AssetID,
		IP: k.addr.String(), L4: k.l4, Port: k.port, StartedUTC: s.StartedUTC, EndedUTC: s.EndedUTC, AfterSeq: afterSeq})
	return d.hold(d.judge(nil)), nil
}

// NotJudged counts, since this detector was built or restored, the sessions
// it couldn't judge: one past MaxPendingSessions, or one whose tied
// invocation ID was dropped past MaxTiedSessions. The node shows it in
// status and raises the alarm (D1 in D4-72).
func (d *Detector) NotJudged() int64 { return d.notJudged }

// OrderingFaults counts, since this detector was built or restored, the
// sessions refused with ErrOrdering.
func (d *Detector) OrderingFaults() int64 { return d.orderingFaults }

// DegradedDropped counts, since this detector was built or restored, the
// degraded intervals dropped past MaxDegradedIntervals. A session in a
// dropped interval may then alert, which fails loud.
func (d *Detector) DegradedDropped() int64 { return d.degradedDropped }

// NotYetSeen lists the enrolled run endpoints whose address the coverage
// record holds nothing for: the acknowledged baseline's addresses, or
// before acknowledgement the detector's own record. own-session-unseen
// never alerts for one, so status shows them (D6, D4-68).
func (d *Detector) NotYetSeen() []Endpoint {
	var out []Endpoint
	for _, e := range d.own.endpointList {
		if _, _, _, ok := d.record(e.addr); !ok {
			out = append(out, e.Endpoint)
		}
	}
	return out
}

// EndpointsNotTracked counts the enrolled endpoint addresses past
// MaxDetectorEndpoints, which the detector's own coverage record never
// holds. Before acknowledgement their sessions are never judged, so the
// node shows the count in status beside NotYetSeen (D1's C1 on #575).
func (d *Detector) EndpointsNotTracked() int { return d.own.untracked }

// track keeps the own-session state o changes: the degraded intervals, the
// endpoint record, and the sessions o's tie marks seen.
func (d *Detector) track(o *netobs.Observation) {
	if len(o.Coverage.Degraded) > 0 {
		at := o.LastUTC
		if d.degradedOpen {
			v := &d.degraded[len(d.degraded)-1]
			if mustTime(at).Before(mustTime(v.StartUTC)) {
				v.StartUTC = at
			}
			if mustTime(at).After(mustTime(v.EndUTC)) {
				v.EndUTC = at
			}
		} else {
			d.degraded = append(d.degraded, netobs.Interval{StartUTC: at, EndUTC: at})
			if len(d.degraded) > netobs.MaxDegradedIntervals {
				d.degraded = slices.Delete(d.degraded, 0, 1)
				d.degradedDropped++
			}
		}
	}
	d.degradedOpen = len(o.Coverage.Degraded) > 0
	ps := o.Node.PlatformSession
	if ps == nil && !d.degradedOpen && o.IP != nil {
		vlan := 0
		if o.L2.VLAN != nil {
			vlan = *o.L2.VLAN
		}
		for _, s := range []string{o.IP.Src, o.IP.Dst} {
			if a, ok := parseAddr(s); ok && d.own.recorded[a] {
				d.see(a, vlan, o.Citation.Frames)
			}
		}
	}
	if ps == nil {
		return
	}
	if i := slices.IndexFunc(d.sessions, func(p netobs.PendingSession) bool { return p.InvocationID == ps.InvocationID }); i >= 0 {
		d.sessions = slices.Delete(d.sessions, i, i+1)
		return
	}
	if i := slices.IndexFunc(d.tied, func(t netobs.TiedSession) bool { return t.InvocationID == ps.InvocationID }); i >= 0 {
		d.tied[i].ClockUTC = d.clockUTC
		return
	}
	d.tied = append(d.tied, netobs.TiedSession{InvocationID: ps.InvocationID, ClockUTC: d.clockUTC})
	if len(d.tied) > netobs.MaxTiedSessions {
		d.tied = slices.Delete(d.tied, 0, 1)
		d.notJudged++
	}
}

// see records that a was seen on vlan, and on the frames' PRP LANs.
func (d *Detector) see(a netip.Addr, vlan int, frames []netobs.CitedFrame) {
	e := d.seen[a]
	if e == nil {
		e = &netobs.EndpointSeen{IP: a.String(), VLANs: []int{}, LANs: []string{}}
		d.seen[a] = e
	}
	if i, found := slices.BinarySearch(e.VLANs, vlan); !found {
		if len(e.VLANs) < netobs.MaxEndpointVLANs {
			e.VLANs = slices.Insert(e.VLANs, i, vlan)
		} else {
			e.VLANsOverflow = true
		}
	}
	for _, f := range frames {
		if i, found := slices.BinarySearch(e.LANs, f.LAN); f.LAN != "" && !found {
			e.LANs = slices.Insert(e.LANs, i, f.LAN)
		}
	}
}

// record is what the coverage record holds for a: the acknowledged
// baseline's addresses, or before acknowledgement the detector's own.
func (d *Detector) record(a netip.Addr) (vlans []int, overflow bool, lans []string, ok bool) {
	if d.base == nil {
		e := d.seen[a]
		if e == nil {
			return nil, false, nil, false
		}
		return e.VLANs, e.VLANsOverflow, e.LANs, true
	}
	for _, x := range d.base.Addresses {
		if b, good := parseAddr(x.IP); good && b == a {
			vlans, lans, ok = append(vlans, x.VLANs...), append(lans, x.LANs...), true
		}
	}
	return vlans, false, lans, ok
}

// covers reports whether the coverage covers p's endpoint: no degraded
// interval meets the session's window, widened by g, and the record holds
// the address on a VLAN, and a PRP LAN, the last coverage statement says
// the sensor sees (baseline note §4). An overflowed VLAN list on either
// side counts as seen, which fails loud.
func (d *Detector) covers(p *netobs.PendingSession, g time.Duration) bool {
	from, to := mustTime(p.StartedUTC).Add(-g), mustTime(p.EndedUTC).Add(g)
	for _, v := range d.degraded {
		if !mustTime(v.EndUTC).Before(from) && !mustTime(v.StartUTC).After(to) {
			return false
		}
	}
	a, _ := parseAddr(p.IP)
	vlans, overflow, lans, ok := d.record(a)
	if !ok || d.cov == nil {
		return false
	}
	vlanOK := overflow || d.cov.VLANsOverflow
	for _, v := range vlans {
		vlanOK = vlanOK || (v == 0 && d.cov.UntaggedSeen) || (v != 0 && slices.Contains(d.cov.VLANsSeen, v))
	}
	lanOK := len(lans) == 0
	for _, l := range lans {
		lanOK = lanOK || slices.Contains(d.cov.PRP.LANsSeen, l)
	}
	return vlanOK && lanOK
}

// judge judges every pending session that is due, in the order taken, and
// appends the alerts it raises to out. It also drops the tied invocation
// IDs past tiedHorizon.
func (d *Detector) judge(out []netobs.Alert) []netobs.Alert {
	if d.clockUTC == "" {
		return out
	}
	d.tied = slices.DeleteFunc(d.tied, func(t netobs.TiedSession) bool {
		return d.clock.After(mustTime(t.ClockUTC).Add(tiedHorizon))
	})
	g := time.Duration(d.params.TieGraceS) * time.Second
	kept := d.sessions[:0]
	var due []netobs.PendingSession
	for _, p := range d.sessions {
		if d.through >= p.AfterSeq && !d.clock.Before(mustTime(p.EndedUTC).Add(g)) {
			due = append(due, p)
		} else {
			kept = append(kept, p)
		}
	}
	d.sessions = kept
	for _, p := range due {
		if !d.covers(&p, g) {
			continue
		}
		bv := "each connected session of the node's own is seen by the sensor while its coverage covers the asset"
		text := fmt.Sprintf("connected session %s to %s, %s to %s, not seen", p.InvocationID,
			strings.ToUpper(p.L4)+" "+hostPort(p.IP, &p.Port), p.StartedUTC, p.EndedUTC)
		out = d.raise(out, Key{netobs.RuleOwnSessionUnseen, p.AssetID}, d.clockUTC, bv, text, "", 0, nil, *d.cov)
	}
	return out
}
