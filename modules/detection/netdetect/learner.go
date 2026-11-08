package netdetect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"

	"otsec.local/otsec/contracts/netobs"
)

// LearnerConfig is one learning run's configuration (baseline note §2.2).
type LearnerConfig struct {
	SensorID string
	// Version is the version the draft records: n + 1 over the last.
	Version int64
	// StartUTC is when the operator started learning.
	StartUTC string
	Params   netobs.BaselineParams
}

// ErrFrozen is returned by Observe after Freeze: a frozen draft folds
// nothing more (baseline note §2.2).
var ErrFrozen = errors.New("netdetect: the draft is frozen")

// Learner folds stored C13 observations into a draft network baseline
// (baseline note §2.1). It is deterministic: the same observations in the
// same stream order give the same draft bytes, however the node batches
// them between checkpoints.
//
// The draft never exceeds netobs.MaxBaselineBytes. Room is reserved for the
// period at its largest, so counting never pushes a draft over. Once an
// entry doesn't fit, it is refused, the entries already held are kept,
// and the observation counts once in period.overflow (D4-71).
type Learner struct {
	cfg     LearnerConfig
	through uint64
	frozen  bool
	endUTC  string
	period  netobs.Period

	pairs     map[netobs.Pair]bool
	services  map[netobs.BaselineService]bool
	functions map[string]netobs.BaselineFunction // keyed by its encoding
	addresses map[addrKey]*netobs.Address
	// held are the TCP starts whose pair waits for its flow to show it was
	// not only a dial (§2.2, D1 in D4-71), keyed by flow.
	held map[flowKey]netobs.Pair

	// reserve is the encoded document with every list empty and the
	// period at its largest; lists[i] is list i's item count and bytes.
	reserve int
	lists   [4]listSize
	addrLen map[addrKey]int
}

type addrKey struct{ ip, endpoint string }

// flowKey is a TCP flow as its client sent it: the client's address and
// port, and the server's address and port.
type flowKey struct {
	src   string
	sport int
	dst   string
	dport int
}

type listSize struct{ n, bytes int }

// cost is what the list's encoding grows by when it takes an item of n
// bytes: the item, and a comma unless it is the first.
func (s listSize) cost(n int) int {
	if s.n == 0 {
		return n
	}
	return n + 1
}

const (
	listPairs = iota
	listServices
	listFunctions
	listAddresses
)

// worstEndUTC is the longest end time C13 accepts, for the reserve.
const worstEndUTC = "9999-12-31T23:59:59.999999999Z"

// NewLearner starts a learning run with an empty draft.
func NewLearner(cfg LearnerConfig) (*Learner, error) {
	l := &Learner{cfg: cfg, endUTC: cfg.StartUTC,
		pairs: map[netobs.Pair]bool{}, services: map[netobs.BaselineService]bool{},
		functions: map[string]netobs.BaselineFunction{}, addresses: map[addrKey]*netobs.Address{}, addrLen: map[addrKey]int{},
		held: map[flowKey]netobs.Pair{}}
	worst := l.document()
	worst.Period = netobs.Period{StartUTC: cfg.StartUTC, EndUTC: worstEndUTC,
		Observations: netobs.Counts{Flow: math.MaxInt64, Service: math.MaxInt64, Function: math.MaxInt64, Insecure: math.MaxInt64,
			Encrypted: math.MaxInt64, Identity: math.MaxInt64, Undecoded: math.MaxInt64},
		Degraded: math.MaxInt64, PlatformSession: math.MaxInt64, Overflow: netobs.MaxOverflow}
	b, err := worst.Encode()
	if err != nil {
		return nil, fmt.Errorf("netdetect: learner configuration: %w", err)
	}
	l.reserve = len(b)
	l.period = netobs.Period{StartUTC: cfg.StartUTC, EndUTC: cfg.StartUTC}
	return l, nil
}

// Through is the last observation-stream seq the learner has taken.
func (l *Learner) Through() uint64 { return l.through }

// Frozen reports whether learning has ended.
func (l *Learner) Frozen() bool { return l.frozen }

// Observe folds the stored observation o at stream seq seq. A seq at or
// below Through was taken already and is passed over, so a re-read after a
// restore folds nothing twice. A refused observation (not stored, or
// another sensor's) returns an error, folds nothing, and still takes its
// seq. An observation tied to the node's own
// session, or seen while the coverage was degraded, is counted and not
// learned (§2.1). It returns ErrFrozen after Freeze.
func (l *Learner) Observe(seq uint64, o *netobs.Observation) error {
	switch {
	case l.frozen:
		return ErrFrozen
	case seq <= l.through:
		return nil
	}
	// The seq is taken even when the observation is refused, so the
	// node's cursor can move past it and the stream still prunes (D5-S1
	// on #561). A refused observation is reported, not folded.
	l.through = seq
	switch {
	case o == nil || o.Node == nil:
		return errors.New("netdetect: not a stored observation")
	case o.SensorID != l.cfg.SensorID:
		return fmt.Errorf("netdetect: observation of sensor %s, not %s", o.SensorID, l.cfg.SensorID)
	}
	switch {
	case o.Node.PlatformSession != nil:
		l.period.PlatformSession++
		return nil
	case len(o.Coverage.Degraded) != 0:
		l.period.Degraded++
		return nil
	}
	l.count(o.Kind)
	if o.IP == nil {
		return nil
	}
	src := endpoint(o.Node.SrcAsset, o.IP.Src)
	dst := endpoint(o.Node.DstAsset, o.IP.Dst)
	vlan := 0
	if o.L2.VLAN != nil {
		vlan = *o.L2.VLAN
	}
	var lans []string
	for _, f := range o.Citation.Frames {
		if f.LAN != "" {
			lans = append(lans, f.LAN)
		}
	}
	slices.Sort(lans)
	lans = slices.Compact(lans)
	fits := l.address(o.IP.Src, src, vlan, lans)
	fits = l.address(o.IP.Dst, dst, vlan, lans) && fits
	// An entry is learned only when both addresses it was seen at are
	// held, so every end of every entry has its address in the draft
	// (D3's S1 on #561; the acknowledgement view relies on it, D4-70).
	//
	// Each kind's IP header is oriented by C13, not by the flow: a
	// service's server is ip.dst (C13 §4.3), and a function is a request,
	// so its ip.src is the client and ip.dst the server, on a midstream
	// flow too (C13 §4.3, §14 item 14). So the pair below is the client's
	// to the server's port for both. A flow's own src is its first frame's
	// sender only when midstream (C13 §4.1), and a midstream flow learns
	// no pair.
	if fits && (o.IP.L4 == "tcp" || o.IP.L4 == "udp") && o.IP.Dport != nil {
		pair := netobs.Pair{Client: src, Server: dst, L4: o.IP.L4, Port: *o.IP.Dport, Protocol: o.Protocol}
		var key flowKey
		if o.IP.Sport != nil {
			key = flowKey{o.IP.Src, *o.IP.Sport, o.IP.Dst, *o.IP.Dport}
		}
		switch {
		// A pair is learned from a client-server start only once its flow
		// shows it was not only a dial: an end with syn_only false, or a
		// decoded function, whichever comes first. Until then the start
		// is held (§2.2, D1 in D4-71). Midstream flows add nothing: a pair
		// is never guessed (§2.1).
		case o.Kind == netobs.KindFlow && o.Flow != nil && o.Flow.Phase == "start" && o.Direction == netobs.DirectionClientServer:
			if !l.pairs[pair] {
				fits = l.hold(key, pair) && fits
			}
		case o.Kind == netobs.KindFlow && o.Flow != nil && o.Flow.Phase == "end":
			if p, ok := l.held[key]; ok {
				delete(l.held, key)
				if o.Flow.SynOnly != nil && !*o.Flow.SynOnly {
					fits = l.pair(p) && fits
				}
			}
		case o.Kind == netobs.KindService && o.Service != nil:
			fits = l.service(netobs.BaselineService{Server: dst, L4: pair.L4, Port: pair.Port, Protocol: pair.Protocol, Basis: o.Service.Basis}) && fits
		case o.Kind == netobs.KindFunction && o.Function != nil:
			if p, ok := l.held[key]; ok {
				delete(l.held, key)
				fits = l.pair(p) && fits
			}
			fits = l.function(functionOf(pair, o.Function)) && fits
		}
	}
	if !fits && l.period.Overflow < netobs.MaxOverflow {
		l.period.Overflow++
	}
	return nil
}

func endpoint(asset, ip string) string {
	if asset != netobs.AssetUnresolved {
		return asset
	}
	return "addr:" + ip
}

func (l *Learner) count(k netobs.Kind) {
	c := &l.period.Observations
	switch k {
	case netobs.KindFlow:
		c.Flow++
	case netobs.KindService:
		c.Service++
	case netobs.KindFunction:
		c.Function++
	case netobs.KindInsecure:
		c.Insecure++
	case netobs.KindEncrypted:
		c.Encrypted++
	case netobs.KindIdentity:
		c.Identity++
	case netobs.KindUndecoded:
		c.Undecoded++
	}
}

// size is the draft's largest encoded size: the reserve and every list's
// items.
func (l *Learner) size() int {
	n := l.reserve
	for _, s := range l.lists {
		n += s.bytes
	}
	return n
}

// take adds an item of n bytes to list i if the draft still fits.
func (l *Learner) take(i, n int) bool {
	c := l.lists[i].cost(n)
	if l.size()+c > netobs.MaxBaselineBytes {
		return false
	}
	l.lists[i].n++
	l.lists[i].bytes += c
	return true
}

func encodedLen(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // the entry types always encode
	}
	return len(b)
}

func (l *Learner) pair(p netobs.Pair) bool {
	if l.pairs[p] {
		return true
	}
	if !l.take(listPairs, encodedLen(p)) {
		return false
	}
	l.pairs[p] = true
	return true
}

// hold holds a start's pair until its flow proves it. A start with no
// source port has no flow to prove it, and isn't held. One that can't be
// held, with MaxHeldStarts held already, is refused and counts in overflow.
func (l *Learner) hold(k flowKey, p netobs.Pair) bool {
	if k == (flowKey{}) {
		return true
	}
	if _, ok := l.held[k]; !ok && len(l.held) >= netobs.MaxHeldStarts {
		return false
	}
	l.held[k] = p
	return true
}

func (l *Learner) service(s netobs.BaselineService) bool {
	if l.services[s] {
		return true
	}
	if !l.take(listServices, encodedLen(s)) {
		return false
	}
	l.services[s] = true
	return true
}

// functionOf is f's entry on pair as the baseline keeps it: objects sorted,
// without duplicates.
func functionOf(pair netobs.Pair, f *netobs.Function) netobs.BaselineFunction {
	objects := slices.Clone(f.Objects)
	slices.Sort(objects)
	return netobs.BaselineFunction{Pair: pair, Code: f.Code, Sub: f.Sub, Objects: slices.Compact(objects)}
}

func functionKey(f netobs.BaselineFunction) string {
	if f.Objects == nil {
		f.Objects = []string{}
	}
	b, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (l *Learner) function(f netobs.BaselineFunction) bool {
	if f.Sub != nil {
		v := *f.Sub
		f.Sub = &v
	}
	k := functionKey(f)
	if _, ok := l.functions[k]; ok {
		return true
	}
	if !l.take(listFunctions, len(k)) {
		return false
	}
	l.functions[k] = f
	return true
}

func addressLen(a *netobs.Address) int {
	e := *a
	if e.VLANs == nil {
		e.VLANs = []int{}
	}
	if e.LANs == nil {
		e.LANs = []string{}
	}
	return encodedLen(e)
}

// address adds ip's address entry for endpoint, or the VLAN and LANs it
// lacks. Growing an entry is refused like a new one when the draft is full;
// the entry is then left as it was.
func (l *Learner) address(ip, ep string, vlan int, lans []string) bool {
	k := addrKey{ip, ep}
	a, ok := l.addresses[k]
	if !ok {
		n := &netobs.Address{IP: ip, Endpoint: ep, VLANs: []int{vlan}, LANs: slices.Clone(lans)}
		ln := addressLen(n)
		if !l.take(listAddresses, ln) {
			return false
		}
		l.addresses[k], l.addrLen[k] = n, ln
		return true
	}
	grown := &netobs.Address{IP: ip, Endpoint: ep, VLANs: a.VLANs, LANs: a.LANs}
	if !slices.Contains(grown.VLANs, vlan) {
		grown.VLANs = append(slices.Clone(grown.VLANs), vlan)
		slices.Sort(grown.VLANs)
	}
	for _, x := range lans {
		if !slices.Contains(grown.LANs, x) {
			grown.LANs = append(slices.Clone(grown.LANs), x)
			slices.Sort(grown.LANs)
		}
	}
	ln := addressLen(grown)
	if ln == l.addrLen[k] {
		return true
	}
	d := ln - l.addrLen[k]
	if l.size()+d > netobs.MaxBaselineBytes {
		return false
	}
	l.lists[listAddresses].bytes += d
	l.addresses[k], l.addrLen[k] = grown, ln
	return true
}

// document is the draft as a Baseline, its lists sorted.
func (l *Learner) document() *netobs.Baseline {
	b := &netobs.Baseline{Schema: netobs.BaselineIdentifier, SensorID: l.cfg.SensorID, Version: l.cfg.Version,
		FunctionTable: Table, Period: l.period, Params: l.cfg.Params}
	b.Period.EndUTC = l.endUTC
	for p := range l.pairs {
		b.Pairs = append(b.Pairs, p)
	}
	for s := range l.services {
		b.Services = append(b.Services, s)
	}
	for _, f := range l.functions {
		b.Functions = append(b.Functions, f)
	}
	for _, a := range l.addresses {
		b.Addresses = append(b.Addresses, *a)
	}
	netobs.SortBaseline(b)
	return b
}

// Draft returns the draft in C13 §8's canonical encoding. Until Freeze, its
// end_utc is its start_utc.
func (l *Learner) Draft() ([]byte, error) {
	return l.document().Encode()
}

// Freeze ends learning at endUTC and returns the frozen draft, which the
// node records as baseline.network. Freezing again at the same time
// returns the same bytes.
func (l *Learner) Freeze(endUTC string) ([]byte, error) {
	if l.frozen && endUTC != l.endUTC {
		return nil, fmt.Errorf("netdetect: frozen at %s already", l.endUTC)
	}
	prev := l.endUTC
	l.endUTC = endUTC
	b, err := l.Draft()
	if err != nil {
		l.endUTC = prev
		return nil, err
	}
	// A start still unproven at the period's end is not learned (D1 in
	// D4-71): its session alerts once if it reconnects after
	// acknowledgement.
	l.frozen = true
	clear(l.held)
	return b, nil
}

// Checkpoint returns the learner's otsec.netcheckpoint/0.1 document.
func (l *Learner) Checkpoint() ([]byte, error) {
	d, err := l.Draft()
	if err != nil {
		return nil, err
	}
	k := netobs.LearnerCheckpoint{Schema: netobs.CheckpointIdentifier, Half: netobs.HalfLearner, SensorID: l.cfg.SensorID,
		Through: l.through, Frozen: l.frozen, Draft: d}
	for f, p := range l.held {
		k.Held = append(k.Held, netobs.HeldStart{Src: f.src, Sport: f.sport, Dst: f.dst, Pair: p})
	}
	slices.SortFunc(k.Held, netobs.CompareHeldStart)
	return k.Encode()
}

// RestoreLearner resumes a learning run from its checkpoint. The checkpoint
// must belong to cfg's run: the same sensor, version, start and parameters,
// and this package's function table. Restored, the learner continues
// exactly as the run it was taken from.
func RestoreLearner(cfg LearnerConfig, checkpoint []byte) (*Learner, error) {
	k, err := netobs.DecodeLearnerCheckpoint(checkpoint)
	if err != nil {
		return nil, err
	}
	b, err := netobs.DecodeBaseline(k.Draft)
	if err != nil {
		return nil, err
	}
	switch {
	case b.SensorID != cfg.SensorID || b.Version != cfg.Version || b.Period.StartUTC != cfg.StartUTC || b.Params != cfg.Params:
		return nil, errors.New("netdetect: the checkpoint is of another learning run")
	case b.FunctionTable != Table:
		return nil, fmt.Errorf("netdetect: the checkpoint's function table is %s, not %s", b.FunctionTable, Table)
	case !k.Frozen && b.Period.EndUTC != b.Period.StartUTC:
		return nil, errors.New("netdetect: an unfrozen draft ends at its start")
	}
	l, err := NewLearner(cfg)
	if err != nil {
		return nil, err
	}
	l.through, l.frozen, l.period, l.endUTC = k.Through, k.Frozen, b.Period, b.Period.EndUTC
	for _, p := range b.Pairs {
		l.pairs[p] = true
		l.lists[listPairs].bytes += l.lists[listPairs].cost(encodedLen(p))
		l.lists[listPairs].n++
	}
	for _, s := range b.Services {
		l.services[s] = true
		l.lists[listServices].bytes += l.lists[listServices].cost(encodedLen(s))
		l.lists[listServices].n++
	}
	for _, f := range b.Functions {
		key := functionKey(f)
		l.functions[key] = f
		l.lists[listFunctions].bytes += l.lists[listFunctions].cost(len(key))
		l.lists[listFunctions].n++
	}
	for i := range b.Addresses {
		a := b.Addresses[i]
		k := addrKey{a.IP, a.Endpoint}
		ln := addressLen(&a)
		l.addresses[k], l.addrLen[k] = &a, ln
		l.lists[listAddresses].bytes += l.lists[listAddresses].cost(ln)
		l.lists[listAddresses].n++
	}
	for _, h := range k.Held {
		l.held[flowKey{h.Src, h.Sport, h.Dst, h.Pair.Port}] = h.Pair
	}
	if again, err := l.Checkpoint(); err != nil || !bytes.Equal(again, checkpoint) {
		return nil, errors.New("netdetect: the checkpoint does not restore to itself")
	}
	return l, nil
}
