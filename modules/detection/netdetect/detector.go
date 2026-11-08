package netdetect

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// DetectorConfig is what a Detector judges with.
type DetectorConfig struct {
	SensorID string
	// NodeID and Stream are the sensor's observation stream on this node,
	// which every observation's event ID names.
	NodeID event.NodeID
	Stream event.Stream
	// Baseline is the acknowledged network baseline's exact stored bytes,
	// or nil before any acknowledgement. Without one, only the
	// baseline-free rules run (D4-68 ruling 10).
	Baseline []byte
	// Params are the rules' parameters while there is no baseline. With
	// one, the baseline's own params are in force.
	Params netobs.BaselineParams
}

// Key is an alert's coalescing key, which is also the key the node counts
// a dropped alert under (C13 §7.3, D4-68 ruling 4): the rule and the
// destination asset, or netobs.AssetUnresolved for the one unresolved
// bucket. No port or address is in it, so traffic can't mint new keys.
type Key struct {
	Rule    netobs.Rule
	AssetID string
}

// KeyOf is a's key.
func KeyOf(a *netobs.Alert) Key { return Key{a.Rule, a.AssetID} }

// Committed is an alert record already on the sensor's alert stream, at
// its seq.
type Committed struct {
	Seq   uint64
	Alert netobs.Alert
}

// Detector raises the network alerts of one sensor's observation stream
// (baseline note §3, §4). It holds no clock of its own: its time is the
// capture time of the observations it takes, so the same observations in
// the same order give the same alerts. It leaves each alert's Capture
// empty; the node builds the capture from the cited frames and fills it
// (C13 §7.1).
//
// This version runs the five rules that judge against the baseline and
// sa-failed. The rules on the platform's own traffic come with the
// session records' call shape.
type Detector struct {
	sensor  string
	node    event.NodeID
	stream  event.Stream
	base    *netobs.Baseline
	hash    string
	version int64
	params  netobs.BaselineParams

	pairs     map[netobs.Pair]bool
	services  map[serviceKey]bool
	functions map[string]bool
	writers   map[netobs.Writer]bool
	addresses map[addrKey]bool

	through  uint64
	clock    time.Time
	clockUTC string
	windows  map[Key]*netobs.DetectorWindow

	// After a restore: the committed alerts not yet raised again, and the
	// stream's last observation seq when the restore began.
	pending    []Committed
	head       uint64
	mismatches int64
}

// serviceKey is a service without its basis: new-service asks whether the
// service was seen, by content or by port.
type serviceKey struct {
	server, l4 string
	port       int
	protocol   string
}

// NewDetector starts a detector with no open windows.
func NewDetector(cfg DetectorConfig) (*Detector, error) {
	d := &Detector{sensor: cfg.SensorID, node: cfg.NodeID, stream: cfg.Stream, params: cfg.Params, windows: map[Key]*netobs.DetectorWindow{}}
	switch {
	case !netobs.ValidUUID(cfg.SensorID):
		return nil, fmt.Errorf("netdetect: sensor %q is not a UUID", cfg.SensorID)
	case !cfg.NodeID.Valid() || !cfg.Stream.Valid():
		return nil, fmt.Errorf("netdetect: %q:%q is not an observation stream", cfg.NodeID, cfg.Stream)
	}
	if cfg.Baseline == nil {
		if err := checkParams(cfg.Params); err != nil {
			return nil, err
		}
		return d, nil
	}
	b, err := netobs.DecodeBaseline(cfg.Baseline)
	switch {
	case err != nil:
		return nil, err
	case !netobs.IsCanonical(cfg.Baseline):
		return nil, errors.New("netdetect: the baseline is not in canonical encoding")
	case b.SensorID != cfg.SensorID:
		return nil, fmt.Errorf("netdetect: the baseline is sensor %s's, not %s", b.SensorID, cfg.SensorID)
	case b.FunctionTable != Table:
		return nil, fmt.Errorf("netdetect: the baseline's function table is %s, not %s", b.FunctionTable, Table)
	}
	sum := sha256.Sum256(cfg.Baseline)
	d.base, d.hash, d.version, d.params = b, "sha256:"+hex.EncodeToString(sum[:]), b.Version, b.Params
	d.pairs, d.services, d.functions = map[netobs.Pair]bool{}, map[serviceKey]bool{}, map[string]bool{}
	d.writers, d.addresses = map[netobs.Writer]bool{}, map[addrKey]bool{}
	for _, p := range b.Pairs {
		d.pairs[p] = true
	}
	for _, s := range b.Services {
		d.services[serviceKey{s.Server, s.L4, s.Port, s.Protocol}] = true
	}
	for _, f := range b.Functions {
		d.functions[functionKey(f)] = true
	}
	for _, w := range b.AuthorizedWriters {
		d.writers[w] = true
	}
	for _, a := range b.Addresses {
		d.addresses[addrKey{a.IP, a.Endpoint}] = true
	}
	return d, nil
}

func checkParams(p netobs.BaselineParams) error {
	// The baseline's own check holds the bounds; borrow it on an empty one.
	b := netobs.Baseline{Schema: netobs.BaselineIdentifier, SensorID: "00000000-0000-4000-8000-000000000000", Version: 1,
		FunctionTable: Table, Params: p, Period: netobs.Period{StartUTC: "2026-01-01T00:00:00Z", EndUTC: "2026-01-01T00:00:00Z"}}
	if _, err := b.Encode(); err != nil {
		return fmt.Errorf("netdetect: params: %w", err)
	}
	return nil
}

// Through is the last observation-stream seq the detector has taken.
func (d *Detector) Through() uint64 { return d.through }

// Mismatches counts, since this detector was built or restored, the
// departures a restore found from the run it replays: an alert raised
// again that is not the next committed one, and a committed alert never
// raised again by the stream's head. The node raises each as an alarm. An
// alert raised again that didn't match is still returned, so it is
// committed: only an exact match is held back (D1 on the 2a/2b plan).
func (d *Detector) Mismatches() int64 { return d.mismatches }

// Observe takes the stored observation o, whose event ID is id, and returns
// the alerts it raises, in order: first the summaries of the windows its
// capture time closes, then each rule's alert. A seq at or below Through
// was taken already and raises nothing. A refused observation (not stored,
// another sensor's, or with no readable time) returns an error, raises
// nothing, and still takes its seq. An ID on another stream is refused
// and takes nothing.
func (d *Detector) Observe(id event.EventID, o *netobs.Observation) ([]netobs.Alert, error) {
	if id.NodeID != d.node || id.Stream != d.stream {
		return nil, fmt.Errorf("netdetect: %v is not on %s:%s", id, d.node, d.stream)
	}
	if id.Seq <= d.through {
		return nil, nil
	}
	d.through = id.Seq
	defer d.settle()
	switch {
	case o == nil || o.Node == nil:
		return nil, errors.New("netdetect: not a stored observation")
	case o.SensorID != d.sensor:
		return nil, fmt.Errorf("netdetect: observation of sensor %s, not %s", o.SensorID, d.sensor)
	}
	at, err := time.Parse(time.RFC3339Nano, o.FirstUTC)
	if err != nil {
		return nil, fmt.Errorf("netdetect: first_utc: %w", err)
	}
	if d.clockUTC == "" || at.After(d.clock) {
		d.clock, d.clockUTC = at, o.FirstUTC
	}
	out := d.close()
	for _, r := range rules {
		if r.base && (d.base == nil || o.Node.PlatformSession != nil) {
			continue
		}
		if o.IP == nil || !r.applies(d, o) {
			continue
		}
		bv, text := r.explain(d, o)
		out = d.hit(out, id, o, r.rule, bv, text)
	}
	return d.hold(out), nil
}

// close ends every window whose time has passed on the capture clock, and
// returns the summaries of those that had repeats, in key order.
func (d *Detector) close() []netobs.Alert {
	var ended []*netobs.DetectorWindow
	for k, w := range d.windows {
		start, _ := time.Parse(time.RFC3339Nano, w.WindowStartUTC)
		if !d.clock.Before(start.Add(time.Duration(d.params.CoalesceWindowS) * time.Second)) {
			ended = append(ended, w)
			delete(d.windows, k)
		}
	}
	slices.SortFunc(ended, compareWindow)
	var out []netobs.Alert
	for _, w := range ended {
		if w.Hits > 1 {
			out = append(out, d.alert(w))
		}
	}
	return out
}

func compareWindow(a, b *netobs.DetectorWindow) int {
	return cmp.Or(cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.AssetID, b.AssetID))
}

// hit counts one hit of rule on o's key and appends what it raises to out.
// The first hit of a window opens it and is raised at once; a later one is
// counted for the summary. With MaxDetectorWindows open, the window that
// started earliest closes first, with its summary if it had repeats (D1 in
// D4-72), so the new key still alerts at once and the state stays bounded.
func (d *Detector) hit(out []netobs.Alert, id event.EventID, o *netobs.Observation, rule netobs.Rule, bv, text string) []netobs.Alert {
	k := Key{rule, o.Node.DstAsset}
	c := cite(o, rule)
	w, ok := d.windows[k]
	if !ok {
		if len(d.windows) >= netobs.MaxDetectorWindows {
			out = d.evict(out)
		}
		w = &netobs.DetectorWindow{Rule: rule, AssetID: k.AssetID, KeyText: string(rule) + " against " + k.AssetID,
			BaselineValue: bv, Observation: text, AtUTC: o.FirstUTC, WindowStartUTC: o.FirstUTC, Hits: 1,
			Sources: []string{o.IP.Src}, Related: []uint64{id.Seq}, Cites: []netobs.Cite{c}, Coverage: o.Coverage}
		d.windows[k] = w
		return append(out, d.alert(w))
	}
	// A summary shows the latest hit's text and coverage, and the latest
	// capture time among the hits, which is never before the window's start.
	w.Hits++
	w.BaselineValue, w.Observation, w.Coverage = bv, text, o.Coverage
	if mustTime(o.FirstUTC).After(mustTime(w.AtUTC)) {
		w.AtUTC = o.FirstUTC
	}
	if i, found := slices.BinarySearch(w.Sources, o.IP.Src); !found && len(w.Sources) < netobs.MaxRelated {
		w.Sources = slices.Insert(w.Sources, i, o.IP.Src)
	}
	if len(w.Related) < netobs.MaxRelated {
		w.Related = append(w.Related, id.Seq)
	}
	if len(w.Cites) < netobs.MaxAlertFlows {
		w.Cites = append(w.Cites, c)
	}
	return out
}

// evict closes the open window that started earliest, ties going by rule
// and then asset, and appends its summary if it had repeats.
func (d *Detector) evict(out []netobs.Alert) []netobs.Alert {
	var first *netobs.DetectorWindow
	for _, w := range d.windows {
		if first == nil {
			first = w
			continue
		}
		if c := mustTime(w.WindowStartUTC).Compare(mustTime(first.WindowStartUTC)); c < 0 || (c == 0 && compareWindow(w, first) < 0) {
			first = w
		}
	}
	delete(d.windows, Key{first.Rule, first.AssetID})
	if first.Hits > 1 {
		out = append(out, d.alert(first))
	}
	return out
}

func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// alert is the alert w gives now.
func (d *Detector) alert(w *netobs.DetectorWindow) netobs.Alert {
	var params []netobs.Param
	for _, name := range netobs.RuleParams(w.Rule) {
		if name == "tie_grace_s" {
			params = append(params, netobs.Param{Name: name, Value: strconv.FormatInt(d.params.TieGraceS, 10)})
		}
	}
	k := netobs.DetectorCheckpoint{NodeID: d.node, Stream: d.stream, Baseline: d.hash, BaselineVersion: d.version}
	a := w.Alert(&k, params)
	a.Cites = slices.Clone(a.Cites)
	a.Coverage = cloneCoverage(a.Coverage)
	return a
}

func cloneCoverage(c netobs.Coverage) netobs.Coverage {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	var out netobs.Coverage
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// cite is o's citation as an alert shows it: the first two cited frames,
// or for sa-failed the request and the error, its first and last (C13 §7.1).
func cite(o *netobs.Observation, rule netobs.Rule) netobs.Cite {
	fs := o.Citation.Frames
	pick := fs[:min(len(fs), netobs.MaxAlertFramesPerFlow)]
	if rule == netobs.RuleSAFailed && len(fs) > 1 {
		pick = []netobs.CitedFrame{fs[0], fs[len(fs)-1]}
	}
	c := netobs.Cite{CaptureID: o.Citation.CaptureID}
	for _, f := range pick {
		c.Frames = append(c.Frames, netobs.CiteFrame{N: f.N, SHA256: f.SHA256})
	}
	return c
}

// hold drops from out each alert a restore finds already committed. The
// committed alerts after the checkpoint are a prefix of what the replay
// raises, in order, so each alert raised again is compared with the next
// committed one: an exact match is held back; anything else is returned,
// and the committed one it stood against is passed over, as one mismatch.
func (d *Detector) hold(out []netobs.Alert) []netobs.Alert {
	kept := out[:0]
	for _, a := range out {
		if len(d.pending) == 0 {
			kept = append(kept, a)
			continue
		}
		next := d.pending[0]
		d.pending = d.pending[1:]
		if !same(&a, &next.Alert) {
			d.mismatches++
			kept = append(kept, a)
		}
	}
	return kept
}

// same reports whether a, raised again, is the committed c byte for byte
// as a health body, but for the capture the node filled in.
func same(a, c *netobs.Alert) bool {
	x := *a
	x.Capture = c.Capture
	hx, err1 := x.Health()
	hc, err2 := c.Health()
	if err1 != nil || err2 != nil {
		return false
	}
	bx, _ := json.Marshal(hx)
	bc, _ := json.Marshal(hc)
	return bytes.Equal(bx, bc)
}

// settle ends a restore's matching once the detector has taken the
// stream's head as of the restore: every committed alert came from an
// observation at or below it, so one still waiting was never raised again.
func (d *Detector) settle() {
	if len(d.pending) > 0 && d.through >= d.head {
		d.mismatches += int64(len(d.pending))
		d.pending = nil
	}
}

// Checkpoint returns the detector's otsec.netcheckpoint/0.1 document.
// lastAlertSeq is the last seq on the alert stream the node has committed;
// every alert Observe returned before this call must be committed by then.
// While a restore still has committed alerts waiting, the checkpoint names
// the seq before the first of them, so a second restore reads them again.
func (d *Detector) Checkpoint(lastAlertSeq uint64) ([]byte, error) {
	if len(d.pending) > 0 {
		lastAlertSeq = d.pending[0].Seq - 1
	}
	k := netobs.DetectorCheckpoint{Schema: netobs.CheckpointIdentifier, Half: netobs.HalfDetector, SensorID: d.sensor,
		NodeID: d.node, Stream: d.stream, Baseline: d.hash, BaselineVersion: d.version, Through: d.through, LastAlertSeq: lastAlertSeq, ClockUTC: d.clockUTC,
		Windows: []netobs.DetectorWindow{}}
	for _, w := range d.windows {
		k.Windows = append(k.Windows, *w)
	}
	slices.SortFunc(k.Windows, func(a, b netobs.DetectorWindow) int { return compareWindow(&a, &b) })
	return k.Encode()
}

// RestoreDetector resumes a detector from its checkpoint (baseline note
// §3). committed are the alert records on the sensor's alert stream after
// the checkpoint's last_alert_seq, in seq order. head is the observation
// stream's last seq when the restore begins. The node then reads the
// observations after Through again: an alert raised again that is exactly
// a committed one is held back, so a restore gives the alert records of an
// uninterrupted run. It goes by seq, not time, so a backward clock step
// between the commits changes nothing.
func RestoreDetector(cfg DetectorConfig, checkpoint []byte, committed []Committed, head uint64) (*Detector, error) {
	k, err := netobs.DecodeDetectorCheckpoint(checkpoint)
	if err != nil {
		return nil, err
	}
	d, err := NewDetector(cfg)
	if err != nil {
		return nil, err
	}
	switch {
	case k.SensorID != d.sensor:
		return nil, fmt.Errorf("netdetect: the checkpoint is sensor %s's, not %s", k.SensorID, d.sensor)
	case k.NodeID != d.node || k.Stream != d.stream:
		return nil, fmt.Errorf("netdetect: the checkpoint read %s:%s, not %s:%s", k.NodeID, k.Stream, d.node, d.stream)
	case k.Baseline != d.hash:
		return nil, fmt.Errorf("netdetect: the checkpoint judged against %q, not %q", k.Baseline, d.hash)
	}
	last := k.LastAlertSeq
	for _, c := range committed {
		if c.Seq <= last {
			return nil, fmt.Errorf("netdetect: committed alert seq %d is not after %d", c.Seq, last)
		}
		last = c.Seq
	}
	d.through, d.clockUTC = k.Through, k.ClockUTC
	if k.ClockUTC != "" {
		d.clock = mustTime(k.ClockUTC)
	}
	for i := range k.Windows {
		w := k.Windows[i]
		d.windows[Key{w.Rule, w.AssetID}] = &w
	}
	if again, err := d.Checkpoint(k.LastAlertSeq); err != nil || !bytes.Equal(again, checkpoint) {
		return nil, errors.New("netdetect: the checkpoint does not restore to itself")
	}
	d.pending, d.head = slices.Clone(committed), head
	d.settle()
	return d, nil
}
