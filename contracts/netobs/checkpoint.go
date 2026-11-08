package netobs

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/internal/strictjson"
)

// CheckpointIdentifier is the schema of both network checkpoints, the
// learner's and the detector's, its first field (C13 §8).
const CheckpointIdentifier = "otsec.netcheckpoint/0.1"

// The checkpoint halves. Each is its own C5 series (C13 §8): the learner's
// in netcheckpoint.learner, the detector's in netcheckpoint.detector.
const (
	HalfLearner  = "learner"
	HalfDetector = "detector"
)

// MaxHeldStarts bounds the TCP starts a learner holds until its flow shows
// it was not only a dial (baseline note §2.2, D1 in D4-71). A start that
// can't be held counts in period.overflow.
const MaxHeldStarts = 512

// MaxHeldStartBytes bounds one held start as encoded, with its comma
// (TestWorstHeldStartFits).
const MaxHeldStartBytes = 384

// MaxDetectorWindows bounds the open coalescing windows a detector holds
// (C13 §7.3, D1 in D4-72). When it is full, a new key still alerts at once,
// and the window that started earliest closes early with its summary.
const MaxDetectorWindows = 96

// MaxDetectorWindowBytes bounds one open window as encoded, with its comma
// (TestWorstDetectorWindowFits).
const MaxDetectorWindowBytes = 12 << 10

// The own-session state's bounds (D1 in D4-72). Past MaxPendingSessions
// pending sessions or MaxTiedSessions tied invocation IDs, the extra
// session is counted as not judged and the node raises the alarm. Past
// MaxDegradedIntervals the oldest interval is dropped, never merged. Past
// MaxDetectorEndpoints the extra endpoints are never recorded, so they show
// as not yet seen. Past MaxTakenSessions the oldest taken ID is dropped.
// A taken entry is a tied entry's size. Each Max*Bytes bounds one entry as encoded, with its
// comma (TestWorstDetectorCheckpointFits).
const (
	MaxPendingSessions       = 128
	MaxPendingSessionBytes   = 512
	MaxTiedSessions          = 256
	MaxTiedSessionBytes      = 128
	MaxTakenSessions         = 128
	MaxDetectorEndpoints     = 256
	MaxDetectorEndpointBytes = 192
	MaxEndpointVLANs         = 8
	MaxDegradedIntervals     = 64
	MaxDegradedIntervalBytes = 128
)

// MaxDetectorCheckpointBytes bounds a detector checkpoint: the sum of its
// parts at their worst (its windows, pending sessions, tied and taken
// invocation IDs, endpoint record, degraded intervals and coverage
// statement) and an envelope of under 1 KiB, 1,354,752 bytes. It is
// strictly below the configuration record cap less its headroom
// (1,507,328), with 152,576 bytes (10.1%) to spare, so a checkpoint that fits is never refused there
// (C13 §14 item 17).
const MaxDetectorCheckpointBytes = MaxDetectorWindows*MaxDetectorWindowBytes +
	MaxPendingSessions*MaxPendingSessionBytes + (MaxTiedSessions+MaxTakenSessions)*MaxTiedSessionBytes +
	MaxDetectorEndpoints*MaxDetectorEndpointBytes + MaxDegradedIntervals*MaxDegradedIntervalBytes +
	MaxCoverageBytes + 1<<10

// MaxLearnerCheckpointBytes bounds a learner checkpoint: its draft, at
// most MaxBaselineBytes, its held starts, and an envelope of under 1 KiB.
const MaxLearnerCheckpointBytes = MaxBaselineBytes + MaxHeldStarts*MaxHeldStartBytes + 1<<10

// HeldStart is a TCP client-server flow start whose pair the learner has
// not learned yet: its flow (the client's address and port, and the
// server's address with the pair's port) and the pair it would learn.
type HeldStart struct {
	Src   string `json:"src"`
	Sport int    `json:"sport"`
	Dst   string `json:"dst"`
	Pair  Pair   `json:"pair"`
}

// CompareHeldStart orders held starts by flow: src, sport, dst, then the
// server port.
func CompareHeldStart(a, b HeldStart) int {
	return cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Sport, b.Sport), cmp.Compare(a.Dst, b.Dst), cmp.Compare(a.Pair.Port, b.Pair.Port))
}

// LearnerCheckpoint is the learner's checkpoint (C13 §8, baseline note
// §2.2). The learner's whole state is its draft, so restoring is decoding
// the draft and folding on after Through.
type LearnerCheckpoint struct {
	Schema   string `json:"schema"`
	Half     string `json:"half"`
	SensorID string `json:"sensor_id"`
	// Through is the last observation-stream seq the learner folded or
	// passed over. It folds nothing at or below it, so a re-read after a
	// restore folds each observation once.
	Through uint64 `json:"through"`
	// Frozen says learning has ended: the draft is final and the learner
	// folds nothing more.
	Frozen bool `json:"frozen"`
	// Draft is the draft baseline in C13 §8's canonical encoding, with no
	// authorized writers. Until it is frozen, its end_utc is its start_utc.
	Draft json.RawMessage `json:"draft"`
	// Held are the starts held unproven, sorted by flow, one per flow, at
	// most MaxHeldStarts, and none once frozen: a start unproven at the
	// period's end is not learned.
	Held []HeldStart `json:"held"`
}

// Validate checks the checkpoint: its schema and half, its sensor, and a
// draft that is a canonical baseline of the same sensor with no writers.
func (k *LearnerCheckpoint) Validate() error {
	c := &checker{}
	if k.Schema != CheckpointIdentifier {
		c.fail(CodeSchema, "schema", "%q is not %s", k.Schema, CheckpointIdentifier)
	}
	if k.Half != HalfLearner {
		c.fail(CodeForm, "half", "%q is not %s", k.Half, HalfLearner)
	}
	c.uuid("sensor_id", k.SensorID)
	b, err := DecodeBaseline(k.Draft)
	switch {
	case err != nil:
		c.fail(CodeForm, "draft", "not a network baseline: %v", err)
	case !IsCanonical(k.Draft):
		c.fail(CodeForm, "draft", "not in canonical encoding")
	case b.SensorID != k.SensorID:
		c.fail(CodeConflict, "draft.sensor_id", "%s, not the checkpoint's %s", b.SensorID, k.SensorID)
	case len(b.AuthorizedWriters) != 0:
		c.fail(CodeForm, "draft.authorized_writers", "a draft has none; a person adds them")
	}
	switch {
	case len(k.Held) > MaxHeldStarts:
		c.fail(CodeRange, "held", "%d starts, above %d", len(k.Held), MaxHeldStarts)
	case k.Frozen && len(k.Held) != 0:
		c.fail(CodeConflict, "held", "a frozen draft holds no starts")
	}
	for i := range k.Held {
		h := &k.Held[i]
		f := fmt.Sprintf("held[%d]", i)
		c.addr(f+".src", h.Src)
		c.addr(f+".dst", h.Dst)
		if h.Sport < 0 || h.Sport > 65535 {
			c.fail(CodeRange, f+".sport", "%d not in [0, 65535]", h.Sport)
		}
		h.Pair.check(c, f+".pair")
		if h.Pair.L4 != "tcp" {
			c.fail(CodeForm, f+".pair.l4", "%q: only a TCP start is held", h.Pair.L4)
		}
		if i > 0 && CompareHeldStart(k.Held[i-1], *h) >= 0 {
			c.fail(CodeOrder, "held", "sorted by flow, one per flow")
		}
	}
	return c.err()
}

// Encode validates k and encodes it.
func (k *LearnerCheckpoint) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	e := *k
	if e.Held == nil {
		e.Held = []HeldStart{}
	}
	out, err := json.Marshal(&e)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxLearnerCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(out), MaxLearnerCheckpointBytes)}
	}
	return out, nil
}

// DecodeLearnerCheckpoint decodes a learner checkpoint strictly and
// validates it. The draft is kept as its exact bytes.
func DecodeLearnerCheckpoint(b []byte) (*LearnerCheckpoint, error) {
	if len(b) > MaxLearnerCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxLearnerCheckpointBytes)}
	}
	var k LearnerCheckpoint
	if err := strictjson.Decode(b, &k); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "checkpoint", Detail: err.Error()}
	}
	k.Draft = bytes.Clone(k.Draft)
	return &k, k.Validate()
}

// DetectorCheckpoint is the detector's checkpoint (C13 §8, baseline note
// §3): the baseline it judges against, the last observation it took, the
// capture clock, the open coalescing windows, and the last alert seq it
// knew of. A restore replays the observations after Through from this
// state, and the alerts committed after LastAlertSeq tell it which of the
// alerts it raises again were committed already.
type DetectorCheckpoint struct {
	Schema   string `json:"schema"`
	Half     string `json:"half"`
	SensorID string `json:"sensor_id"`
	// NodeID and Stream are the observation stream the detector reads. A
	// window's related observations are seqs on it.
	NodeID event.NodeID `json:"node_id"`
	Stream event.Stream `json:"stream"`
	// Baseline and BaselineVersion name the acknowledged baseline the
	// detector judges against: its hash and version, or "" and 0 before any
	// acknowledgement.
	Baseline        string `json:"baseline"`
	BaselineVersion int64  `json:"baseline_version"`
	// Through is the last observation-stream seq the detector took.
	Through uint64 `json:"through"`
	// LastAlertSeq is the last seq on the sensor's alert stream that the
	// detector knew to be committed.
	LastAlertSeq uint64 `json:"last_alert_seq"`
	// ClockUTC is the capture clock: the latest first_utc taken, or "" when
	// none has been.
	ClockUTC string `json:"clock_utc"`
	// Windows are the open coalescing windows, sorted by rule and then
	// asset, one per key, at most MaxDetectorWindows (C13 §7.3).
	Windows []DetectorWindow `json:"windows"`
	// Coverage is the coverage statement of the last observation taken, or
	// null when none has been. own-session-unseen judges against it.
	Coverage *Coverage `json:"coverage"`
	// SessionThrough is the health-stream seq of the last session record
	// taken, or 0.
	SessionThrough uint64 `json:"session_through"`
	// Sessions are the connected sessions taken and not yet judged, in the
	// order taken.
	Sessions []PendingSession `json:"sessions"`
	// Tied are the invocation IDs that observations were tied to and whose
	// session record has not been taken yet, in the order first tied.
	Tied []TiedSession `json:"tied"`
	// Taken are the invocation IDs of sessions handed over and done with,
	// oldest first, so a later record tied to one takes no room in Tied
	// (D6's F1 on #575).
	Taken []TiedSession `json:"taken"`
	// Endpoints are the enrolled run endpoints' addresses seen in
	// observations neither tied nor degraded, sorted by address: the
	// coverage record before acknowledgement (D1 in D4-72).
	Endpoints []EndpointSeen `json:"endpoints"`
	// Degraded are the capture-time intervals of runs of observations whose
	// coverage was degraded, oldest first. DegradedOpen says the last
	// observation taken was degraded, so the next degraded one extends the
	// last interval.
	Degraded     []Interval `json:"degraded"`
	DegradedOpen bool       `json:"degraded_open"`
}

// PendingSession is a connected session of the node's own whose flow has
// not been seen yet (baseline note §5): its run's invocation ID, asset and
// endpoint, its window on the collector host's clock, and the observation
// seq it was handed over after.
type PendingSession struct {
	InvocationID string `json:"invocation_id"`
	AssetID      string `json:"asset_id"`
	IP           string `json:"ip"`
	L4           string `json:"l4"`
	Port         int    `json:"port"`
	StartedUTC   string `json:"started_utc"`
	EndedUTC     string `json:"ended_utc"`
	AfterSeq     uint64 `json:"after_seq"`
}

// TiedSession is an invocation ID observations were tied to, and the
// capture clock when one last was.
type TiedSession struct {
	InvocationID string `json:"invocation_id"`
	ClockUTC     string `json:"clock_utc"`
}

// EndpointSeen is an enrolled run endpoint's address and the VLANs (0 for
// untagged) and PRP LANs it was seen on, at most MaxEndpointVLANs VLANs;
// VLANsOverflow says there were more.
type EndpointSeen struct {
	IP            string   `json:"ip"`
	VLANs         []int    `json:"vlans"`
	VLANsOverflow bool     `json:"vlans_overflow"`
	LANs          []string `json:"lans"`
}

// Interval is a capture-time interval, both ends inclusive.
type Interval struct {
	StartUTC string `json:"start_utc"`
	EndUTC   string `json:"end_utc"`
}

// DetectorWindow is one open coalescing window: what its summary alert
// would carry so far, and the distinct source addresses it has counted.
// Its first alert was raised when it opened.
type DetectorWindow struct {
	Rule           Rule   `json:"rule"`
	AssetID        string `json:"asset_id"`
	KeyText        string `json:"key_text"`
	BaselineValue  string `json:"baseline_value"`
	Observation    string `json:"observation"`
	AtUTC          string `json:"at_utc"`
	WindowStartUTC string `json:"window_start_utc"`
	Hits           int64  `json:"hits"`
	// Sources are the distinct source addresses counted, sorted, at most
	// MaxRelated; past that the count stops (baseline note §8).
	Sources []string `json:"sources"`
	// Related are the seqs, on the checkpoint's observation stream, of the
	// first min(hits, MaxRelated) hits, in order.
	Related  []uint64 `json:"related"`
	Cites    []Cite   `json:"cites"`
	Coverage Coverage `json:"coverage"`
}

// Alert is the summary alert w would give now, without its capture, under
// the baseline k names and with the rule's params.
func (w *DetectorWindow) Alert(k *DetectorCheckpoint, params []Param) Alert {
	related := make([]event.EventID, len(w.Related))
	for i, seq := range w.Related {
		related[i] = event.EventID{NodeID: k.NodeID, Stream: k.Stream, Seq: seq}
	}
	total := w.Hits
	if w.Rule == RuleOwnSessionUnseen {
		total = 0 // it names a session record, no traffic
	}
	return Alert{Schema: Identifier, Rule: w.Rule, AssetID: w.AssetID, Baseline: k.Baseline, BaselineVersion: k.BaselineVersion,
		KeyText: w.KeyText, Params: params, BaselineValue: w.BaselineValue, Observation: w.Observation, Clock: ClockCapture,
		AtUTC: w.AtUTC, WindowStartUTC: w.WindowStartUTC, Hits: w.Hits, Sources: int64(len(w.Sources)),
		Related: related, RelatedTotal: total, Cites: w.Cites, Coverage: w.Coverage}
}

// Validate checks the checkpoint: its schema, half and sensor, the baseline
// named or not, the clock, and every window as the alert it would give.
func (k *DetectorCheckpoint) Validate() error {
	c := &checker{}
	if k.Schema != CheckpointIdentifier {
		c.fail(CodeSchema, "schema", "%q is not %s", k.Schema, CheckpointIdentifier)
	}
	if k.Half != HalfDetector {
		c.fail(CodeForm, "half", "%q is not %s", k.Half, HalfDetector)
	}
	c.uuid("sensor_id", k.SensorID)
	if !k.NodeID.Valid() {
		c.fail(CodeForm, "node_id", "%q is not a node ID", k.NodeID)
	}
	if !k.Stream.Valid() {
		c.fail(CodeForm, "stream", "%q is not a stream", k.Stream)
	}
	if len(k.Windows) > MaxDetectorWindows {
		c.fail(CodeRange, "windows", "%d open, above %d", len(k.Windows), MaxDetectorWindows)
	}
	switch {
	case k.Baseline == "" && k.BaselineVersion != 0:
		c.fail(CodeConflict, "baseline_version", "a version with no baseline")
	case k.Baseline != "" && !baselineHashForm.MatchString(k.Baseline):
		c.fail(CodeForm, "baseline", "%q is not sha256:<hex>", k.Baseline)
	case k.Baseline != "" && k.BaselineVersion < 1:
		c.fail(CodeRange, "baseline_version", "%d is below 1", k.BaselineVersion)
	}
	if k.ClockUTC == "" && len(k.Windows) != 0 {
		c.fail(CodeConflict, "clock_utc", "windows open with no clock")
	}
	if k.ClockUTC != "" {
		c.utc("clock_utc", k.ClockUTC)
	}
	for i := range k.Windows {
		w := &k.Windows[i]
		f := fmt.Sprintf("windows[%d]", i)
		if i > 0 {
			p := &k.Windows[i-1]
			if p.Rule > w.Rule || (p.Rule == w.Rule && p.AssetID >= w.AssetID) {
				c.fail(CodeOrder, f, "windows sorted by rule and asset, one per key")
			}
		}
		var params []Param
		for _, name := range ruleParams[w.Rule] {
			params = append(params, Param{Name: name, Value: "1"}) // the values are the detector's
		}
		a := w.Alert(k, params)
		if w.Rule != RuleOwnSessionUnseen {
			a.Capture = fmt.Sprintf("%064x", 0)
		}
		if err := a.Validate(); err != nil {
			c.fail(CodeForm, f, "%v", err)
		}
		if w.Rule == RuleOwnSessionUnseen {
			continue
		}
		if n := min(w.Hits, MaxRelated); int64(len(w.Related)) != n {
			c.fail(CodeConflict, f+".related", "%d seqs for %d hits", len(w.Related), w.Hits)
		}
		for j, seq := range w.Related {
			if seq == 0 || seq > k.Through || (j > 0 && w.Related[j-1] >= seq) {
				c.fail(CodeOrder, f+".related", "seqs rising, from 1 to through %d", k.Through)
				break
			}
		}
		for j, s := range w.Sources {
			c.addr(fmt.Sprintf("%s.sources[%d]", f, j), s)
			if j > 0 && w.Sources[j-1] >= s {
				c.fail(CodeOrder, f+".sources", "sorted, without duplicates")
			}
		}
		if len(w.Sources) > MaxRelated {
			c.fail(CodeRange, f+".sources", "%d, above %d", len(w.Sources), MaxRelated)
		}
	}
	k.validateOwn(c)
	return c.err()
}

// validateOwn checks the own-session state.
func (k *DetectorCheckpoint) validateOwn(c *checker) {
	if k.Coverage != nil {
		k.Coverage.check(c, "coverage")
	}
	// With no clock, only sessions handed over before any observation may
	// be held, pending: the rest comes from observations (D1 on #590).
	if k.ClockUTC == "" && (k.Coverage != nil || len(k.Tied)+len(k.Taken)+len(k.Endpoints)+len(k.Degraded) != 0 || k.DegradedOpen) {
		c.fail(CodeConflict, "clock_utc", "own-session state with no clock")
	}
	if k.DegradedOpen && len(k.Degraded) == 0 {
		c.fail(CodeConflict, "degraded_open", "no interval to extend")
	}
	bound := func(f string, n, most, each int, v any) {
		if n > most {
			c.fail(CodeRange, f, "%d, above %d", n, most)
		}
		if b, err := json.Marshal(v); err != nil || len(b)+1 > each {
			c.fail(CodeRange, f, "%d bytes encoded with its comma, above %d", len(b)+1, each)
		}
	}
	ids := map[string]bool{}
	for i, p := range k.Sessions {
		f := fmt.Sprintf("sessions[%d]", i)
		bound("sessions", len(k.Sessions), MaxPendingSessions, MaxPendingSessionBytes, p)
		c.uuid(f+".invocation_id", p.InvocationID)
		c.uuid(f+".asset_id", p.AssetID)
		if ids[p.InvocationID] {
			c.fail(CodeConflict, f+".invocation_id", "pending twice")
		}
		ids[p.InvocationID] = true
		c.addr(f+".ip", p.IP)
		if (p.L4 != "tcp" && p.L4 != "udp") || p.Port < 1 || p.Port > 65535 {
			c.fail(CodeForm, f, "%s %d is not a transport and port", p.L4, p.Port)
		}
		s, ok1 := c.utc(f+".started_utc", p.StartedUTC)
		e, ok2 := c.utc(f+".ended_utc", p.EndedUTC)
		if ok1 && ok2 && e.Before(s) {
			c.fail(CodeOrder, f+".ended_utc", "before started_utc")
		}
		if i > 0 && p.AfterSeq < k.Sessions[i-1].AfterSeq {
			c.fail(CodeOrder, f+".after_seq", "sessions in the order taken, after_seq not falling")
		}
		if k.SessionThrough == 0 {
			c.fail(CodeConflict, "session_through", "sessions pending, none taken")
		}
	}
	for i, t := range k.Tied {
		f := fmt.Sprintf("tied[%d]", i)
		bound("tied", len(k.Tied), MaxTiedSessions, MaxTiedSessionBytes, t)
		c.uuid(f+".invocation_id", t.InvocationID)
		c.utc(f+".clock_utc", t.ClockUTC)
		if ids[t.InvocationID] {
			c.fail(CodeConflict, f+".invocation_id", "both pending and tied")
		}
		ids[t.InvocationID] = true
	}
	for i, t := range k.Taken {
		f := fmt.Sprintf("taken[%d]", i)
		bound("taken", len(k.Taken), MaxTakenSessions, MaxTiedSessionBytes, t)
		c.uuid(f+".invocation_id", t.InvocationID)
		c.utc(f+".clock_utc", t.ClockUTC)
		if ids[t.InvocationID] {
			c.fail(CodeConflict, f+".invocation_id", "taken and also pending, tied or taken")
		}
		ids[t.InvocationID] = true
	}
	for i, e := range k.Endpoints {
		f := fmt.Sprintf("endpoints[%d]", i)
		bound("endpoints", len(k.Endpoints), MaxDetectorEndpoints, MaxDetectorEndpointBytes, e)
		c.addr(f+".ip", e.IP)
		if i > 0 && k.Endpoints[i-1].IP >= e.IP {
			c.fail(CodeOrder, f, "sorted by address, without duplicates")
		}
		if len(e.VLANs) == 0 || len(e.VLANs) > MaxEndpointVLANs || (e.VLANsOverflow && len(e.VLANs) != MaxEndpointVLANs) {
			c.fail(CodeRange, f+".vlans", "%d VLANs, from 1 to %d, all %d when overflowed", len(e.VLANs), MaxEndpointVLANs, MaxEndpointVLANs)
		}
		for j, v := range e.VLANs {
			if v < 0 || v > 4094 || (j > 0 && e.VLANs[j-1] >= v) {
				c.fail(CodeOrder, f+".vlans", "0 to 4094, ascending")
				break
			}
		}
		if !slices.Equal(e.LANs, []string{}) && !slices.Equal(e.LANs, []string{"a"}) && !slices.Equal(e.LANs, []string{"b"}) && !slices.Equal(e.LANs, []string{"a", "b"}) {
			c.fail(CodeForm, f+".lans", "%q is not a sorted set of a and b", e.LANs)
		}
	}
	for i, v := range k.Degraded {
		f := fmt.Sprintf("degraded[%d]", i)
		bound("degraded", len(k.Degraded), MaxDegradedIntervals, MaxDegradedIntervalBytes, v)
		s, ok1 := c.utc(f+".start_utc", v.StartUTC)
		e, ok2 := c.utc(f+".end_utc", v.EndUTC)
		if ok1 && ok2 && e.Before(s) {
			c.fail(CodeOrder, f+".end_utc", "before start_utc")
		}
	}
}

// Encode validates k and encodes it.
func (k *DetectorCheckpoint) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	e := *k
	if e.Windows == nil {
		e.Windows = []DetectorWindow{}
	}
	if e.Sessions == nil {
		e.Sessions = []PendingSession{}
	}
	if e.Tied == nil {
		e.Tied = []TiedSession{}
	}
	if e.Taken == nil {
		e.Taken = []TiedSession{}
	}
	if e.Endpoints == nil {
		e.Endpoints = []EndpointSeen{}
	}
	if e.Degraded == nil {
		e.Degraded = []Interval{}
	}
	out, err := json.Marshal(&e)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxDetectorCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(out), MaxDetectorCheckpointBytes)}
	}
	return out, nil
}

// DecodeDetectorCheckpoint decodes a detector checkpoint strictly and
// validates it.
func DecodeDetectorCheckpoint(b []byte) (*DetectorCheckpoint, error) {
	if len(b) > MaxDetectorCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxDetectorCheckpointBytes)}
	}
	var k DetectorCheckpoint
	if err := strictjson.Decode(b, &k); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "checkpoint", Detail: err.Error()}
	}
	return &k, k.Validate()
}
