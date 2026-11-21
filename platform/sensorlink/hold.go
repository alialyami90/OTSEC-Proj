package sensorlink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// The intake hold (D4-72, baseline note section 5, D5-c5-0.9.md section 8).
// The node sets an observation's platform_session tie when it commits it,
// but a run's local_addr and connected_at reach the node only with the
// run's result. So the link holds every observation between a node address
// and the endpoint of a run the node has dispatched, until the run's result
// ties it or a deadline passes, and then commits it, tied or untied. Every
// exit commits: the hold delays an alert, never suppresses one (AP-35).
//
// The four parts of section 5:
//   - (a) the connection tie: a 0.9 result that is connected ties the flow
//     with the session's exact 5-tuple whose start falls in
//     [started_at - g, ended_at + g], so a flow the sensor first sees
//     midstream still ties (D1 on #576). Of overlapping runs to one
//     endpoint, a new flow goes to the newest;
//   - (b) the window tie: a 0.8 result that is connected, with no
//     local_addr, ties the first established flow that starts in
//     [started_at - g, ended_at + g];
//   - (c) the failed dial: a TCP flow to the endpoint from another client
//     port, or of a run that did not connect, that starts in the run's
//     window and ends syn_only takes the window tie. One that has not ended
//     at the result waits for its end, and gives way, untied, at its
//     deadline, on a new sensor run or on degraded coverage;
//   - (d) a tied flow still open is kept in the open table by its key, and
//     its later records tie to the same session until its end. A start on
//     the key never ties through the table: the sensor saw the old flow
//     end, so the entry leaves and the start is judged as a new flow. An
//     entry expires at its latest record + flow_idle_s + g, and a new
//     sensor run clears the table (D1 on #576).
//
// g is HoldConfig.TieGrace. The hold's state is saved through
// HoldConfig.Save before each change takes effect (C5's
// netcheckpoint.intake); a save that fails commits the record untied and is
// counted.

// The hold's bounds (D3's I1, D1 in D4-72).
const (
	// HoldFlowCap is the distinct flows a run holds: one per dial attempt,
	// the collector's connect_retries ceiling plus one. A new flow past it
	// commits untied at once and never evicts a held one.
	HoldFlowCap = adapter.MaxConnectRetries + 1
	// HoldRecordCap is the records a run holds, so its saved record stays
	// under the configuration record cap (1.5 MiB / 64 KiB, less one for
	// the envelope). A record past it releases the run's whole hold
	// untied, itself included.
	HoldRecordCap = 23
	// HoldOpenCap is the open table's keys. Past it the oldest gives way:
	// its later records commit untied.
	HoldOpenCap = 64
	// HoldRunLimit is the longest a run can take, as the node can't see
	// the collector's own limits: C2's deadline ceiling.
	HoldRunLimit = adapter.MaxDeadlineMS * time.Millisecond
	// HoldDialLimit is C2's connect timeout ceiling, the longest a failed
	// dial runs before the sensor sees no more of it.
	HoldDialLimit = adapter.MaxConnectTimeoutMS * time.Millisecond
	// HoldLateEntries bounds the late index (part (e)): past it the oldest
	// entry gives way, counted. HoldLateHorizon is an entry's horizon after
	// its session's end, on the node's wall clock: MaxFlowIdleS, plus
	// backlog_tie_s at its ceiling, plus g, plus room for the engine's own
	// pipeline (section 1.6; E-D4-03 unmeasured).
	HoldLateEntries = 1024
	HoldLateHorizon = 15 * time.Minute
	// AlarmLateIndexShort is raised once a stretch when an entry is evicted
	// inside its horizon (section 1.6).
	AlarmLateIndexShort = "sensor-late-index-short"
)

// Ties (C13 node.platform_session.tie).
const (
	TieConnection = "connection"
	TieWindow     = "window"
)

// HoldRun is a run the node dispatched: the hold watches its endpoint from
// Dispatch until Result, Abandon or its deadline.
type HoldRun struct {
	RequestID string         `json:"request_id"`
	AssetID   string         `json:"asset_id"`
	Endpoint  netip.AddrPort `json:"endpoint"`
	L4        string         `json:"l4"`
	// Deadline is when the hold gives way untied, in node wall time:
	// dispatch plus HoldRunLimit plus g.
	Deadline time.Time `json:"deadline_utc"`
}

// Session is what the run's result says about its one connection
// (C2 SessionFacts and Result times).
type Session struct {
	InvocationID string    `json:"invocation_id"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at"`
	Connected    bool      `json:"connected"`
	// Local and ConnectedAt are set by a 0.9 result that connected; a 0.8
	// result has neither.
	Local       netip.AddrPort `json:"local_addr,omitzero"`
	ConnectedAt time.Time      `json:"connected_at,omitzero"`
}

// FlowKey is a flow seen from the node: the node's end, the endpoint's end
// and the transport. An observation in either direction has the same key.
type FlowKey struct {
	Node netip.AddrPort `json:"node"`
	Peer netip.AddrPort `json:"peer"`
	L4   string         `json:"l4"`
}

// HeldRecord is one held observation: the stored form without a tie, its
// capture, and the received time of its arrival.
type HeldRecord struct {
	RunID       string          `json:"run_id"`
	Seq         uint64          `json:"seq"`
	Observation json.RawMessage `json:"observation"`
	Capture     *c5.Capture     `json:"capture,omitempty"`
	Received    event.Received  `json:"received"`
}

// HeldFlow is a held flow and what its records showed.
type HeldFlow struct {
	Key     FlowKey      `json:"key"`
	Start   time.Time    `json:"start_utc"` // the first record's first_utc
	Records []HeldRecord `json:"records"`
	Ended   bool         `json:"ended,omitempty"`
	SynOnly bool         `json:"syn_only,omitempty"`
	// Other: the flow carried a record other than its start and end, so
	// it was more than a dial.
	Other bool `json:"other,omitempty"`
	// EndLost: a new sensor run or degraded coverage came after its start,
	// so an end may never come.
	EndLost bool `json:"end_lost,omitempty"`
	// Wait is set once the run's result left the flow waiting for its end
	// as a failed dial: it gives way untied then (part (c)).
	Wait time.Time `json:"wait_utc,omitzero"`
	// FlowIdle is the sensor's flow_idle_s from the flow's first record.
	FlowIdle int64 `json:"flow_idle_s"`
	// Arrival is the node's wall time when its first record arrived, and
	// Last when its latest did.
	Arrival time.Time `json:"arrival_utc"`
	Last    time.Time `json:"last_utc"`
}

// OpenFlow is a tied flow not yet ended (part (d)).
type OpenFlow struct {
	Key          FlowKey `json:"key"`
	InvocationID string  `json:"invocation_id"`
	Tie          string  `json:"tie"`
	AssetID      string  `json:"asset_id"`
	// Expires is its latest record's arrival + flow_idle_s + g, in node
	// wall time: the sensor ends an idle flow by then, so a record after it
	// can't be the same flow (D1 on #576). FlowIdle is the flow's
	// flow_idle_s, for the clamp.
	Expires  time.Time `json:"expires_utc"`
	FlowIdle int64     `json:"flow_idle_s"`
	// Off is the node's offset (wall less monotonic) when the entry was
	// made, and Live that it was made since the node's start: in memory
	// only, so an entry restored at a start ties nothing on the 0.2 path
	// (section 1.5, the rule on the two clocks).
	Off  int64 `json:"-"`
	Live bool  `json:"-"`
}

// HoldRecordState is a saved run record's state.
const (
	HoldHolding   = "holding"   // the run has no result yet
	HoldWaiting   = "waiting"   // the result came; failed dials wait for their end
	HoldReleasing = "releasing" // Releasing is being committed
	HoldReleased  = "released"  // nothing held
)

// RunRecord is the hold's saved state for one run, with the open table:
// what the node writes as a netcheckpoint.intake document. Releasing holds
// the records a release commits, with their ties, and Head the stream's
// last seq before that batch, so a restart can tell whether it committed.
type RunRecord struct {
	State     string     `json:"state"`
	Run       HoldRun    `json:"run"`
	Session   *Session   `json:"session,omitempty"`
	Flows     []HeldFlow `json:"flows"`
	Releasing []Release  `json:"releasing,omitempty"`
	Head      uint64     `json:"head,omitempty"`
	// AfterSeq is the observation stream's head once the release
	// committed: the seq the run's session follows (D1's (A)).
	AfterSeq uint64 `json:"after_seq,omitempty"`
	// WindowTaken: a 0.8 result's window tie went to a flow already.
	WindowTaken bool `json:"window_taken,omitempty"`
	// OpenFlow is the release's Released.OpenFlow, kept so the node's start
	// repair writes what the live path would (D4's F1 on #584).
	OpenFlow bool       `json:"open_flow,omitempty"`
	Open     []OpenFlow `json:"open"`
}

// Release is a released record and its tie, if any.
type Release struct {
	Record HeldRecord              `json:"record"`
	Tie    *netobs.PlatformSession `json:"tie,omitempty"`
	Asset  string                  `json:"asset_id,omitempty"`
	// Skewed: released untied because no tie was made for skew, so the
	// record carries node.skewed (CH-41).
	Skewed bool `json:"skewed,omitempty"`
}

// HoldConfig configures the hold. With no NodeAddrs the link holds nothing.
type HoldConfig struct {
	NodeAddrs []netip.Addr
	TieGrace  time.Duration
	// Now is the node's wall clock, which runs the deadlines.
	Now func() time.Time
	// Save writes rec before the change takes effect (the node's
	// netcheckpoint.intake). A nil Save keeps the hold in memory only.
	Save func(ctx context.Context, rec RunRecord) error
	// Restore is the saved records to start from: the newest of each run
	// still holding, waiting or releasing, then the newest record of all,
	// whose Open table is taken.
	Restore []RunRecord
}

// HoldStats are the hold's counts since the link was made.
type HoldStats struct {
	Held               int    `json:"held"` // records held now
	Runs               int    `json:"runs"` // runs holding or waiting
	Open               int    `json:"open"`
	Tied               uint64 `json:"tied"`
	PastFlowCap        uint64 `json:"past_flow_cap"`
	RecordCapReleases  uint64 `json:"record_cap_releases"`
	DeadlineReleases   uint64 `json:"deadline_releases"`
	OpenEvicted        uint64 `json:"open_evicted"`
	OpenSuperseded     uint64 `json:"open_superseded"` // a start on an open key
	OpenExpired        uint64 `json:"open_expired"`
	CheckpointFailures uint64 `json:"checkpoint_failures"`
	// HeadUnread counts releases not begun because the stream's head, or
	// on the 0.2 path its saved position, could not be read: the run stays
	// as it was, and a deadline or the next TickHold tries again (D4's
	// condition (i) on #676; D6's N3 on #742).
	HeadUnread uint64 `json:"head_unread"`
	// The late index (part (e)): its entries now; the flows it tied; and
	// late_untied by reason, a record that matched an entry past its
	// horizon, and an entry evicted by the bound.
	Late        int    `json:"late_entries"`
	LateTied    uint64 `json:"late_tied"`
	LateHorizon uint64 `json:"late_untied_horizon"`
	LateEvicted uint64 `json:"late_untied_evicted"`
}

// stamps are the stored-time half of the rule on the two clocks for a
// run's window (section 1.5), in memory only: live, the run was dispatched
// since the node's start; the node's offset and wall time at Dispatch, and
// its offset at Result once one came.
type stamps struct {
	live     bool
	dispOff  int64
	dispWall time.Time
	resOff   int64
	resulted bool
}

// holdRun is a run in memory.
type holdRun struct {
	rec   RunRecord
	order int // dispatch order, for the open table's last record
	stamps
	// skewed: the run's window was refused for skew (CH-41). onset: the
	// onset refused it and counted it once (skewOnset), so none of the
	// run's ties is made, or counted, after.
	skewed, onset bool
}

// hold is the link's hold state. The link's cmu guards it.
type hold struct {
	cfg   HoldConfig
	addrs map[netip.Addr]bool
	runs  map[string]*holdRun
	n     int
	open  []OpenFlow // oldest first
	// pending is the open entries of the release being built: they join
	// the table only with its releasing record (release).
	pending     []OpenFlow
	pendingTied uint64
	// repoint is a result's re-point of an open entry (Result), staged as
	// pending is; repointed says whether the last release applied it.
	repoint   *OpenFlow
	repointed bool
	last      *RunRecord // the newest record saved, which carries the open table
	stats     HoldStats
	// phase is the release in progress, for result's deferred clean-up.
	phase *releasePhase
	// lastStart is the node's monotonic time when it last took a flow start
	// of the sensor run, and started whether one was taken since the link
	// was made: an open entry past its bound expires only once a start is
	// taken at or after the bound (CH-57; D4-102 item 5 (c)). The start is
	// placed on the wall clock at each check, from the monotonic time since
	// it, so a step of the wall clock after it cannot move it past a bound
	// (D4's N1 and D6's N4 on #732). Its wall time is kept too, and the
	// earlier of the two placements counts, so a forward step cannot carry
	// it past a bound either (D6's N5 on #732). It is not saved, so after a
	// restart an entry past its bound waits for the next start taken after
	// it.
	lastStart     time.Duration
	lastStartWall time.Time
	started       bool
	mono          func() time.Duration
	// off is the link's offNow, so an open entry's offset is taken on the
	// clock it is compared with (D6's N5 on #748).
	off func() int64
	// skewed is the runs not held because no tie was made for skew at
	// their Dispatch, which their Result reports.
	skewed map[string]bool
	// late is the late index (part (e)), oldest first: memory only, empty
	// at each start. lateShort: sensor-late-index-short was raised in this
	// stretch.
	late      []lateEntry
	lateShort bool
}

// lateEntry is a session released with no flow tied (part (e)): its run,
// its session, and the stored-time half of its window.
type lateEntry struct {
	run HoldRun
	s   Session
	stamps
}

// releasePhase is how far a release has gone, for result's deferred
// clean-up after a recovered panic (D3's B3 and N1, D1's ruling on #676).
type releasePhase struct {
	prev   []OpenFlow // the open table before the staged changes
	staged bool       // the open table holds the staged changes
	saved  bool       // the releasing record is saved
	taken  bool       // the batch's receipts are taken: its records are in the store
	after  uint64     // the receipts' largest seq, or the head before the batch
	finish func()     // the end state, as when the record after the batch is not saved
	// resave writes the run's holding record again, with the open table
	// rolled back, over a releasing record saved before a panic.
	resave func()
}

func newHold(cfg HoldConfig) (*hold, error) {
	h := &hold{cfg: cfg, addrs: map[netip.Addr]bool{}, runs: map[string]*holdRun{}, skewed: map[string]bool{}}
	for _, a := range cfg.NodeAddrs {
		h.addrs[a.Unmap().WithZone("")] = true
	}
	if len(h.addrs) > 0 && (cfg.Now == nil || cfg.TieGrace <= 0) {
		return nil, errors.New("sensorlink: a hold needs Now and a tie grace")
	}
	for i := range cfg.Restore {
		r := cfg.Restore[i]
		if r.State != HoldReleased {
			h.n++
			h.runs[r.Run.RequestID] = &holdRun{rec: r, order: h.n}
		}
	}
	if n := len(cfg.Restore); n > 0 {
		last := cfg.Restore[n-1]
		h.open = slices.Clone(last.Open)
		h.last = &last
	}
	return h, nil
}

// on reports whether the hold watches anything at all.
func (h *hold) on() bool { return len(h.addrs) > 0 }

// keyOf is o's flow key and the run whose endpoint it reaches, if o runs
// between a node address and an endpoint the hold watches, in either
// direction.
func (h *hold) keyOf(o *netobs.Observation) (FlowKey, bool) {
	if o.IP == nil || o.IP.Sport == nil || o.IP.Dport == nil {
		return FlowKey{}, false
	}
	src, err1 := netip.ParseAddr(o.IP.Src)
	dst, err2 := netip.ParseAddr(o.IP.Dst)
	if err1 != nil || err2 != nil {
		return FlowKey{}, false
	}
	s := netip.AddrPortFrom(src.Unmap().WithZone(""), uint16(*o.IP.Sport))
	d := netip.AddrPortFrom(dst.Unmap().WithZone(""), uint16(*o.IP.Dport))
	switch {
	case h.addrs[s.Addr()]:
		return FlowKey{Node: s, Peer: d, L4: o.IP.L4}, true
	case h.addrs[d.Addr()]:
		return FlowKey{Node: d, Peer: s, L4: o.IP.L4}, true
	}
	return FlowKey{}, false
}

// grace is g.
func (h *hold) grace() time.Duration { return h.cfg.TieGrace }

// now is the node's wall time.
func (h *hold) now() time.Time { return h.cfg.Now().UTC() }

// save writes rec and makes it the newest.
func (h *hold) save(ctx context.Context, rec RunRecord) error {
	rec.Open = slices.Clone(h.open)
	if rec.Open == nil {
		rec.Open = []OpenFlow{}
	}
	if rec.Flows == nil {
		rec.Flows = []HeldFlow{}
	}
	if h.cfg.Save != nil {
		if err := h.cfg.Save(ctx, rec); err != nil {
			h.stats.CheckpointFailures++
			return err
		}
	}
	h.last = &rec
	return nil
}

// openIndex is the open table's entry for k, or -1.
func (h *hold) openIndex(k FlowKey) int {
	return slices.IndexFunc(h.open, func(o OpenFlow) bool { return o.Key == k })
}

// flowStart is a record's first_utc.
func flowStart(o *netobs.Observation) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, o.FirstUTC)
	return t.UTC()
}

func isStart(o *netobs.Observation) bool {
	return o.Kind == netobs.KindFlow && o.Flow != nil && o.Flow.Phase == "start"
}

func isEnd(o *netobs.Observation) bool {
	return o.Kind == netobs.KindFlow && o.Flow != nil && o.Flow.Phase == "end"
}

func degraded(c netobs.Coverage) bool { return len(c.Degraded) > 0 }

// in reports whether t is in [from, to].
func in(t, from, to time.Time) bool { return !t.Before(from) && !t.After(to) }

// errHoldMissing: a release named a run the hold does not have.
var errHoldMissing = errors.New("sensorlink: no such run held")

// String names a key in counts and errors.
func (k FlowKey) String() string { return fmt.Sprintf("%s %s-%s", k.L4, k.Node, k.Peer) }

// statsNow is the counts with the hold's current size.
func (h *hold) statsNow() HoldStats {
	s := h.stats
	s.Runs, s.Open, s.Late = len(h.runs), len(h.open), len(h.late)
	for _, r := range h.runs {
		for _, f := range r.rec.Flows {
			s.Held += len(f.Records)
		}
	}
	return s
}

// runFor is the run k's records go to: a holding run whose endpoint k
// reaches, or a waiting run that holds k.
func (h *hold) runFor(k FlowKey) *holdRun {
	var out *holdRun
	for _, r := range h.runs {
		if slices.ContainsFunc(r.rec.Flows, func(f HeldFlow) bool { return f.Key == k }) {
			return r // the run already holding the flow
		}
		// Otherwise the newest run to the endpoint with no result yet. This
		// approximates D1's rule on #576, that of overlapping sessions the
		// latest connected_at not after the flow's start + g wins: the
		// node can't know connected_at until the result, and every holding
		// run was dispatched before the flow arrived.
		if r.rec.State == HoldHolding && r.rec.Run.Endpoint == k.Peer && r.rec.Run.L4 == k.L4 && (out == nil || r.order > out.order) {
			out = r
		}
	}
	return out
}

// sorted is the runs in dispatch order.
func (h *hold) sorted() []*holdRun {
	out := make([]*holdRun, 0, len(h.runs))
	for _, r := range h.runs {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *holdRun) int { return a.order - b.order })
	return out
}

// addOpen adds a tied flow to the open table; past HoldOpenCap the oldest
// gives way, counted.
func (h *hold) addOpen(o OpenFlow) (evicted uint64) {
	if i := h.openIndex(o.Key); i >= 0 {
		h.open = slices.Delete(h.open, i, i+1)
	}
	h.open = append(h.open, o)
	if len(h.open) > HoldOpenCap {
		h.open = slices.Delete(h.open, 0, len(h.open)-HoldOpenCap)
		evicted++
	}
	return evicted
}

// expires is of's expiry, never later than now + its flow_idle_s + g, so
// a backward clock step can't stretch it.
func (h *hold) expires(of OpenFlow, now time.Time) time.Time {
	if lim := now.Add(time.Duration(of.FlowIdle)*time.Second + h.grace()); of.Expires.After(lim) {
		return lim
	}
	return of.Expires
}

// expired reports whether of has expired at now: past its bound, and a
// flow start taken at or after the bound (CH-57). The start counts only
// when both its wall time and its monotonic placement are at or after the
// bound, so a step of the wall clock either way after it cannot carry it
// past the bound.
func (h *hold) expired(of OpenFlow, now time.Time) bool {
	end := h.expires(of, now)
	if now.Before(end) || !h.started {
		return false
	}
	return !h.lastStartWall.Before(end) && !now.Add(h.lastStart-h.mono()).Before(end)
}

// expireOpen removes the open entries that have expired, counted, and
// writes the table if it changed.
func (h *hold) expireOpen(ctx context.Context) {
	now, n := h.now(), len(h.open)
	open := make([]OpenFlow, 0, n)
	for _, of := range h.open {
		expired := h.expired(of, now)
		of.Expires = h.expires(of, now)
		if !expired {
			open = append(open, of)
		}
	}
	h.open = open
	if len(open) < n {
		h.stats.OpenExpired += uint64(n - len(open))
		if h.last != nil {
			_ = h.save(ctx, *h.last) // counted on failure
		}
	}
}

// cloneRec copies a record deeply enough to change its flows.
func cloneRec(r RunRecord) RunRecord {
	r.Flows = slices.Clone(r.Flows)
	for i := range r.Flows {
		r.Flows[i].Records = slices.Clone(r.Flows[i].Records)
	}
	return r
}

func heldCount(r RunRecord) (n int) {
	for _, f := range r.Flows {
		n += len(f.Records)
	}
	return n
}

// note updates what f's records showed with st.
func note(f *HeldFlow, st *netobs.Observation) {
	switch {
	case isEnd(st):
		f.Ended = true
		f.SynOnly = st.Flow.SynOnly != nil && *st.Flow.SynOnly
	case !isStart(st):
		f.Other = true
	}
}

// Dispatch starts holding run's endpoint. The run's deadline is now plus
// HoldRunLimit plus g. The record is saved first; if that fails nothing is
// held for the run, and its flows commit untied. It is a scheduler call: it
// waits at most HoldLockWait for the link's lock, and a panic in it is
// recovered; either returns ErrHoldTimeout, and nothing is held.
func (l *Link) Dispatch(ctx context.Context, run HoldRun) error {
	return l.schedCall(&l.stats.DispatchTimeouts, func() error {
		h := l.hold
		if !h.on() {
			return nil
		}
		if c := l.standing(); c != "" {
			// No tie is made for skew: nothing is held, and the run's window
			// is refused, counted and reported by its Result (section 1.5).
			l.countRefusal(c)
			h.skewed[run.RequestID] = true
			return nil
		}
		run.Endpoint = netip.AddrPortFrom(run.Endpoint.Addr().Unmap().WithZone(""), run.Endpoint.Port())
		run.Deadline = h.now().Add(HoldRunLimit + h.grace())
		rec := RunRecord{State: HoldHolding, Run: run}
		if err := h.save(ctx, rec); err != nil {
			return fmt.Errorf("sensorlink: the hold for run %s was not saved, so its flows commit untied: %w", run.RequestID, err)
		}
		h.n++
		h.runs[run.RequestID] = &holdRun{rec: *h.last, order: h.n, stamps: stamps{live: true, dispOff: l.offNow(), dispWall: l.now()}}
		return nil
	})
}

// Released is what a run's result did.
type Released struct {
	// AfterSeq is the observation stream's head once the run's flows
	// committed: the seq the run's session follows.
	AfterSeq uint64
	// OpenFlow: the session's 5-tuple was a flow still open in the table,
	// which an earlier session began (an SNMPv3 run that reuses its
	// conversation). Its entry now ties to this run's invocation (D1 on
	// #576); the node writes open_flow on collection.run.
	OpenFlow bool
	// Skewed: the run's window was refused for skew, so its collection.run
	// is marked skewed (CH-41).
	Skewed bool
}

// Result ties the run's held flows by its session and commits them in
// arrival order, leaving any failed dial still to end waiting (part (c)).
// A second result for a run, or one for a run the hold doesn't know, does
// nothing. It is a scheduler call, as Dispatch is: past HoldLockWait, or on
// a recovered panic before the batch's records are in the store, it
// returns ErrHoldTimeout, the staged changes are rolled back, and the
// run's flows stay held until its deadline releases them untied. A panic
// after the receipts finishes the release, as when the record after the
// batch is not saved, and returns the receipts' after_seq, so the session
// is handed on (D1's ruling on #676). The after_seq is the largest seq of
// the batch's receipts, or the head read before the batch when nothing
// committed; when that head can't be read, it returns the error before
// anything is applied, and the run stays held (D6's note 1 on #663, D3's
// B2 on #676).
func (l *Link) Result(ctx context.Context, requestID string, s Session) (out Released, err error) {
	err = l.schedCall(&l.stats.ResultTimeouts, func() error {
		out, err = l.result(ctx, requestID, s)
		return err
	})
	if l.lateShortDue.Swap(false) {
		// Raised outside the link's lock, as the alarms are elsewhere.
		l.raise(AlarmLateIndexShort, fmt.Sprintf("sensor %s: a late-index entry was evicted inside its %s horizon", l.cfg.SensorID, HoldLateHorizon))
	}
	return out, err
}

func (l *Link) result(ctx context.Context, requestID string, s Session) (out Released, err error) {
	// The phased clean-up (D1's ruling on #676). It always clears the
	// hold-wide staged state, which the next release, perhaps another
	// run's, would otherwise apply. Before the receipts it rolls back the
	// open table and lets the panic reach schedCall; after them it
	// finishes the release and returns its after_seq.
	l.hold.phase = nil
	defer func() {
		p := recover()
		if after, done := l.endPhase(p); done {
			out, err = Released{AfterSeq: after, OpenFlow: l.hold.repointed}, nil
			return
		}
		if p != nil {
			panic(p)
		}
	}()
	r := l.hold.runs[requestID]
	if r == nil || r.rec.State != HoldHolding {
		head, err := l.head(ctx)
		skewed := l.hold.skewed[requestID] || (r != nil && r.skewed)
		delete(l.hold.skewed, requestID)
		return Released{AfterSeq: head, Skewed: skewed}, err
	}
	h, g, now := l.hold, l.hold.grace(), l.hold.now()
	rec := cloneRec(r.rec)
	rec.Session = &s
	// The skew gate (section 1.5): a cause that stands, or the run's
	// window refused, refuses every tie; the capture floor refuses a flow
	// captured at or before it. Each tie refused is counted once.
	standing, window := l.standing(), l.windowRefusal(r, s)
	r.resOff, r.resulted = l.offNow(), true
	r.skewed = r.skewed || standing != "" || window != ""
	if s.Connected && s.Local.IsValid() {
		if i := h.openIndex(FlowKey{Node: s.Local, Peer: rec.Run.Endpoint, L4: rec.Run.L4}); i >= 0 && !h.expired(h.open[i], now) {
			o := h.open[i]
			// The re-point ties the entry's later records to this run, so
			// the skew gate takes it as a tie (D6's N1 on #748): refused, it
			// is counted once and not made, and the entry keeps its tie,
			// decided again at each later record (openTie).
			switch c := first(standing, window, l.storedRefusal(o.Off, o.Live)); {
			case r.onset:
			case c != "":
				l.countRefusal(c)
				r.skewed = true
			default:
				// Staged: it takes effect only with the release's record
				// below (D6's N1 on #576). Its expiry is unchanged.
				o.InvocationID, o.Tie, o.AssetID = s.InvocationID, TieConnection, rec.Run.AssetID
				h.repoint = &o
			}
		}
	}
	var rel []Release
	var remaining []HeldFlow
	for _, f := range rec.Flows {
		tie, wait := "", time.Time{}
		start := l.toNode(f.Start) // t_sensor + E (CH-22's sign)
		failedDial := f.Key.L4 == "tcp" && !f.Other && in(start, s.StartedAt.Add(-g), s.EndedAt.Add(g)) &&
			(!s.Connected || !s.Local.IsValid() || f.Key.Node.Port() != s.Local.Port())
		switch {
		case s.Connected && s.Local.IsValid() && f.Key == (FlowKey{Node: s.Local, Peer: rec.Run.Endpoint, L4: rec.Run.L4}) &&
			in(start, s.StartedAt.Add(-g), s.EndedAt.Add(g)):
			tie = TieConnection
		case s.Connected && !s.Local.IsValid() && !rec.WindowTaken && in(start, s.StartedAt.Add(-g), s.EndedAt.Add(g)) &&
			(f.Other || (f.Ended && !f.SynOnly)):
			tie, rec.WindowTaken = TieWindow, true
		case failedDial && f.Ended && f.SynOnly:
			tie = TieWindow
		case failedDial && !f.Ended && !f.EndLost:
			if w := f.Arrival.Add(HoldDialLimit + time.Duration(f.FlowIdle)*time.Second + g); w.After(now) {
				wait = w
			}
		}
		if !wait.IsZero() {
			f.Wait = wait
			remaining = append(remaining, f)
			continue
		}
		skewed := standing != ""
		switch {
		case tie == "":
		case r.onset:
			tie, skewed = "", true // refused and counted at the onset
		default:
			if c := first(standing, window, l.floorRefusal(f.Start)); c != "" {
				l.countRefusal(c)
				tie, skewed = "", true
			}
		}
		rel = append(rel, markSkewed(h.releaseFlow(f, tie, s.InvocationID, rec.Run.AssetID), skewed)...)
	}
	after, err := l.release(ctx, r, rec, rel, remaining)
	if err != nil {
		return Released{}, err
	}
	// A session released with no flow tied, none left waiting and its
	// window not refused enters the late index (part (e); D3's L2 (i)).
	tied := h.repointed || slices.ContainsFunc(rel, func(x Release) bool { return x.Tie != nil })
	if (!tied || lateIndexAll) && len(remaining) == 0 && !r.skewed {
		l.lateAdd(lateEntry{run: rec.Run, s: s, stamps: r.stamps})
	}
	out.AfterSeq = after
	out.OpenFlow = h.repointed
	out.Skewed = r.skewed
	return out, nil
}

// markSkewed marks rel's untied records as released untied for skew.
func markSkewed(rel []Release, skewed bool) []Release {
	if skewMarkAlarmOnly {
		skewed = false // the control: the alarm's onset releases nothing marked
	}
	for i := range rel {
		rel[i].Skewed = skewed && rel[i].Tie == nil
	}
	return rel
}

// windowRefusal is the stored-time half of the rule on the two clocks for
// a run's window at its Result (section 1.5): the node's offsets at
// Dispatch and now agree within MaxSkew, and the session's times lie
// between the node's wall times at Dispatch and now, within MaxSkew. A run
// held before the node's start ties nothing. "" when the window may tie,
// and always off the 0.2 path.
func (l *Link) windowRefusal(r *holdRun, s Session) string {
	if !l.skewOn() || skewNoStored {
		return ""
	}
	if c := l.storedRefusal(r.dispOff, r.live); c != "" {
		return c
	}
	if s.StartedAt.Before(r.dispWall.Add(-MaxSkew)) || s.EndedAt.After(l.now().Add(MaxSkew)) {
		return skewMoved
	}
	return ""
}

// laterRefusal is the gate for a tie decided at a later record's read, by
// a waiting run (part (c)) or the late index (part (e)): a cause that
// stands, the window's offsets at Dispatch and at Result, each against the
// current one, and the capture floor.
func (l *Link) laterRefusal(r stamps, capt time.Time) string {
	if !l.skewOn() {
		return ""
	}
	return first(l.standing(), l.storedRefusal(r.dispOff, r.live), l.storedRefusal(r.resOff, r.live && r.resulted),
		l.floorRefusal(capt))
}

// skewOnset is the onset of a cause that refuses every tie: every run the
// hold keeps gives way untied at once, its records marked, and its window
// refused, counted once for each run under the cause that stands, as
// Dispatch counts (section 1.5 item 2; D4's F1 and D6's B1 on #748). A
// holding run stays, empty, so its Result reports the window refused and
// ties nothing it holds after. The caller holds curMu and not cmu.
func (l *Link) skewOnset(ctx context.Context) {
	c := l.standing()
	if skewNoOnset || c == "" {
		return
	}
	l.cmu.Lock()
	defer l.cmu.Unlock()
	defer l.syncHold()
	h := l.hold
	for _, r := range h.sorted() {
		rec := cloneRec(r.rec)
		if rec.State != HoldHolding && rec.State != HoldWaiting {
			continue
		}
		if !r.onset {
			l.countRefusal(c)
		}
		r.skewed, r.onset = true, true
		if len(rec.Flows) == 0 {
			continue
		}
		keep := rec.State == HoldHolding
		// A head not read begins nothing; the run's deadline tries again.
		if _, err := l.release(ctx, r, rec, markSkewed(h.untied(rec.Flows), true), nil); err == nil && keep {
			if cur := h.runs[rec.Run.RequestID]; cur == nil {
				// release ended a holding run with nothing left: keep it
				// holding, empty, for its Result.
				rec.Flows, rec.State = nil, HoldHolding
				if h.save(ctx, rec) == nil {
					r.rec = *h.last
					h.runs[rec.Run.RequestID] = r
				} else {
					// Not kept: its Result reports the window refused from
					// here (D4's F3 (a), D6's N3 on #748).
					h.skewed[rec.Run.RequestID] = true
				}
			}
		}
	}
}

// endPhase is a scheduler call's deferred clean-up of its release, given
// the recovered panic p or nil (D1's ruling on #676). It always clears the
// hold-wide staged state. On a panic after the batch's receipts it finishes
// the release, as when the record after the batch is not saved, counts the
// panic as that checkpoint failure, so intake-checkpoint-failed stands on
// the node (D6's B1 on #676's 98aa92e8), and reports the receipts'
// after_seq and true: the caller returns it, and p is spent. On a panic
// before them it rolls back the open table, and the caller re-panics. If
// the releasing record was saved, it then saves the run's holding record
// again, so a restart does not find the run releasing and commit its batch
// tied to a session never handed on (D3's B2 and D4's note on #676's
// 98aa92e8). A failed re-save is counted in checkpoint_failures and leaves
// the releasing record newest, as with no re-save; a panic in it is
// recovered and counted the same way, and the first panic still reaches
// the caller.
func (l *Link) endPhase(p any) (after uint64, done bool) {
	h := l.hold
	ph := h.phase
	h.phase = nil
	resave := false
	switch {
	case p != nil && ph != nil && ph.taken:
		h.stats.CheckpointFailures++
		ph.finish()
		l.notePanic(p)
		after, done = ph.after, true
	case p != nil && ph != nil && ph.staged:
		h.open = ph.prev
		resave = ph.saved
	}
	h.pending, h.pendingTied, h.repoint = nil, 0, nil
	if resave {
		func() {
			defer func() {
				if recover() != nil {
					h.stats.CheckpointFailures++
				}
			}()
			ph.resave()
		}()
	}
	return after, done
}

// Abandon releases a run that ended without a result, untied, at once. It
// is a scheduler call, counted with the results. Its release has result's
// phased clean-up (endPhase): a panic after the batch's receipts finishes
// the release and returns their after_seq, so the deadline does not commit
// the run's records a second time (D6's N3 on #676's 98aa92e8).
func (l *Link) Abandon(ctx context.Context, requestID string) (head uint64, err error) {
	err = l.schedCall(&l.stats.ResultTimeouts, func() (ferr error) {
		l.hold.phase = nil
		defer func() {
			p := recover()
			if after, done := l.endPhase(p); done {
				head, ferr = after, nil
				return
			}
			if p != nil {
				panic(p)
			}
		}()
		delete(l.hold.skewed, requestID) // no Result comes for it (D6's N3 (b) on #748)
		r := l.hold.runs[requestID]
		if r == nil {
			head, err = l.head(ctx)
			return err
		}
		head, err = l.release(ctx, r, cloneRec(r.rec), l.hold.untied(r.rec.Flows), nil)
		return err
	})
	return head, err
}

// TickHold releases, untied, every hold past its deadline: a run with no
// result past its own, and a failed dial past its wait. A deadline is never
// later than now plus its limits plus g, so a backward clock step can't
// stretch it (D1).
func (l *Link) TickHold(ctx context.Context) {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	defer l.syncHold()
	h := l.hold
	g, now := h.grace(), h.now()
	if h.on() {
		h.expireOpen(ctx)
	}
	for _, r := range h.sorted() {
		rec := cloneRec(r.rec)
		switch rec.State {
		case HoldHolding:
			if lim := now.Add(HoldRunLimit + g); rec.Run.Deadline.After(lim) {
				r.rec.Run.Deadline, rec.Run.Deadline = lim, lim
			}
			if !now.Before(rec.Run.Deadline) {
				if _, err := l.release(ctx, r, rec, h.untied(rec.Flows), nil); err == nil {
					h.stats.DeadlineReleases++ // a head not read begins nothing, tried at the next tick
				}
			}
		case HoldWaiting:
			var rel []Release
			var remaining []HeldFlow
			due := uint64(0)
			for i, f := range rec.Flows {
				if lim := now.Add(HoldDialLimit + time.Duration(f.FlowIdle)*time.Second + g); f.Wait.After(lim) {
					r.rec.Flows[i].Wait, f.Wait = lim, lim
				}
				if now.Before(f.Wait) {
					remaining = append(remaining, f)
					continue
				}
				due++
				rel = append(rel, h.untied([]HeldFlow{f})...)
			}
			if len(rel) > 0 {
				if _, err := l.release(ctx, r, rec, rel, remaining); err == nil {
					h.stats.DeadlineReleases += due
				}
			}
		}
	}
}

// giveWay is a new sensor run, or degraded coverage: a failed dial's end
// may never come. A waiting flow gives way untied at once, and a held flow
// with no end yet can no longer wait for one. A new run also clears the
// open table, whose ends will never come. The caller holds cmu.
func (l *Link) giveWay(ctx context.Context, newRun bool) {
	h := l.hold
	if !h.on() {
		return
	}
	if newRun && len(h.open) > 0 && h.last != nil {
		h.open = nil
		_ = h.save(ctx, *h.last) // counted on failure; the table is cleared either way
	}
	for _, r := range h.sorted() {
		rec := cloneRec(r.rec)
		switch rec.State {
		case HoldHolding:
			changed := false
			for i := range rec.Flows {
				if !rec.Flows[i].Ended && !rec.Flows[i].EndLost {
					rec.Flows[i].EndLost, changed = true, true
				}
			}
			if changed && h.save(ctx, rec) == nil {
				r.rec = rec
			}
		case HoldWaiting:
			l.release(ctx, r, rec, h.untied(rec.Flows), nil)
		}
	}
}

// untied is fs's records with no tie.
func (h *hold) untied(fs []HeldFlow) (out []Release) {
	for _, f := range fs {
		out = append(out, h.releaseFlow(f, "", "", "")...)
	}
	return out
}

// releaseFlow is f's records with tie, if any; a tied flow not yet ended
// joins the open table (part (d)) with the release (release).
func (h *hold) releaseFlow(f HeldFlow, tie, invocation, assetID string) []Release {
	out := make([]Release, len(f.Records))
	for i, r := range f.Records {
		out[i].Record = r
		if tie != "" {
			out[i].Tie = &netobs.PlatformSession{InvocationID: invocation, Tie: tie}
			out[i].Asset = assetID
		}
	}
	if tie != "" {
		h.pendingTied++
	}
	if tie != "" && !f.Ended {
		h.pending = append(h.pending, OpenFlow{Key: f.Key, InvocationID: invocation, Tie: tie, AssetID: assetID,
			Expires: f.Last.Add(time.Duration(f.FlowIdle)*time.Second + h.grace()), FlowIdle: f.FlowIdle,
			Off: h.off(), Live: true})
	}
	return out
}

// release commits rel and keeps remaining, in rec's run: first the record
// saying what it releases (state releasing), then the batch, then the
// record after it. A release whose record can't be saved commits untied
// (D4-72). It returns the after_seq: the largest seq of the batch's
// receipts, taken as soon as the batch returns, or the head read before
// the batch when nothing committed. While cmu is held nothing else commits
// to the stream, so the head before is exact then. A head that can't be
// read before begins nothing: no releasing record is saved without the
// head RecoverHold compares (D4's condition (i), D1's ruling on #676).
func (l *Link) release(ctx context.Context, r *holdRun, rec RunRecord, rel []Release, remaining []HeldFlow) (uint64, error) {
	h := l.hold
	head, err := l.head(ctx)
	if err == nil {
		err = l.readPos(ctx) // the 0.2 position, as the head (D6's N3 on #742)
	}
	if err != nil {
		// Nothing is applied, so the staged ties the caller built
		// (releaseFlow) go with it: they never reach the next release (D6's
		// B2 on #676's 98aa92e8).
		h.stats.HeadUnread++
		h.pending, h.pendingTied = nil, 0
		return 0, err
	}
	ph := &releasePhase{prev: slices.Clone(h.open), after: head}
	h.phase = ph
	rec.Flows, rec.Releasing, rec.Head = remaining, rel, head
	rec.State = HoldReleasing
	// The staged table changes (the tied flows still open, and a result's
	// re-point) take effect only with the first record saved below: the
	// releasing record if there is a batch, else the final one.
	evicted := uint64(0)
	if o := h.repoint; o != nil {
		if i := h.openIndex(o.Key); i >= 0 {
			h.open = slices.Clone(h.open)
			h.open[i] = *o
		}
	}
	for _, o := range h.pending {
		evicted += h.addOpen(o)
	}
	ph.staged = true
	applied := true
	rec.OpenFlow = h.repoint != nil
	// final is the record after the batch, and settle the end state in
	// memory, as built from it.
	final := func() RunRecord {
		f := rec
		f.Releasing, f.Head, f.AfterSeq = nil, 0, ph.after
		f.State = HoldReleased
		if len(remaining) > 0 {
			f.State = HoldWaiting
		}
		f.OpenFlow = applied && h.repoint != nil
		return f
	}
	settle := func(f RunRecord) {
		if applied {
			h.stats.OpenEvicted += evicted
			h.stats.Tied += h.pendingTied
		}
		f.OpenFlow = applied && h.repoint != nil
		h.repointed = f.OpenFlow
		h.pending, h.pendingTied, h.repoint = nil, 0, nil
		if f.State == HoldReleased {
			delete(h.runs, f.Run.RequestID)
		} else {
			r.rec = f
		}
	}
	// After the receipts, a recovered panic ends the release as a failed
	// save of the record after the batch does (result).
	ph.finish = func() { settle(final()) }
	ph.resave = func() { _ = h.save(ctx, r.rec) } // counted on failure
	if len(rel) > 0 {
		if err := h.save(ctx, rec); err != nil {
			h.open, applied = ph.prev, false
			for i := range rel {
				rel[i].Tie, rel[i].Asset = nil, ""
			}
		} else {
			ph.saved = true
		}
		l.commitBatch(ctx, rel, func(last uint64) { ph.after, ph.taken = last, true })
	}
	f := final()
	// Counted on failure; a restart finds the releasing record and checks
	// the batch.
	if err := h.save(ctx, f); err != nil && len(rel) == 0 {
		h.open, applied = ph.prev, false
	}
	settle(f)
	h.phase = nil
	return ph.after, nil
}

// RecoverHold finishes a release a restart interrupted: a run saved as
// releasing whose batch did not commit, by the stream's head, commits it
// now. It runs once, at start, before Serve.
func (l *Link) RecoverHold(ctx context.Context) error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	defer l.syncHold()
	for _, r := range l.hold.sorted() {
		if r.rec.State != HoldReleasing {
			continue
		}
		head, err := l.head(ctx)
		if err == nil {
			err = l.readPos(ctx)
		}
		if err != nil {
			return err
		}
		rec := cloneRec(r.rec)
		after := head // the receipts' rule, as in release, so no 0 is saved (D4 on #676)
		if head == rec.Head {
			l.commitBatch(ctx, rec.Releasing, func(last uint64) { after = last })
		}
		rec.Releasing, rec.Head, rec.AfterSeq = nil, 0, after
		rec.State = HoldReleased
		if len(rec.Flows) > 0 {
			rec.State = HoldWaiting
		}
		_ = l.hold.save(ctx, rec)
		if rec.State == HoldReleased {
			delete(l.hold.runs, rec.Run.RequestID)
		} else {
			r.rec = rec
		}
	}
	return nil
}

// takeHeld holds st, ties it by the open table or the late index, or
// reports false so the caller commits it untied. bk: st is a backlog
// record the break refuses (CH-39), which takes no tie: the open table
// keeps its bookkeeping, and nothing holds it or ties it. The caller holds
// cmu.
func (l *Link) takeHeld(ctx context.Context, st *netobs.Observation, hr HeldRecord, bk bool) bool {
	h := l.hold
	if !h.on() {
		return false
	}
	if isStart(st) {
		h.lastStart, h.lastStartWall, h.started = h.mono(), h.now(), true // any start of the run, before the match (CH-57)
	}
	k, ok := h.keyOf(st)
	if !ok {
		return false
	}
	if i := h.openIndex(k); i >= 0 {
		of, now := h.open[i], h.now()
		// The arriving record is matched before the expiry check, so it never
		// expires the entry it is about to tie (D4-102 item 5 (c)).
		switch {
		case isStart(st) || h.expired(of, now):
			// A start means the sensor saw the old flow end, and an entry
			// that has expired (past its bound, with a later start taken)
			// the sensor has ended as idle: the entry leaves, written first
			// and counted, and the record is judged as a new flow (D1 on
			// #576).
			if isStart(st) {
				h.stats.OpenSuperseded++
			} else {
				h.stats.OpenExpired++
			}
			h.open = slices.Delete(slices.Clone(h.open), i, i+1)
			if h.last != nil && h.save(ctx, *h.last) != nil {
				l.commitOne(ctx, hr, nil, "")
				return true
			}
		case isEnd(st) && h.last != nil:
			// The end releases the key, and the release is written first.
			h.open = slices.Delete(slices.Clone(h.open), i, i+1)
			if err := h.save(ctx, *h.last); err != nil {
				h.open = slices.Insert(h.open, i, of)
				l.commitOne(ctx, hr, nil, "")
				return true
			}
			tie := l.openTie(of, st, &hr, bk) // before hr is read: it may mark it
			l.commitOne(ctx, hr, tie, of.AssetID)
			return true
		default:
			// The flow is still live: its expiry moves to this record's,
			// written so that it survives a restart (a failed write is
			// counted, and leaves the earlier expiry).
			h.open = slices.Clone(h.open)
			h.open[i].Expires = now.Add(time.Duration(of.FlowIdle)*time.Second + h.grace())
			if h.last != nil {
				_ = h.save(ctx, *h.last)
			}
			tie := l.openTie(of, st, &hr, bk) // before hr is read: it may mark it
			l.commitOne(ctx, hr, tie, of.AssetID)
			return true
		}
	}
	if bk {
		// No hold and no late tie for it (CH-39), but an entry it matches
		// is spent by it, refused (D1's ruling 2 on #770).
		if i := l.lateFind(k, st); i >= 0 {
			h.late = slices.Delete(h.late, i, i+1)
		}
		return false
	}
	r := h.runFor(k)
	if r == nil {
		return l.lateTie(ctx, st, hr, k)
	}
	if c := l.standing(); c != "" {
		// No tie is made for skew: the record commits untied, counted and
		// marked here, since a cause read here may have come after observe
		// read none (the closure moves with the wall clock). A run the
		// onset refused was counted then.
		if !r.onset {
			l.countRefusal(c)
		}
		if l.marks(c) && !skewTakeHeldUnmarked {
			if b, err := nodeBody(hr.Observation, "skewed", true); err == nil {
				hr.Observation = b
			}
		}
		l.commitOne(ctx, hr, nil, "")
		return true
	}
	rec := cloneRec(r.rec)
	fi := slices.IndexFunc(rec.Flows, func(f HeldFlow) bool { return f.Key == k })
	if fi < 0 && (rec.State != HoldHolding || len(rec.Flows) >= HoldFlowCap) {
		h.stats.PastFlowCap++
		return false
	}
	if heldCount(rec) >= HoldRecordCap {
		// A release not begun (its head unread) leaves the run held and hr
		// to the caller, which commits it untied or counts its drop (D3's
		// B1 and D6's B2 on #676's 98aa92e8).
		rel := append(h.untied(rec.Flows), Release{Record: hr})
		if _, err := l.release(ctx, r, rec, rel, nil); err != nil {
			return false
		}
		h.stats.RecordCapReleases++
		return true
	}
	if fi < 0 {
		rec.Flows = append(rec.Flows, HeldFlow{Key: k, Start: flowStart(st), FlowIdle: int64(st.Coverage.Settings.FlowIdleS), Arrival: h.now()})
		fi = len(rec.Flows) - 1
	}
	f := &rec.Flows[fi]
	f.Records, f.Last = append(f.Records, hr), h.now()
	note(f, st)
	if rec.State == HoldWaiting && (f.Ended || f.Other) {
		// A waiting dial ended or carried data: a syn_only end takes the
		// window tie; anything else is untied, unless it is the first
		// established flow of a 0.8 run (part (b)).
		s, tie := rec.Session, ""
		switch {
		case f.Ended && f.SynOnly && !f.Other:
			tie = TieWindow
		case s != nil && s.Connected && !s.Local.IsValid() && !rec.WindowTaken && in(l.toNode(f.Start), s.StartedAt.Add(-h.grace()), s.EndedAt.Add(h.grace())):
			tie, rec.WindowTaken = TieWindow, true
		}
		skewed := l.standing() != ""
		switch c := l.laterRefusal(r.stamps, f.Start); {
		case tie == "":
		case r.onset:
			tie, skewed = "", true // refused and counted at the onset (D6's B4 on #748)
		case c != "":
			l.countRefusal(c)
			tie, skewed = "", true
		}
		done := *f
		rec.Flows = slices.Delete(rec.Flows, fi, fi+1)
		invocation := ""
		if s != nil {
			invocation = s.InvocationID
		}
		if _, err := l.release(ctx, r, rec, markSkewed(h.releaseFlow(done, tie, invocation, rec.Run.AssetID), skewed), rec.Flows); err != nil {
			return false // as at the record cap
		}
		return true
	}
	if err := h.save(ctx, rec); err != nil {
		return false
	}
	r.rec = rec
	return true
}

// openTie is the open table's tie for a later record of of's flow (part
// (d)), decided at its read: nil, counted, when the gate refuses it, and
// the record then carries node.skewed (section 1.5); nil for a backlog
// record the break refuses (bk), which carries node.backlog instead.
func (l *Link) openTie(of OpenFlow, st *netobs.Observation, hr *HeldRecord, bk bool) *netobs.PlatformSession {
	if bk {
		return nil
	}
	if c := first(l.standing(), l.storedRefusal(of.Off, of.Live), l.floorRefusal(flowStart(st))); c != "" {
		l.countRefusal(c)
		if b, err := nodeBody(hr.Observation, "skewed", true); err == nil {
			hr.Observation = b
		}
		return nil
	}
	return &netobs.PlatformSession{InvocationID: of.InvocationID, Tie: of.Tie}
}

// head is the observation stream's last committed seq.
func (l *Link) head(ctx context.Context) (uint64, error) { return l.opt.Store.LastCommitted(ctx) }

// syncHold copies the hold's counts into Stats. The caller holds cmu.
func (l *Link) syncHold() {
	s := l.hold.statsNow()
	l.mu.Lock()
	l.stats.Hold = s
	l.mu.Unlock()
}
