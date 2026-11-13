package node

import (
	"bytes"
	"context"
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
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/netdetect"
	"otsec.local/otsec/platform/sensorlink"
)

// The detector consumer (P4-4-B5 deliverable 3, D4-72 to D4-74,
// docs/phase4/D5-sensor-node.md section 3): the node reads the sensor's
// observation stream into netdetect's detector, hands it the node's own
// sessions from collection.run, commits the alerts it raises with their
// capture, and checkpoints it, and only then moves its C5 cursor.

// DetectorConsumer is the detector's required C5 consumer of the
// observation stream: what it has folded into a committed checkpoint is
// prunable.
const DetectorConsumer c5.ConsumerID = "node-netdetector"

// The detector's alarms.
const (
	// AlarmDetectorCheckpoint: a netcheckpoint.detector was not stored,
	// or the cursor not saved after it, so the cursor stays where it was
	// and a restart resumes from the last checkpoint stored.
	AlarmDetectorCheckpoint = "network-detector-checkpoint-failed"
	// AlarmDetectorNotStarted: the detector consumer did not start, so
	// no alert is raised, and its cursor holds the observation stream.
	AlarmDetectorNotStarted = "network-detector-not-started"
	// AlarmDetectorNotRestored: the stored checkpoint did not restore, so
	// the detector started again from the oldest retained observation.
	AlarmDetectorNotRestored = "network-detector-not-restored"
	// AlarmDetectorMismatch: a restore's replay departed from the alerts
	// already committed (netdetect.Detector.Mismatches).
	AlarmDetectorMismatch = "network-detector-mismatch"
	// AlarmSessionNotJudged: a session was not judged for pending-full or
	// tied-evicted, raised as each count rises (D1's F2 on #590).
	AlarmSessionNotJudged = "network-session-not-judged"
	// AlarmDetectorOrdering: a session was handed over after observations
	// it precedes, the node's ordering fault (netdetect.ErrOrdering).
	AlarmDetectorOrdering = "network-detector-ordering"
	// AlarmEndpointsNotTracked: enrolled run endpoints past
	// MaxDetectorEndpoints, whose sessions are never judged before
	// acknowledgement (D1's C1 on #575). Raised at start.
	AlarmEndpointsNotTracked = "network-endpoints-not-tracked"
	// AlarmAlertNotStored: an alert the detector raised was not committed.
	// One the store refused for the class's quota or record cap is dropped
	// and counted by (rule, asset). Any other is kept and tried again at
	// each tick, and until it commits the detector reads nothing more and
	// is not checkpointed. Raised once until an alert commits (D1 on B3).
	AlarmAlertNotStored = "network-alert-not-stored"
)

// FrameIndexEntries bounds the frame index, from a cited frame's SHA-256
// to the first-sight capture that holds it; the oldest goes first (D1 in
// D4-74).
const FrameIndexEntries = 4096

// detectorReadPage is how many records the driver reads at a time.
const detectorReadPage = 256

// DetectorStatus is the detector's part of the sensor section. Nothing in
// it is device text or packet bytes.
type DetectorStatus struct {
	// Through is the last observation seq taken, Checkpointed the last
	// one a stored checkpoint holds, which the cursor follows.
	Through      uint64 `json:"through"`
	Checkpointed uint64 `json:"checkpointed"`
	Restored     bool   `json:"restored"`
	// Alerts are the alerts committed since start; AlertsFramesMissing
	// those of them with frames_missing above 0 (D1 in D4-74).
	Alerts              int64 `json:"alerts"`
	AlertsFramesMissing int64 `json:"alerts_frames_missing"`
	AlertsNotStored     int64 `json:"alerts_not_stored"`
	// AlertsPending are the alerts raised and not yet committed, and
	// AlertCommitFailures the commits of them that failed since start.
	AlertsPending       int   `json:"alerts_pending"`
	AlertCommitFailures int64 `json:"alert_commit_failures"`
	// Refused are observations the detector refused, still taken.
	Refused int64 `json:"observations_refused"`
	// NotJudged are the sessions not judged, by reason (D4-74).
	NotJudged map[string]int64 `json:"not_judged"`
	// OpenFlowSeen counts the sessions seen through a reused conversation,
	// apart from those seen by a tie (D1 in D4-73).
	OpenFlowSeen        int64 `json:"open_flow_seen"`
	EndpointsNotTracked int   `json:"endpoints_not_tracked"`
	// NotYetSeen are the run endpoints own-session-unseen can't judge yet,
	// as "<asset_id> <l4> <addr>:<port>".
	NotYetSeen []string `json:"not_yet_seen,omitempty"`
	// EarlyCloses are the windows closed early since start, and
	// EarlyClosesPerHour the same over the node's monotonic hours since
	// start: a rising rate is decoys rotated over more keys than the cap
	// (D3's C1 on #569).
	EarlyCloses        int64   `json:"early_closes"`
	EarlyClosesPerHour float64 `json:"early_closes_per_hour"`
	Mismatches         int64   `json:"mismatches"`
	OrderingFaults     int64   `json:"ordering_faults"`
	CheckpointsWritten int64   `json:"checkpoints_written"`
	CheckpointFailures int64   `json:"checkpoint_failures"`
	// LagS is the node-clock seconds since the oldest observation the
	// detector has not read was committed, 0 when it has read them all;
	// Lagging says network-detector-lag stands for this stretch.
	LagS    int64 `json:"lag_s"`
	Lagging bool  `json:"lagging"`
}

// netDetector is the runtime's detector and its driver's state.
type netDetector struct {
	d   *netdetect.Detector
	cfg netdetect.DetectorConfig
	obs c5.StreamID
	// restored: the detector came from a checkpoint. pruned says the
	// observations after its Through were pruned at start, as they are at
	// a first start over a pruned stream, with firstObs the node's commit
	// time of the first record the detector read, refused or not: the
	// before-retained guard (D1 in D4-74 and on D4's F1 on #590). Not the
	// sensor's first_utc, which is a flow's start, nor received.utc, which
	// a held record's later commit takes out of seq order.
	restored bool
	pruned   bool
	firstObs time.Time
	// health is the health stream's seq the driver has read sessions to.
	health c5.Seq
	// written is Through at the last stored checkpoint, saved the cursor
	// stored, and ckpts the seqs of the stored checkpoints, oldest first,
	// the last one the newest. handed is the newest collection.run seq
	// handed over, and moved says one was handed over since the last
	// stored checkpoint, which holds the sessions taken.
	written uint64
	saved   c5.Seq
	ckpts   []c5.Seq
	handed  uint64
	moved   bool
	// unsent are the alert records raised and not yet committed, in the
	// order raised, and unsentAt each one's frames_missing above 0 and its
	// drop key.
	// While any are unsent the driver reads nothing more and the detector
	// is not checkpointed, so neither its checkpoint nor its cursor passes
	// an alert that isn't stored; a restart reads the observations again
	// and raises it again (D1's F1 on #590).
	unsent   []c5.Record
	unsentAt []unsentAlert
	index    frameIndex
	start    time.Duration
	st       DetectorStatus
	raised   map[string]bool
	// lagging: AlarmDetectorLag is raised for this stretch.
	lagging bool
}

// unsentAlert is what the node keeps of an unsent alert beside its record:
// whether frames_missing is above 0, and its drop key "<rule>.<asset>".
type unsentAlert struct {
	fm  bool
	key string
}

// frameIndex maps a cited frame's SHA-256 to the evidence ref of the
// first-sight capture that holds it, oldest out past FrameIndexEntries.
type frameIndex struct {
	at    map[string]string
	order []string
}

func (x *frameIndex) add(frame, ref string) {
	if x.at == nil {
		x.at = map[string]string{}
	}
	if _, ok := x.at[frame]; ok {
		return
	}
	x.at[frame] = ref
	x.order = append(x.order, frame)
	if len(x.order) > FrameIndexEntries {
		delete(x.at, x.order[0])
		x.order = x.order[1:]
	}
}

// note indexes o's frames when it is a first sight.
func (x *frameIndex) note(o *netobs.Observation) {
	if o == nil || o.Node == nil || o.Node.StoredCapture == "" {
		return
	}
	for _, f := range o.Citation.Frames {
		x.add(f.SHA256, "sha256:"+o.Node.StoredCapture)
	}
}

// detectorConfig is the detector's configuration from the node's.
func (r *Runtime) detectorConfig() netdetect.DetectorConfig {
	s := r.cfg.NetworkSensor
	cfg := netdetect.DetectorConfig{SensorID: s.SensorID, NodeID: r.cfg.NodeID, Stream: event.Stream(NetObservationStream(s.SensorID)),
		Params:        netobs.BaselineParams{TieGraceS: netobs.DefaultTieGraceS, CoalesceWindowS: netobs.DefaultCoalesceWindowS},
		NodeAddresses: s.NodeAddresses, NodeMACs: s.NodeMACs}
	for _, v := range s.NodeVLANs {
		if v == 0 {
			cfg.NodeUntagged = true
		} else {
			cfg.NodeVLANs = append(cfg.NodeVLANs, int(v))
		}
	}
	for _, x := range r.cfg.NetExclusions() {
		cfg.Exclusions = append(cfg.Exclusions, netdetect.Destination{Addr: x.Addr.String(), L4: x.L4, Port: x.Port})
	}
	seen := map[netdetect.Endpoint]bool{}
	for _, col := range r.cfg.Schedule {
		ep, l4, ok := r.cfg.holdEndpoint(col)
		if !ok {
			continue
		}
		e := netdetect.Endpoint{AssetID: col.AssetID, Destination: netdetect.Destination{Addr: ep.Addr().String(), L4: l4, Port: int(ep.Port())}}
		if !seen[e] {
			seen[e] = true
			cfg.Endpoints = append(cfg.Endpoints, e)
		}
	}
	return cfg
}

// startDetector restores the detector from its newest checkpoint, or starts
// it at the oldest retained observation, after the intake's start repair
// (D4-72). It rebuilds the frame index from the retained first sights.
func (r *Runtime) startDetector(ctx context.Context) error {
	s := r.cfg.NetworkSensor
	nd := &netDetector{cfg: r.detectorConfig(), obs: NetObservationStream(s.SensorID), start: r.opt.Mono(), raised: map[string]bool{}}
	odb := r.Store(nd.obs)
	if odb == nil {
		return errors.New("the network database is not open")
	}
	head, err := odb.LastCommitted(ctx, nd.obs)
	if err != nil {
		return err
	}
	cursors, err := odb.LoadCursors(ctx, nd.obs)
	if err != nil {
		return err
	}
	for _, c := range cursors {
		if c.Consumer == DetectorConsumer {
			nd.saved = c.Through
		}
	}
	if seqs, doc, err := r.detectorCheckpoints(ctx); err != nil {
		return err
	} else if doc != nil {
		// Every stored checkpoint goes once a newer one is stored, the
		// one that didn't restore too.
		nd.ckpts = seqs
		committed, err := r.alertsAfter(ctx, doc)
		if err == nil {
			nd.d, err = netdetect.RestoreDetector(nd.cfg, doc, committed, head)
		}
		if err != nil {
			r.opt.Status.Raise("", AlarmDetectorNotRestored, "the detector's checkpoint did not restore, so it starts again from the oldest retained observation: "+err.Error())
		} else {
			// The health read starts after the last session taken, so a
			// run before it, one that doesn't parse included, is not
			// read or counted again (D1's note 2 on #590).
			nd.restored, nd.written, nd.health = true, nd.d.Through(), c5.Seq(nd.d.SessionThrough())
		}
	}
	if nd.d == nil {
		if nd.d, err = netdetect.NewDetector(nd.cfg); err != nil {
			return err
		}
	}
	first, err := odb.FirstRetained(ctx, nd.obs)
	if err != nil {
		return err
	}
	through := c5.Seq(nd.d.Through())
	nd.pruned = first > through+1 || (first == 0 && head > through)
	if err := r.rebuildFrameIndex(ctx, nd); err != nil {
		return err
	}
	if !nd.restored {
		// A first start stores its checkpoint before it reads anything,
		// so a crash before the next one restores from it and holds back
		// the alerts already committed. The guard holds after that
		// restore, as the observations after Through 0 are still pruned.
		r.checkpointDetector(ctx, nd)
	}
	nd.st.EndpointsNotTracked = nd.d.EndpointsNotTracked()
	if n := nd.st.EndpointsNotTracked; n > 0 {
		r.opt.Status.Raise("", AlarmEndpointsNotTracked, fmt.Sprintf("%d enrolled run endpoint addresses past %d are not tracked, so before acknowledgement their sessions are never judged", n, netobs.MaxDetectorEndpoints))
	}
	r.detector = nd
	return nil
}

// observationOf decodes a stored observation.
func observationOf(st c5.Stored) (*netobs.Observation, error) {
	e, err := event.Decode(st.Event)
	if err != nil {
		return nil, err
	}
	return netobs.ObservationFromEvent(e)
}

// detectorCheckpoints are the seqs of the netcheckpoint.detector records
// on the intake's configuration stream, oldest first, and the newest's
// document, or nil.
func (r *Runtime) detectorCheckpoints(ctx context.Context) ([]c5.Seq, []byte, error) {
	stream := r.intakeStream()
	db := r.Store(stream)
	if db == nil {
		return nil, nil, errors.New("the configuration database is not open")
	}
	var (
		after c5.Seq
		seqs  []c5.Seq
		doc   []byte
	)
	for {
		got, err := db.Read(ctx, stream, after, 16)
		if err != nil {
			return nil, nil, err
		}
		for _, st := range got {
			after = st.Key.Seq
			var head struct{ Schema, Half string }
			if json.Unmarshal(st.Event, &head) == nil && head.Schema == netobs.CheckpointIdentifier && head.Half == netobs.HalfDetector {
				seqs, doc = append(seqs, st.Key.Seq), st.Event
			}
		}
		if len(got) < 16 {
			return seqs, doc, nil
		}
	}
}

// alertsAfter are the alerts on the alert stream after the checkpoint's
// last_alert_seq, which a restore holds back when its replay raises them
// again (D1 in D4-74).
func (r *Runtime) alertsAfter(ctx context.Context, doc []byte) ([]netdetect.Committed, error) {
	k, err := netobs.DecodeDetectorCheckpoint(doc)
	if err != nil {
		return nil, err
	}
	stream := NetAlertStream(r.cfg.NetworkSensor.SensorID)
	db := r.Store(stream)
	if db == nil {
		return nil, errors.New("the network database is not open")
	}
	var out []netdetect.Committed
	for after := c5.Seq(k.LastAlertSeq); ; {
		got, err := db.Read(ctx, stream, after, detectorReadPage)
		if err != nil {
			return nil, err
		}
		for _, st := range got {
			after = st.Key.Seq
			e, err := event.Decode(st.Event)
			if err != nil {
				return nil, err
			}
			a, err := netobs.AlertFromEvent(e)
			if err != nil {
				return nil, err
			}
			out = append(out, netdetect.Committed{Seq: st.Key.Seq, Alert: *a})
		}
		if len(got) < detectorReadPage {
			return out, nil
		}
	}
}

// rebuildFrameIndex indexes the frames of the retained first sights at or
// below the detector's Through, newest first, until the index is full.
func (r *Runtime) rebuildFrameIndex(ctx context.Context, nd *netDetector) error {
	db := r.Store(nd.obs)
	first, err := db.FirstRetained(ctx, nd.obs)
	if err != nil || first == 0 {
		return err
	}
	var sights []*netobs.Observation
	n := 0
	for hi := c5.Seq(nd.d.Through()); hi >= first && n < FrameIndexEntries; {
		lo := max(first-1, hi-min(hi, detectorReadPage))
		got, err := db.Read(ctx, nd.obs, lo, int(hi-lo))
		if err != nil {
			return err
		}
		for i := len(got) - 1; i >= 0 && n < FrameIndexEntries; i-- {
			if o, err := observationOf(got[i]); err == nil && o.Node != nil && o.Node.StoredCapture != "" {
				sights = append(sights, o)
				n += len(o.Citation.Frames)
			}
		}
		if lo < first {
			break
		}
		hi = lo
	}
	for i := len(sights) - 1; i >= 0; i-- {
		nd.index.note(sights[i])
	}
	return nil
}

// AlarmDetectorLag: the oldest observation the detector has not read was
// committed more than DetectorLagRaise ago on the node's clock, so alerts
// come late. It is raised once for each stretch, which ends when the lag
// is below DetectorLagClear; status shows the lag (section 1.9 item 3).
const AlarmDetectorLag = "network-detector-lag"

// DetectorLagRaise and DetectorLagClear are the lag alarm's bounds
// (section 1.10).
const (
	DetectorLagRaise = 60 * time.Second
	DetectorLagClear = 30 * time.Second
)

// tickDetector drives the detector once, within a drive's bounds, and
// checkpoints when the detector took an observation or a session since
// the last checkpoint. It runs at each step Tick asks for, so a checkpoint
// is written at most once a TickInterval (60 s), and at a clean stop (D1 in
// D4-74; section 1.9 item 3); the drives between steps never checkpoint. A
// session counts because a restart must find it taken: one skipped, handed
// over again to a restored detector, would be judged. It reports whether
// the drive stopped at its bound, with more to read.
func (r *Runtime) tickDetector(ctx context.Context) (more bool) {
	nd := r.detector
	if nd == nil {
		return false
	}
	more = r.driveOnce(ctx, nd)
	if len(nd.unsent) == 0 && (nd.d.Through() != nd.written || nd.moved) {
		r.checkpointDetector(ctx, nd)
	} else if c5.Seq(nd.written) > nd.saved || len(nd.ckpts) > 1 {
		// A cursor save or a removal that failed is tried again, though no
		// new checkpoint is due (D6's N2 on #590).
		r.saveDetectorCursor(ctx, nd)
	}
	r.detectorStatus(nd)
	return more
}

// driveOnce commits the alerts still unsent, then drives the detector
// within one drive's bounds, and judges its lag. It reports whether the
// drive stopped at its bound.
func (r *Runtime) driveOnce(ctx context.Context, nd *netDetector) (more bool) {
	if r.flushAlerts(ctx, nd) {
		more = r.driveDetector(ctx, nd, newDrive())
	}
	r.detectorLag(ctx, nd)
	return more
}

// drive bounds one drive of the detector: at most DriveObservations
// observations, and DriveTime of the process's monotonic clock, which
// bounds the manager's own work and is no rule on the node's clock.
type drive struct {
	left  int
	until time.Time
	spent bool
}

func newDrive() *drive { return &drive{left: DriveObservations, until: time.Now().Add(DriveTime)} }

// take reports whether the drive may take one more observation.
func (dv *drive) take() bool {
	if dv.left <= 0 || !time.Now().Before(dv.until) {
		dv.spent = true
		return false
	}
	dv.left--
	return true
}

// detectorLag sets the detector's lag in status: the node-clock time since
// the oldest observation it has not read was committed, 0 when it has read
// them all. It raises AlarmDetectorLag once a stretch past
// DetectorLagRaise, and the stretch ends below DetectorLagClear. A read that
// fails leaves the lag as it was.
func (r *Runtime) detectorLag(ctx context.Context, nd *netDetector) {
	db := r.Store(nd.obs)
	if db == nil {
		return
	}
	head, err := db.LastCommitted(ctx, nd.obs)
	if err != nil {
		return
	}
	var lag time.Duration
	if through := nd.d.Through(); through < uint64(head) {
		got, err := db.Read(ctx, nd.obs, c5.Seq(through), 1)
		if err != nil || len(got) == 0 {
			return
		}
		lag = max(r.opt.Now().Sub(got[0].CommittedAt), 0)
	}
	nd.st.LagS = int64(lag / time.Second)
	switch {
	case lag > DetectorLagRaise && !nd.lagging:
		nd.lagging = true
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmDetectorLag, At: r.opt.Now(), Stream: nd.obs,
			Detail: fmt.Sprintf("the oldest observation the detector has not read was committed %s ago, more than %s, so its alerts come late", lag.Round(time.Second), DetectorLagRaise)})
	case lag < DetectorLagClear:
		nd.lagging = false
	}
	nd.st.Lagging = nd.lagging
}

// driveDetector feeds the detector the sessions and observations committed
// since it last ran. The observation stream's head is read first, then the
// handover barrier (the lowest after_seq of a run whose release committed
// and whose collection.run may still come), then the health stream: so a
// run that releases after the barrier has its after_seq at or past the
// head read, and a run that left the barrier has its collection.run on the
// health stream already. Observations go to min(head, barrier), and each
// session is handed over, in health-stream seq order, before the
// observations past its after_seq (D4's finding 4 on #576). It stops at an
// alert that isn't committed, and at dv's bound before a session whose
// after_seq it has not reached, which keeps the ordering rule; it reports
// whether it stopped at the bound.
func (r *Runtime) driveDetector(ctx context.Context, nd *netDetector, dv *drive) bool {
	odb, hdb := r.Store(nd.obs), r.Store(HealthStream)
	if odb == nil || hdb == nil {
		return false
	}
	head, err := odb.LastCommitted(ctx, nd.obs)
	if err != nil {
		return false
	}
	limit := min(head, r.intake.barrier(head))
	runs, end, err := r.newSessions(ctx, hdb, nd)
	if err != nil {
		return false
	}
	// The health position moves past a collection.run only once it is
	// handed over, or counted when it doesn't parse, so one the driver
	// stops before is read again at the next tick (D6's N1 on #590).
	for _, e := range runs {
		if e.bad {
			r.intake.missing() // D3 on #590
		} else {
			if r.observeTo(ctx, nd, min(e.s.AfterSeq, limit), dv); len(nd.unsent) > 0 || dv.spent {
				return dv.spent && len(nd.unsent) == 0
			}
			r.handOver(ctx, nd, e.s)
		}
		nd.health = e.seq
		if len(nd.unsent) > 0 {
			return false
		}
	}
	nd.health = end
	r.observeTo(ctx, nd, limit, dv)
	return dv.spent && len(nd.unsent) == 0
}

// runEntry is a collection.run record on the health stream: its session,
// or bad when it doesn't parse.
type runEntry struct {
	seq c5.Seq
	s   RunSession
	bad bool
}

// newSessions reads the collection.run records with a session after the
// driver's health position, in seq order, and the last seq read. It moves
// nothing: a read that fails gives nothing, and the next tick reads the
// same records again.
func (r *Runtime) newSessions(ctx context.Context, hdb interface {
	Read(context.Context, c5.StreamID, c5.Seq, int) ([]c5.Stored, error)
}, nd *netDetector) ([]runEntry, c5.Seq, error) {
	var out []runEntry
	want := []byte(`"` + HealthCollectionRun + `"`)
	for after := nd.health; ; {
		got, err := hdb.Read(ctx, HealthStream, after, detectorReadPage)
		if err != nil {
			return nil, 0, err
		}
		for _, st := range got {
			after = st.Key.Seq
			if !bytes.Contains(st.Event, want) {
				continue
			}
			if s, ok, err := runSessionOf(st); err != nil {
				out = append(out, runEntry{seq: st.Key.Seq, bad: true})
			} else if ok {
				out = append(out, runEntry{seq: st.Key.Seq, s: s})
			}
		}
		if len(got) < detectorReadPage {
			return out, after, nil
		}
	}
}

// handOver hands s to the detector, or skips it when its flows may have
// been pruned (beforeRetained).
func (r *Runtime) handOver(ctx context.Context, nd *netDetector, s RunSession) {
	ds := netdetect.Session{Seq: s.Seq, InvocationID: s.InvocationID, AssetID: s.AssetID,
		Endpoint:  netdetect.Destination{Addr: s.Endpoint.Addr().String(), L4: s.L4, Port: int(s.Endpoint.Port())},
		Connected: s.Connected, OpenFlow: s.OpenFlow, StartedUTC: s.StartedUTC, EndedUTC: s.EndedUTC}
	var (
		alerts []netobs.Alert
		err    error
	)
	if s.Seq > nd.handed {
		nd.handed, nd.moved = s.Seq, true
	}
	if nd.beforeRetained(s) {
		err = nd.d.Skip(ds, s.AfterSeq)
	} else {
		alerts, err = nd.d.Session(ds, s.AfterSeq)
	}
	switch {
	case errors.Is(err, netdetect.ErrOrdering):
		r.raiseDetector(nd, AlarmDetectorOrdering, fmt.Sprintf("collection.run %d was handed over after observations it precedes; it is not judged", s.Seq))
	case err != nil && !errors.Is(err, netdetect.ErrNotJudged):
		// A session the detector refused is not judged, as one whose
		// record is missing (D6's N3 on #590); ErrNotJudged is pending-full.
		r.intake.missing()
	}
	r.commitAlerts(ctx, nd, alerts)
}

// beforeRetained is the guard: with the observations after the start's
// Through pruned, a connected session that is not open_flow, whose start
// less g is before the commit time of the first record read plus g, may
// have had its flows pruned, so it is skipped (D1 in D4-74).
func (nd *netDetector) beforeRetained(s RunSession) bool {
	if !nd.pruned || !s.Connected || s.OpenFlow {
		return false
	}
	start, err := time.Parse(time.RFC3339Nano, s.StartedUTC)
	g := time.Duration(netobs.DefaultTieGraceS) * time.Second
	return err != nil || nd.firstObs.IsZero() || start.Add(-g).Before(nd.firstObs.Add(g))
}

// observeTo feeds the detector the observations after its Through, to to,
// within dv's bound.
func (r *Runtime) observeTo(ctx context.Context, nd *netDetector, to uint64, dv *drive) {
	db := r.Store(nd.obs)
	for nd.d.Through() < to {
		if db == nil {
			return
		}
		got, err := db.Read(ctx, nd.obs, c5.Seq(nd.d.Through()), int(min(to-nd.d.Through(), detectorReadPage)))
		if err != nil || len(got) == 0 {
			return
		}
		for _, st := range got {
			if st.Key.Seq > to || !dv.take() {
				return
			}
			if f := r.opt.SensorSeams.Observe; f != nil {
				f()
			}
			id := event.EventID{NodeID: r.cfg.NodeID, Stream: event.Stream(nd.obs), Seq: st.Key.Seq}
			o, err := observationOf(st)
			if err != nil {
				o = nil // refused by Observe, which still takes its seq
			}
			nd.index.note(o)
			if nd.firstObs.IsZero() {
				nd.firstObs = st.CommittedAt
			}
			alerts, err := nd.d.Observe(id, o)
			if err != nil {
				nd.st.Refused++
			}
			if r.commitAlerts(ctx, nd, alerts); len(nd.unsent) > 0 {
				return
			}
		}
	}
}

// commitAlerts builds each alert's capture from the first-sight captures
// it cites and commits the alerts, in order, to the alert stream (C13
// section 7.1). A cited frame whose capture the node no longer holds, or
// whose bytes don't hash to the cite, is left out and counted in
// frames_missing (D1 in D4-74). An alert that isn't committed stays unsent
// (flushAlerts). One that can't be built, which no input the detector
// accepts gives, is counted as not stored.
func (r *Runtime) commitAlerts(ctx context.Context, nd *netDetector, alerts []netobs.Alert) {
	if len(alerts) == 0 {
		return
	}
	stream := NetAlertStream(r.cfg.NetworkSensor.SensorID)
	for i := range alerts {
		rec, err := r.alertRecord(ctx, nd, stream, &alerts[i])
		if err != nil {
			r.raiseDetector(nd, AlarmAlertNotStored, "an alert was not built: "+err.Error())
			nd.st.AlertsNotStored++
			continue
		}
		nd.unsent = append(nd.unsent, rec)
		nd.unsentAt = append(nd.unsentAt, unsentAlert{alerts[i].FramesMissing > 0, string(alerts[i].Rule) + "." + alerts[i].AssetID})
	}
	r.flushAlerts(ctx, nd)
}

// flushAlerts commits the unsent alerts, in the order raised, and reports
// whether none is left. An alert the store refuses for its class's quota
// or record cap is dropped and counted by reason and by (rule, asset), as
// C5 0.9 section 8 drops a full class's records, and the detector goes on
// (AP-36 (3)). Any other failure keeps the alert and those after it and is
// counted; the next tick tries again (D1 on #590). Either raises the alarm
// once until an alert commits, so a full class raises it once per stretch
// of drops (D1 on B3).
func (r *Runtime) flushAlerts(ctx context.Context, nd *netDetector) bool {
	if len(nd.unsent) == 0 {
		return true
	}
	if r.appendAlerts(ctx, nd.unsent) == nil {
		r.alertsStored(nd, len(nd.unsent))
		return true
	}
	for len(nd.unsent) > 0 {
		err := r.appendAlerts(ctx, nd.unsent[:1])
		switch {
		case err == nil:
			r.alertsStored(nd, 1)
		case errors.Is(err, &c5.Error{Code: c5.CodeQuotaReached}) || errors.Is(err, &c5.Error{Code: c5.CodeRecordTooLarge}):
			nd.st.AlertsNotStored++
			reason := sensorlink.DropClassFull
			if errors.Is(err, &c5.Error{Code: c5.CodeRecordTooLarge}) {
				reason = sensorlink.DropRecordCap
			}
			r.alertDropped(reason, nd.unsentAt[0].key)
			r.raiseDetector(nd, AlarmAlertNotStored, "alerts are dropped and counted by rule and asset until one commits: "+err.Error())
			nd.unsent, nd.unsentAt = nd.unsent[1:], nd.unsentAt[1:]
		default:
			nd.st.AlertCommitFailures++
			r.raiseDetector(nd, AlarmAlertNotStored, fmt.Sprintf("%d alerts were not committed, so the detector reads nothing more and its cursor stays until they are: %v", len(nd.unsent), err))
			return false
		}
	}
	return true
}

// appendAlerts commits recs to the alert stream in one batch.
func (r *Runtime) appendAlerts(ctx context.Context, recs []c5.Record) error {
	if r.alertAppend != nil {
		return r.alertAppend(recs)
	}
	log := r.Log(NetAlertStream(r.cfg.NetworkSensor.SensorID))
	if log == nil {
		return errors.New("the network database is not open")
	}
	_, err := log.AppendBatch(ctx, recs)
	return err
}

// alertDropped counts an alert the store refused, by reason and by its
// "<rule>.<asset>" key.
func (r *Runtime) alertDropped(reason, key string) {
	in := r.sensor.Load()
	in.mu.Lock()
	in.alerts.reason[reason]++
	in.alerts.asset[key]++
	in.mu.Unlock()
}

// alertsStored counts the first n unsent alerts stored, and re-arms the
// alarm.
func (r *Runtime) alertsStored(nd *netDetector, n int) {
	nd.st.Alerts += int64(n)
	for _, u := range nd.unsentAt[:n] {
		if u.fm {
			nd.st.AlertsFramesMissing++
		}
	}
	nd.unsent, nd.unsentAt = nd.unsent[n:], nd.unsentAt[n:]
	if len(nd.unsent) == 0 {
		nd.unsent, nd.unsentAt = nil, nil
	}
	delete(nd.raised, AlarmAlertNotStored)
}

// alertRecord is a's record, with its capture unless it is
// own-session-unseen, which has none (C13 section 7.1).
func (r *Runtime) alertRecord(ctx context.Context, nd *netDetector, stream c5.StreamID, a *netobs.Alert) (c5.Record, error) {
	var capture *c5.Capture
	if a.Rule != netobs.RuleOwnSessionUnseen {
		c, n, err := r.alertCapture(ctx, nd, a)
		if err != nil {
			return c5.Record{}, err
		}
		capture, a.Capture, a.FramesMissing = c, c.SHA256, n
	}
	h, err := a.Health()
	if err != nil {
		return c5.Record{}, err
	}
	rec, err := r.healthEventRecord(stream, h)
	rec.Capture = capture
	return rec, err
}

// alertCapture is a's capture: its cited frames the node still holds, in
// citation order, in the stored form, and the count of those it doesn't.
func (r *Runtime) alertCapture(ctx context.Context, nd *netDetector, a *netobs.Alert) (*c5.Capture, int64, error) {
	db := r.Store(nd.obs)
	read := map[string][]sensorlink.CaptureFrame{}
	var (
		frames  []sensorlink.CaptureFrame
		missing int64
	)
	for _, ct := range a.Cites {
		for _, f := range ct.Frames {
			ref, ok := nd.index.at[f.SHA256]
			got, done := read[ref]
			if ok && !done {
				if c, err := db.ReadCapture(ctx, ref); err == nil {
					got, _ = sensorlink.ParseCapture(c.Bytes)
				}
				read[ref] = got
			}
			found := false
			for _, cf := range got {
				if sum := sha256.Sum256(cf.Data); hex.EncodeToString(sum[:]) == f.SHA256 {
					frames, found = append(frames, cf), true
					break
				}
			}
			if !found {
				missing++
			}
		}
	}
	c, err := sensorlink.BuildCapture(frames)
	return c, missing, err
}

// checkpointDetector stores the detector's checkpoint, then moves the
// consumer's cursor to its Through, then removes the older checkpoints, as
// identity.read's are (D1 in D4-74). A step that fails keeps the cursor
// where it was and raises the alarm; the next tick tries again.
func (r *Runtime) checkpointDetector(ctx context.Context, nd *netDetector) {
	seq, err := r.storeDetectorCheckpoint(ctx, nd)
	if err != nil {
		nd.st.CheckpointFailures++
		r.raiseDetector(nd, AlarmDetectorCheckpoint, "the detector's checkpoint was not stored, so its cursor stays and a restart resumes from the last one stored: "+err.Error())
		return
	}
	nd.st.CheckpointsWritten++
	nd.written, nd.moved = nd.d.Through(), false
	nd.ckpts = append(nd.ckpts, seq)
	r.saveDetectorCursor(ctx, nd)
}

// storeDetectorCheckpoint stores the detector's checkpoint, which holds
// back the alerts committed after the alert stream's head (D1 in D4-74).
// Item 3's ceiling holds it as it holds the intake's records (D5-c5-0.9
// section 8).
func (r *Runtime) storeDetectorCheckpoint(ctx context.Context, nd *netDetector) (c5.Seq, error) {
	alerts, stream := NetAlertStream(r.cfg.NetworkSensor.SensorID), r.intakeStream()
	adb, log, db := r.Store(alerts), r.Log(stream), r.Store(stream)
	if adb == nil || log == nil || db == nil {
		return 0, errors.New("a database is not open")
	}
	last, err := adb.LastCommitted(ctx, alerts)
	if err != nil {
		return 0, err
	}
	doc, err := nd.d.Checkpoint(uint64(last))
	if err != nil {
		return 0, err
	}
	used, err := db.ClassBytes(ctx, c5.ClassConfiguration)
	if err != nil {
		return 0, err
	}
	if ceiling := r.cfg.Item3Ceiling(); used+int64(len(doc)) > ceiling {
		return 0, fmt.Errorf("a detector checkpoint of %d bytes is over item 3's ceiling (%d of %d bytes used)", len(doc), used, ceiling)
	}
	rc, err := log.Append(ctx, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: doc})
	if err != nil {
		return 0, err
	}
	return rc.Key().Seq, nil
}

// saveDetectorCursor moves the cursor to the last stored checkpoint's
// Through, and then removes the checkpoints older than the newest.
func (r *Runtime) saveDetectorCursor(ctx context.Context, nd *netDetector) {
	if c5.Seq(nd.written) > nd.saved {
		db := r.Store(nd.obs)
		err := errors.New("the network database is not open")
		if db != nil {
			err = db.SaveCursor(ctx, c5.Cursor{Consumer: DetectorConsumer, Stream: nd.obs, Through: c5.Seq(nd.written)})
		}
		if err != nil {
			nd.st.CheckpointFailures++
			r.raiseDetector(nd, AlarmDetectorCheckpoint, "the detector's cursor was not saved, so the observation stream is pruned less and no checkpoint is removed: "+err.Error())
			return
		}
		nd.saved = c5.Seq(nd.written)
	}
	old := nd.ckpts[:len(nd.ckpts)-1]
	for len(old) > 0 {
		step := old[:min(len(old), c5.RemoveConfigStep)]
		db := r.Store(r.intakeStream())
		if db == nil {
			return
		}
		if _, err := db.RemoveConfig(ctx, r.intakeStream(), c5.SeriesNetCheckpointDetector, step); err != nil {
			r.raiseDetector(nd, AlarmDetectorCheckpoint, fmt.Sprintf("older detector checkpoints %v not removed, so they stay in the configuration class: %v", step, err))
			return
		}
		old = old[len(step):]
		nd.ckpts = nd.ckpts[len(step):]
	}
	delete(nd.raised, AlarmDetectorCheckpoint)
}

// raiseDetector raises code once until it clears.
func (r *Runtime) raiseDetector(nd *netDetector, code, detail string) {
	if nd.raised[code] {
		return
	}
	nd.raised[code] = true
	r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: c5.AlarmCode(code), At: r.opt.Now(), Stream: nd.obs, Detail: detail})
}

// detectorStatus sets the detector's counts, and raises the mismatch and
// ordering alarms when their counts rise.
func (r *Runtime) detectorStatus(nd *netDetector) {
	d := nd.d
	if n := d.Mismatches(); n > nd.st.Mismatches {
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmDetectorMismatch, At: r.opt.Now(), Stream: nd.obs,
			Detail: fmt.Sprintf("%d departures of a restore's replay from the alerts already committed", n)})
	}
	if n := d.OrderingFaults(); n > nd.st.OrderingFaults {
		delete(nd.raised, AlarmDetectorOrdering)
	}
	for _, x := range []struct {
		reason, why string
		n           int64
	}{{"pending-full", fmt.Sprintf("past %d sessions pending", netobs.MaxPendingSessions), d.PendingFull()},
		{"tied-evicted", fmt.Sprintf("whose tied flows were dropped past %d", netobs.MaxTiedSessions), d.TiedEvicted()}} {
		if x.n > nd.st.NotJudged[x.reason] {
			r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmSessionNotJudged, At: r.opt.Now(), Stream: nd.obs,
				Detail: fmt.Sprintf("%d of the node's own sessions not judged since start (%s), %s", x.n, x.reason, x.why)})
		}
	}
	r.intake.mu.Lock()
	missing := int64(r.intake.sessionMissing)
	r.intake.mu.Unlock()
	nd.st.Through, nd.st.Checkpointed, nd.st.Restored, nd.st.AlertsPending = d.Through(), nd.written, nd.restored, len(nd.unsent)
	nd.st.NotJudged = map[string]int64{"pending-full": d.PendingFull(), "tied-evicted": d.TiedEvicted(), "before-retained": d.BeforeRetained(), "session-missing": missing}
	nd.st.OpenFlowSeen, nd.st.EarlyCloses, nd.st.Mismatches, nd.st.OrderingFaults = d.OpenFlowSeen(), d.EarlyCloses(), d.Mismatches(), d.OrderingFaults()
	if h := (r.opt.Mono() - nd.start).Hours(); h > 0 {
		nd.st.EarlyClosesPerHour = float64(nd.st.EarlyCloses) / h
	}
	nd.st.NotYetSeen = nil
	for _, e := range d.NotYetSeen() {
		nd.st.NotYetSeen = append(nd.st.NotYetSeen, e.AssetID+" "+e.L4+" "+e.Addr+":"+strconv.Itoa(e.Port))
	}
	slices.Sort(nd.st.NotYetSeen)
}

// checkDetectorRecord is ConfigDocuments' check of a network checkpoint:
// only the detector's half is stored, as working state in its series.
func checkDetectorRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	if capture != nil {
		return c5.DocumentInfo{}, errors.New("configuration document: a detector checkpoint has no capture")
	}
	if _, err := netobs.DecodeDetectorCheckpoint(document); err != nil {
		return c5.DocumentInfo{}, err
	}
	return c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesNetCheckpointDetector}, nil
}
