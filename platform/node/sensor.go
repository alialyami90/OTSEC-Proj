package node

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/sensorlink"
)

// The sensor's intake in the runtime (P4-4-B5 deliverable 2,
// docs/phase4/D5-sensor-node.md sections 2 and 6). The transport waits for
// ADR-0009, so the channel reaches the node through ServeSensor, over any
// byte stream with C13's framing.

// AlarmSensorRecordRefused: the node refused a record from the sensor. It
// is raised once for each reason in a node run, and status counts every
// refused record under its reason (D5-sensor-node.md section 2).
const AlarmSensorRecordRefused = "sensor-record-refused"

// AlarmSensorUnreachable: no heartbeat was accepted for SensorUnreachableAfter
// of the node's monotonic time since the later of the last one and the
// node's start. A connect never resets it, so a sensor that reconnects
// again and again without a heartbeat accepted still raises it (D3's S1,
// D1 in D4-73). It is raised once per such stretch, and status shows the
// sensor unreachable until the next accepted heartbeat (D5-sensor-node.md
// section 2). The node's own clock times it, so a step of the wall clock
// or of the sensor's moves nothing. It is raised at the first Tick at or
// after 60 s of quiet, so at most 60 s + TickInterval (<= 120 s today)
// after the last heartbeat or the start (D1 on #581).
const AlarmSensorUnreachable = "sensor-unreachable"

// SensorUnreachableAfter is six of the sensor's 10 s heartbeats.
const SensorUnreachableAfter = 60 * time.Second

// SensorDropReportEvery is how often, at most, the node writes the
// observation class's drop counts as an intake.drop-counted event, and only
// when they changed (D5-c5-0.9.md section 4).
const SensorDropReportEvery = time.Minute

// SensorDropDetailAssets is the most assets the intake.drop-counted event
// names. The rest are summed in one asset.other detail, so the asset
// details still sum to count. It bounds the event: with every reason and
// every value at its widest, the event renders in under three quarters of
// a default Syslog target's 2048 octets (syslog.DefaultMaxOctets), and a
// health event a target cannot render stops the health stream's forwarding
// (TestSensorDropEventFits).
const SensorDropDetailAssets = 8

// sensorDropOther is the asset key of the summed detail, asset.other. No
// asset ID is "other": they are UUIDs or asset-unresolved.
const sensorDropOther = "other"

// sensorDropScanRecords bounds how far back a start reads platform/health
// for the last drop counts. The node writes them at a clean stop, and a
// crash loses at most the last minute's, so they are near the end; past
// the bound the counts start from zero, and status says from when.
const sensorDropScanRecords = 2000

// SensorStatus is the sensor section of status. Nothing in it is device
// text or packet bytes: the IDs are checked UUIDs and asset IDs, the
// reasons are the node's own codes, and the counters are numbers.
type SensorStatus struct {
	SensorID  string `json:"sensor_id"`
	Connected bool   `json:"connected"`
	// The channel as the link reads it (sensorlink.Stats).
	RunID            string            `json:"run_id,omitempty"`
	LastSeq          uint64            `json:"last_seq"`
	LastCommittedSeq uint64            `json:"last_committed_seq"`
	RunChanges       uint64            `json:"run_changes"`
	SeqGaps          uint64            `json:"seq_gaps"`
	FramesTooLarge   uint64            `json:"frames_too_large"`
	Committed        uint64            `json:"committed"`
	Refused          map[string]uint64 `json:"refused,omitempty"`
	// Dropped and DroppedByAsset are the dropped observations by reason
	// and by destination asset since DropsSince, which a restart keeps
	// from the last intake.drop-counted event (D5-c5-0.9.md section 4).
	// DropsWritten is when they were last written; a crash loses what
	// changed after it.
	Dropped        map[string]uint64 `json:"dropped,omitempty"`
	DroppedByAsset map[string]uint64 `json:"dropped_by_asset,omitempty"`
	DropsSince     time.Time         `json:"drops_since,omitzero"`
	DropsWritten   time.Time         `json:"drops_written,omitzero"`
	// AlertsDropped and AlertsDroppedBy are the alerts the store refused,
	// beside network-full, by reason and by "<rule>.<asset>", with one
	// asset, asset-unresolved, for every unresolved destination, since
	// AlertDropsSince, which a restart keeps as it keeps Dropped (AP-36
	// (3), D5-c5-0.9.md section 4). After a restart a pair the last event
	// summed is in "other".
	AlertsDropped     map[string]uint64 `json:"alerts_dropped,omitempty"`
	AlertsDroppedBy   map[string]uint64 `json:"alerts_dropped_by_rule_asset,omitempty"`
	AlertDropsSince   time.Time         `json:"alert_drops_since,omitzero"`
	AlertDropsWritten time.Time         `json:"alert_drops_written,omitzero"`
	// Unreachable: no heartbeat accepted for SensorUnreachableAfter, as
	// AlarmSensorUnreachable says; it clears at the next accepted one.
	Unreachable bool `json:"unreachable"`
	// Hold is the intake hold's counts since start (D4-72). Repaired and
	// RepairRefused are the start repair's runs: a release whose
	// collection.run it wrote, and one it refused for want of an allowed
	// collector.request.
	Hold          sensorlink.HoldStats `json:"hold"`
	Repaired      uint64               `json:"runs_repaired"`
	RepairRefused uint64               `json:"runs_repair_refused"`
	// SessionMissing counts the runs the hold watched whose collection.run
	// has no session: the dispatch's record was not saved, or the result
	// could not be released (D1 in D4-74).
	SessionMissing uint64 `json:"runs_session_missing"`
	// Detector is the detector consumer's part, nil until it starts
	// (netdetector.go).
	Detector *DetectorStatus `json:"detector,omitempty"`
	// Heartbeat is the last heartbeat of the run: the sensor's own
	// report of its totals and time, which the node checks only for
	// monotonic counters (C13 section 6, AP-36 (2)).
	Heartbeat *SensorHeartbeat `json:"heartbeat,omitempty"`
	// DispatchTimeouts and ResultTimeouts count the scheduler calls on
	// the link that did not have its lock within sensorlink.HoldLockWait,
	// or panicked, so their run went on untied; LockWaitMaxMS is the
	// longest any of them waited (section 1.9 items 4 and 9).
	DispatchTimeouts uint64 `json:"dispatch_timeouts"`
	ResultTimeouts   uint64 `json:"result_timeouts"`
	LockWaitMaxMS    int64  `json:"lock_wait_max_ms"`
	// HealthHeld counts the ceiling's refusals of the sensor's health
	// events since start, not the events: an event tried again, as a
	// forwarder's owed report or a drop count is, is counted at each try
	// (section 1.9 item 5; D4's N2 on #676).
	HealthHeld uint64 `json:"health_held"`
}

// AlarmNetworkSessionNotTied: a scheduler call on the link timed out or
// panicked, so a run's session was not tied: its flows commit untied and
// the base rules judge them (D3's condition). It is raised once for each
// stretch of ticks in which dispatch_timeouts or result_timeouts rises.
const AlarmNetworkSessionNotTied = "network-session-not-tied"

// SensorHeartbeat is the part of a heartbeat status shows.
type SensorHeartbeat struct {
	AtUTC          string          `json:"at_utc"`
	Counters       netobs.Counters `json:"counters"`
	RingOldestUTC  string          `json:"ring_oldest_utc,omitempty"`
	InterfaceCheck string          `json:"interface_check"`
}

// SetSensor records the sensor section.
func (s *Status) SetSensor(n *SensorStatus) {
	s.mu.Lock()
	s.sensor = n
	s.mu.Unlock()
}

// sensorIntake is the runtime's side of the link: the drop counts kept
// across a restart, and what status shows.
type sensorIntake struct {
	link   *sensorlink.Link
	stream c5.StreamID

	mu        sync.Mutex
	connected int
	// base is the counts restored at start, which the link's own add to.
	base dropCounts
	// alerts are the alerts the store refused, by reason and by
	// "<rule>.<asset>", since alert.since: those restored at start and
	// the detector's since (netdetector.go, AP-36 (3)).
	alerts dropCounts
	// obs and alert are the two classes' intake.drop-counted reports.
	obs, alert dropReport
	refused    map[string]bool // reasons whose alarm is raised
	// The sensor-unreachable timer: quietFrom is the monotonic time of the
	// last accepted heartbeat, or of the start before the first;
	// heartbeats is the link's count last seen.
	quietFrom   time.Duration
	heartbeats  uint64
	unreachable bool // status shows it, until a heartbeat
	raised      bool // the alarm for this quiet stretch is raised
	// checkpointFailures is the hold's count the last alarm was raised at.
	checkpointFailures uint64
	// detectorDown: the detector consumer did not start, and its alarm is
	// raised; each tick tries again (netdetector.go).
	detectorDown bool
}

// dropCounts are dropped records by reason and by destination asset, or
// for alerts by "<rule>.<asset>".
type dropCounts struct{ reason, asset map[string]uint64 }

// dropReport is a class's drop counts as its intake.drop-counted events
// keep them: since is when the counts began, which a restart keeps from
// the last event; written is the counts that event carried and writtenAt
// its node time; triedMono is the monotonic time of the last write, or of
// the last failed one.
type dropReport struct {
	stream    c5.StreamID
	since     time.Time
	written   dropCounts
	writtenAt time.Time
	triedMono time.Duration
	everTried bool
}

func (d dropCounts) equal(o dropCounts) bool {
	return maps.Equal(d.reason, o.reason) && maps.Equal(d.asset, o.asset)
}

func (d dropCounts) total() (n uint64) {
	for _, v := range d.reason {
		n += v
	}
	return n
}

// startSensor makes the link when the configuration has the section, and
// restores the drop counts from the last intake.drop-counted event.
func (r *Runtime) startSensor(ctx context.Context) error {
	s := r.cfg.NetworkSensor
	if s == nil {
		return nil
	}
	stream := NetObservationStream(s.SensorID)
	restore, err := r.loadIntake(ctx)
	if err != nil {
		return fmt.Errorf("the intake hold's records: %w", err)
	}
	hold := sensorlink.HoldConfig{NodeAddrs: s.NodeAddrs(), TieGrace: netobs.DefaultTieGraceS * time.Second,
		Now: r.opt.Now, Save: r.saveIntake, Restore: restore}
	link, err := sensorlink.New(sensorlink.Config{NodeID: r.cfg.NodeID, SensorID: s.SensorID, EvidenceClass: s.EvidenceClass,
		OutageHours: s.OutageHours, ObservationQuota: r.cfg.Store.Quotas[string(c5.ClassNetworkObservation)], Stream: stream},
		sensorlink.Options{Assets: r.cfg.AssetRecords(), Store: liveAppender{r, stream}, Monotonic: r.opt.Mono, Received: r.received, Hold: hold})
	if err != nil {
		return err
	}
	now := r.opt.Now().UTC()
	in := &sensorIntake{link: link, stream: stream, refused: map[string]bool{}, quietFrom: r.startMono,
		base: dropCounts{map[string]uint64{}, map[string]uint64{}}, alerts: dropCounts{map[string]uint64{}, map[string]uint64{}},
		obs: dropReport{stream: stream, since: now}, alert: dropReport{stream: NetAlertStream(s.SensorID), since: now}}
	if d, at, ok := r.lastDropCounts(ctx, stream); ok {
		in.base, in.obs.since = d, at
	}
	if d, at, ok := r.lastDropCounts(ctx, in.alert.stream); ok {
		in.alerts, in.alert.since = d, at
	}
	in.obs.written, in.alert.written = in.base, dropCounts{maps.Clone(in.alerts.reason), maps.Clone(in.alerts.asset)}
	// A release a restart interrupted commits once, and a release whose
	// collection.run never committed gets one, before the sensor is
	// served. The next tick then gives way the holds whose deadlines
	// passed while the node was down (D3 on #576, D1 in D4-72). The intake
	// is published only once its hold is recovered and repaired, so a
	// failed start leaves nothing half started, and no tick works on the
	// intake while the manager repairs it.
	if err := link.RecoverHold(ctx); err != nil {
		return fmt.Errorf("the intake hold's recovery: %w", err)
	}
	r.repairIntake(ctx)
	r.pruneIntake(ctx, "")
	r.sensor.Store(in)
	return nil
}

// AlarmSensorIntakeNotStarted: the sensor's intake did not start, so
// nothing is taken from the sensor and no run is held for it. The node
// starts and collects without it, and the sensor manager tries again at
// each tick (F2, D5-sensor-node.md section 1.9 item 2). It is raised once
// for each stretch in which the intake is not started.
const AlarmSensorIntakeNotStarted = "sensor-intake-not-started"

// startIntake starts the intake when the section is set and it has not
// started. It does not start while the observation stream's database is
// not open or accepts no events, since C5 says no new events are taken in
// such a mode (the store itself would commit them), and raises
// AlarmSensorIntakeNotStarted when it fails. Only the sensor manager's
// step calls it.
func (r *Runtime) startIntake(ctx context.Context) {
	s := r.cfg.NetworkSensor
	if s == nil || r.sensor.Load() != nil {
		return
	}
	m := r.smgr
	// No refusal at load: below the platform floor the node starts and
	// collects, and the sensor is not started (section 1.9 item 5).
	if short, why := r.cfg.platformFloorShort(); short {
		if !m.floorShort {
			m.floorShort = true
			r.opt.Status.Raise("", AlarmSensorPlatformFloor, why)
		}
		return
	}
	err := errors.New("the network database is not open")
	if db, _, mode := r.view(r.dbFor(NetObservationStream(s.SensorID))); db != nil && !mode.AcceptsEvents() {
		err = fmt.Errorf("the network database is %s", mode)
	} else if db != nil {
		err = r.startSensor(ctx)
	}
	if err != nil {
		if !m.intakeDown {
			r.opt.Status.Raise("", AlarmSensorIntakeNotStarted, "the sensor's intake did not start, so nothing is taken from the sensor; the node collects without it and tries again at each tick: "+err.Error())
		}
		m.intakeDown = true
		return
	}
	m.intakeDown = false
}

// liveAppender appends to stream through the Log of its database as it is
// now, so a database that the manager reopens is picked up. It appends
// nothing while the database is in a mode that accepts no new events, such
// as drain-only after a retry, or after sensor-failed: the link drops and
// counts the record (D6's item 3 on #663).
type liveAppender struct {
	r      *Runtime
	stream c5.StreamID
}

func (a liveAppender) log(ctx context.Context) (*c5.Log, error) {
	if f := a.r.opt.SensorSeams.Append; f != nil {
		f(ctx)
	}
	if a.r.sensorFailed.Load() {
		return nil, errors.New("node: the sensor's work has failed")
	}
	_, log, mode := a.r.view(a.r.dbFor(a.stream))
	if log == nil {
		return nil, errors.New("node: the network database is not open")
	}
	if !mode.AcceptsEvents() {
		return nil, fmt.Errorf("node: the network database is %s, which accepts no new events", mode)
	}
	return log, nil
}

func (a liveAppender) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	log, err := a.log(ctx)
	if err != nil {
		return nil, err
	}
	return log.Append(ctx, rec)
}

func (a liveAppender) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	log, err := a.log(ctx)
	if err != nil {
		return nil, err
	}
	return log.AppendBatch(ctx, recs)
}

// LastCommitted is the stream's last committed seq.
func (a liveAppender) LastCommitted(ctx context.Context) (uint64, error) {
	db := a.r.Store(a.stream)
	if db == nil {
		return 0, errors.New("node: the network database is not open")
	}
	return db.LastCommitted(ctx, a.stream)
}

// ServeSensor reads one connection of the sensor's channel until it ends
// (sensorlink.Link.Serve). The caller authenticates the stream's peer as
// the configured sensor (ADR-0009, TB6); the records' sensor_id only
// refuses a misrouted stream. It returns an error when the configuration has
// no network_sensor section, or while the intake is not started. Status
// shows the link connected while it runs.
func (r *Runtime) ServeSensor(ctx context.Context, rd io.Reader) error {
	in := r.sensor.Load()
	if in == nil || r.sensorFailed.Load() {
		if r.cfg.NetworkSensor != nil {
			return errors.New("node: the sensor's intake is not started, or the sensor's work has failed")
		}
		return errors.New("node: no network_sensor section")
	}
	in.mu.Lock()
	in.connected++
	in.mu.Unlock()
	defer func() {
		in.mu.Lock()
		in.connected--
		in.mu.Unlock()
	}()
	return in.link.Serve(ctx, rd)
}

// counts are the drop counts now: those restored at start plus the link's.
func (in *sensorIntake) counts(st sensorlink.Stats) dropCounts {
	d := dropCounts{maps.Clone(in.base.reason), maps.Clone(in.base.asset)}
	for k, v := range st.Dropped {
		d.reason[k] += v
	}
	for k, v := range st.DroppedByAsset {
		d.asset[k] += v
	}
	return d
}

// tickSensor writes the drop counts when they changed, at most once every
// SensorDropReportEvery unless final, raises sensor-record-refused for a
// new reason, and sets the sensor section. final is the clean stop's call.
// A write that fails raises store-commit-failed on the health stream's
// database, as Runtime.health does, and is tried again a minute later; one
// past the platform class's ceiling is counted in health_held and tried
// again a minute later. Only the sensor manager's goroutine calls it, at
// each step Tick asks for and at its stop. It reports whether the
// detector's drive stopped at its bound, with more to read.
func (r *Runtime) tickSensor(ctx context.Context, final bool) (more bool) {
	in := r.sensor.Load()
	if in == nil || r.sensorFailed.Load() {
		return false
	}
	in.link.TickHold(ctx)
	r.pruneIntake(ctx, "")
	if r.detector == nil {
		// After the intake's start repair, so the sessions it wrote are
		// on the health stream when the detector replays them (D4-72).
		if err := r.startDetector(ctx); err != nil {
			if !in.detectorDown {
				r.opt.Status.Raise("", AlarmDetectorNotStarted, "the network detector did not start, so no alert is raised and the observation stream is not pruned: "+err.Error())
			}
			in.detectorDown = true
		} else {
			in.detectorDown = false
		}
	}
	more = r.tickDetector(ctx)
	st := in.link.Stats()
	r.notTied(st)
	in.mu.Lock()
	defer in.mu.Unlock()
	now := in.counts(st)
	m := r.opt.Mono()
	r.reportDrops(ctx, &in.obs, now, final, func() map[string]string { return dropDetails(in.stream, in.obs.since, now) })
	r.reportDrops(ctx, &in.alert, in.alerts, final, func() map[string]string { return alertDropDetails(in.alert.stream, in.alert.since, in.alerts) })
	if st.Heartbeats != in.heartbeats {
		in.heartbeats, in.quietFrom, in.raised, in.unreachable = st.Heartbeats, max(in.quietFrom, st.HeartbeatMono), false, false
	}
	if !in.raised && m-in.quietFrom >= SensorUnreachableAfter {
		in.raised, in.unreachable = true, true
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmSensorUnreachable, At: r.opt.Now(), Stream: in.stream,
			Detail: fmt.Sprintf("no heartbeat from the sensor for %s; the network is not watched while it lasts", SensorUnreachableAfter)})
	}
	if n := st.Hold.CheckpointFailures; n > in.checkpointFailures {
		in.checkpointFailures = n
		r.opt.Status.Alarm(ConfigDB, c5.Alarm{Code: AlarmIntakeCheckpointFailed, At: r.opt.Now(), Stream: r.intakeStream(),
			Detail: fmt.Sprintf("%d intake hold records not saved since start, so their flows committed untied", n)})
	}
	for _, reason := range slices.Sorted(maps.Keys(st.Refused)) {
		if in.refused[reason] {
			continue
		}
		in.refused[reason] = true
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmSensorRecordRefused, At: r.opt.Now(), Stream: in.stream,
			Detail: fmt.Sprintf("the sensor sent a record the node refused (%s); every refused record is counted in status", reason)})
	}
	s := &SensorStatus{SensorID: r.cfg.NetworkSensor.SensorID, Connected: in.connected > 0, RunID: st.RunID, LastSeq: st.LastSeq,
		LastCommittedSeq: st.LastCommittedSeq, RunChanges: st.RunChanges, SeqGaps: st.SeqGaps, FramesTooLarge: st.FramesTooLarge,
		Committed: st.Committed, Refused: st.Refused, Unreachable: in.unreachable, Hold: st.Hold, Dropped: now.reason, DroppedByAsset: now.asset, DropsSince: in.obs.since, DropsWritten: in.obs.writtenAt,
		AlertsDropped: maps.Clone(in.alerts.reason), AlertsDroppedBy: maps.Clone(in.alerts.asset), AlertDropsSince: in.alert.since, AlertDropsWritten: in.alert.writtenAt}
	r.intake.mu.Lock()
	s.Repaired, s.RepairRefused, s.SessionMissing = r.intake.repaired, r.intake.repairRefused, r.intake.sessionMissing
	r.intake.mu.Unlock()
	if nd := r.detector; nd != nil {
		d := nd.st
		s.Detector = &d
	}
	if h := st.Heartbeat; h != nil {
		s.Heartbeat = &SensorHeartbeat{AtUTC: h.AtUTC, Counters: h.Counters, RingOldestUTC: h.RingOldestUTC, InterfaceCheck: h.InterfaceCheck}
	}
	s.DispatchTimeouts, s.ResultTimeouts, s.LockWaitMaxMS = st.DispatchTimeouts, st.ResultTimeouts, st.LockWaitMax.Milliseconds()
	s.HealthHeld = r.sensorHeld.Load()
	r.opt.Status.SetSensor(s)
	return more
}

// notTied raises AlarmNetworkSessionNotTied once for each stretch of
// steps in which the scheduler calls' timeouts rise.
func (r *Runtime) notTied(st sensorlink.Stats) {
	m := r.smgr
	n := st.DispatchTimeouts + st.ResultTimeouts
	switch {
	case n > m.timeouts && !m.notTied:
		m.notTied = true
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmNetworkSessionNotTied, At: r.opt.Now(), Stream: NetObservationStream(r.sensorID()),
			Detail: fmt.Sprintf("%d scheduler calls on the sensor link since start (%d dispatches, %d results) did not have its lock within %s or panicked, so their runs' flows commit untied and the base rules judge them",
				n, st.DispatchTimeouts, st.ResultTimeouts, sensorlink.HoldLockWait)})
	case n == m.timeouts:
		m.notTied = false
	}
	m.timeouts = n
}

// driveSensor is a drive of the detector between the steps Tick asks for
// (section 1.9 item 3). It reports whether the drive stopped at its bound.
func (r *Runtime) driveSensor(ctx context.Context) bool {
	if r.sensor.Load() == nil || r.detector == nil {
		return false
	}
	return r.driveOnce(ctx, r.detector)
}

// reportDrops writes now as rep's intake.drop-counted event when it
// changed since the last write, at most once every SensorDropReportEvery
// unless final. A write that fails raises store-commit-failed on the
// health stream's database, as Runtime.health does, and is tried again a
// minute later.
func (r *Runtime) reportDrops(ctx context.Context, rep *dropReport, now dropCounts, final bool, details func() map[string]string) {
	m := r.opt.Mono()
	if now.equal(rep.written) || !(final || !rep.everTried || m-rep.triedMono >= SensorDropReportEvery) {
		return
	}
	at := r.opt.Now().UTC()
	rep.triedMono, rep.everTried = m, true
	if _, err := r.sensorHealth(ctx, event.Health{Type: event.HealthDropCounted, Details: details()}); errors.Is(err, errPastCeiling) {
		return // held: the counts are written once room returns
	} else if err != nil {
		var db c5.DatabaseID
		if d := r.dbFor(HealthStream); d != nil {
			db = d.spec.ID
		}
		r.opt.Status.Alarm(db, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: HealthStream,
			Detail: "health event " + event.HealthDropCounted + " for " + string(rep.stream) + ": " + err.Error()})
	} else {
		rep.written, rep.writtenAt = dropCounts{maps.Clone(now.reason), maps.Clone(now.asset)}, at
	}
}

// dropDetails is the intake.drop-counted event's details: the totals since
// since, by reason ("reason.<r>") and by destination asset ("asset.<id>"),
// and their sum ("count"). It names the SensorDropDetailAssets assets with
// the most drops (ties by ID) and sums the rest in asset.other.
func dropDetails(stream c5.StreamID, since time.Time, d dropCounts) map[string]string {
	return countDetails(stream, c5.ClassNetworkObservation, "asset.", since, d, func(string) int { return 0 })
}

// alertDropDetails is the alert class's intake.drop-counted details, as
// dropDetails but by "<rule>.<asset>", with no prefix: a detail key is at
// most 64 characters, and the longest rule and an asset ID take 63. The
// rest are summed in "other". The pairs of an enrolled asset are named
// before the unresolved buckets, then by the most drops, so decoys to
// unresolved addresses never push an enrolled asset's drop into other (D1
// on B3).
func alertDropDetails(stream c5.StreamID, since time.Time, d dropCounts) map[string]string {
	return countDetails(stream, c5.ClassNetworkAlert, "", since, d, func(key string) int {
		if strings.HasSuffix(key, "."+netobs.AssetUnresolved) {
			return 1
		}
		return 0
	})
}

// countDetails names, under prefix, the SensorDropDetailAssets keys of
// d.asset first by group, then with the most drops (ties by key), and
// sums the rest in <prefix>other.
func countDetails(stream c5.StreamID, class c5.StreamClass, prefix string, since time.Time, d dropCounts, group func(string) int) map[string]string {
	out := map[string]string{"stream": string(stream), "class": string(class),
		"since": since.Format(time.RFC3339Nano), "count": strconv.FormatUint(d.total(), 10)}
	for k, v := range d.reason {
		out["reason."+k] = strconv.FormatUint(v, 10)
	}
	ids := slices.Collect(maps.Keys(d.asset))
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == sensorDropOther })
	slices.SortFunc(ids, func(a, b string) int {
		if c := cmp.Compare(group(a), group(b)); c != 0 {
			return c
		}
		if c := cmp.Compare(d.asset[b], d.asset[a]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	other := d.asset[sensorDropOther]
	for i, id := range ids {
		if i < SensorDropDetailAssets {
			out[prefix+id] = strconv.FormatUint(d.asset[id], 10)
		} else {
			other += d.asset[id]
		}
	}
	if other > 0 {
		out[prefix+sensorDropOther] = strconv.FormatUint(other, 10)
	}
	return out
}

// lastDropCounts reads platform/health newest first, at most
// sensorDropScanRecords back, for the stream's last intake.drop-counted
// event, and returns its counts and since.
func (r *Runtime) lastDropCounts(ctx context.Context, stream c5.StreamID) (dropCounts, time.Time, bool) {
	db := r.Store(HealthStream)
	if db == nil {
		return dropCounts{}, time.Time{}, false
	}
	last, err := db.LastCommitted(ctx, HealthStream)
	if err != nil {
		return dropCounts{}, time.Time{}, false
	}
	first, err := db.FirstRetained(ctx, HealthStream)
	if err != nil || first == 0 {
		return dropCounts{}, time.Time{}, false
	}
	const page = 500
	for hi, read := last, 0; hi >= first && read < sensorDropScanRecords; {
		lo := first - 1
		if hi-lo > page {
			lo = hi - page
		}
		got, err := db.Read(ctx, HealthStream, lo, int(hi-lo))
		if err != nil {
			return dropCounts{}, time.Time{}, false
		}
		read += len(got)
		for i := len(got) - 1; i >= 0; i-- {
			if d, at, ok := parseDropCounts(got[i].Event, stream); ok {
				return d, at, true
			}
		}
		hi = lo
	}
	return dropCounts{}, time.Time{}, false
}

// parseDropCounts reads an event the node wrote with dropDetails or
// alertDropDetails for stream; anything else is not one. It trusts every
// reason.* and asset.* detail, or for the alert class every
// "<rule>.<asset>" and "other" detail, it can parse because only the node
// writes this type for a sensor stream on platform/health; asset.other
// comes back as the key "other".
func parseDropCounts(b []byte, stream c5.StreamID) (dropCounts, time.Time, bool) {
	if !strings.Contains(string(b), `"`+event.HealthDropCounted+`"`) {
		return dropCounts{}, time.Time{}, false
	}
	var e struct {
		Health *event.Health `json:"health"`
	}
	if json.Unmarshal(b, &e) != nil || e.Health == nil || e.Health.Type != event.HealthDropCounted ||
		e.Health.Details["stream"] != string(stream) {
		return dropCounts{}, time.Time{}, false
	}
	since, err := time.Parse(time.RFC3339Nano, e.Health.Details["since"])
	if err != nil {
		return dropCounts{}, time.Time{}, false
	}
	d := dropCounts{map[string]uint64{}, map[string]uint64{}}
	alert := e.Health.Details["class"] == string(c5.ClassNetworkAlert)
	for k, v := range e.Health.Details {
		n, err := strconv.ParseUint(v, 10, 64)
		switch {
		case err != nil || k == "count":
		case strings.HasPrefix(k, "reason."):
			d.reason[strings.TrimPrefix(k, "reason.")] = n
		case !alert && strings.HasPrefix(k, "asset."):
			d.asset[strings.TrimPrefix(k, "asset.")] = n
		case alert && (k == sensorDropOther || strings.Contains(k, ".")):
			d.asset[k] = n // alertDropDetails's "<rule>.<asset>" or "other"
		}
	}
	return d, since, true
}
