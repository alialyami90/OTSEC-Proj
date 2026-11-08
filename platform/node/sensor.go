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
// or of the sensor's moves nothing.
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
	// Unreachable: no heartbeat accepted for SensorUnreachableAfter, as
	// AlarmSensorUnreachable says; it clears at the next accepted one.
	Unreachable bool `json:"unreachable"`
	// Heartbeat is the last heartbeat of the run: the sensor's own
	// report of its totals and time, which the node checks only for
	// monotonic counters (C13 section 6, AP-36 (2)).
	Heartbeat *SensorHeartbeat `json:"heartbeat,omitempty"`
}

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
	base  dropCounts
	since time.Time
	// written is the counts the last event carried and writtenAt its node
	// time; triedMono is the monotonic time of the last write, or of the
	// last failed one.
	written   dropCounts
	writtenAt time.Time
	triedMono time.Duration
	everTried bool
	refused   map[string]bool // reasons whose alarm is raised
	// The sensor-unreachable timer: quietFrom is the monotonic time of the
	// last accepted heartbeat, or of the start before the first;
	// heartbeats is the link's count last seen.
	quietFrom   time.Duration
	heartbeats  uint64
	unreachable bool // status shows it, until a heartbeat
	raised      bool // the alarm for this quiet stretch is raised
}

// dropCounts are dropped observations by reason and by destination asset.
type dropCounts struct{ reason, asset map[string]uint64 }

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
	link, err := sensorlink.New(sensorlink.Config{NodeID: r.cfg.NodeID, SensorID: s.SensorID, EvidenceClass: s.EvidenceClass,
		OutageHours: s.OutageHours, ObservationQuota: r.cfg.Store.Quotas[string(c5.ClassNetworkObservation)], Stream: stream},
		sensorlink.Options{Assets: r.cfg.AssetRecords(), Store: liveAppender{r, stream}, Monotonic: r.opt.Mono, Received: r.received})
	if err != nil {
		return err
	}
	in := &sensorIntake{link: link, stream: stream, since: r.opt.Now().UTC(), refused: map[string]bool{}, quietFrom: r.opt.Mono(),
		base: dropCounts{map[string]uint64{}, map[string]uint64{}}}
	if d, at, ok := r.lastDropCounts(ctx, stream); ok {
		in.base, in.since = d, at
	}
	in.written = in.base
	r.sensor = in
	return nil
}

// liveAppender appends to stream through the Log of its database as it is
// now, so a database that Tick reopens is picked up.
type liveAppender struct {
	r      *Runtime
	stream c5.StreamID
}

func (a liveAppender) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	log := a.r.Log(a.stream)
	if log == nil {
		return nil, errors.New("node: the network database is not open")
	}
	return log.Append(ctx, rec)
}

func (a liveAppender) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	log := a.r.Log(a.stream)
	if log == nil {
		return nil, errors.New("node: the network database is not open")
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
// no network_sensor section. Status shows the link connected while it runs.
func (r *Runtime) ServeSensor(ctx context.Context, rd io.Reader) error {
	in := r.sensor
	if in == nil {
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
// database, as Runtime.health does, and is tried again a minute later.
func (r *Runtime) tickSensor(ctx context.Context, final bool) {
	in := r.sensor
	if in == nil {
		return
	}
	st := in.link.Stats()
	in.mu.Lock()
	defer in.mu.Unlock()
	now := in.counts(st)
	m := r.opt.Mono()
	if !now.equal(in.written) && (final || !in.everTried || m-in.triedMono >= SensorDropReportEvery) {
		at := r.opt.Now().UTC()
		in.triedMono, in.everTried = m, true
		if _, err := (healthSink{r}).Emit(ctx, event.Health{Type: event.HealthDropCounted, Details: dropDetails(in.stream, in.since, now)}); err != nil {
			var db c5.DatabaseID
			if d := r.dbFor(HealthStream); d != nil {
				db = d.spec.ID
			}
			r.opt.Status.Alarm(db, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: HealthStream,
				Detail: "health event " + event.HealthDropCounted + " for " + string(in.stream) + ": " + err.Error()})
		} else {
			in.written, in.writtenAt = now, at
		}
	}
	if st.Heartbeats != in.heartbeats {
		in.heartbeats, in.quietFrom, in.raised, in.unreachable = st.Heartbeats, max(in.quietFrom, st.HeartbeatMono), false, false
	}
	if !in.raised && m-in.quietFrom >= SensorUnreachableAfter {
		in.raised, in.unreachable = true, true
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmSensorUnreachable, At: r.opt.Now(), Stream: in.stream,
			Detail: fmt.Sprintf("no heartbeat from the sensor for %s; the network is not watched while it lasts", SensorUnreachableAfter)})
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
		Committed: st.Committed, Refused: st.Refused, Unreachable: in.unreachable, Dropped: now.reason, DroppedByAsset: now.asset, DropsSince: in.since, DropsWritten: in.writtenAt}
	if h := st.Heartbeat; h != nil {
		s.Heartbeat = &SensorHeartbeat{AtUTC: h.AtUTC, Counters: h.Counters, RingOldestUTC: h.RingOldestUTC, InterfaceCheck: h.InterfaceCheck}
	}
	r.opt.Status.SetSensor(s)
}

// dropDetails is the intake.drop-counted event's details: the totals since
// since, by reason ("reason.<r>") and by destination asset ("asset.<id>"),
// and their sum ("count"). It names the SensorDropDetailAssets assets with
// the most drops (ties by ID) and sums the rest in asset.other.
func dropDetails(stream c5.StreamID, since time.Time, d dropCounts) map[string]string {
	out := map[string]string{"stream": string(stream), "class": string(c5.ClassNetworkObservation),
		"since": since.Format(time.RFC3339Nano), "count": strconv.FormatUint(d.total(), 10)}
	for k, v := range d.reason {
		out["reason."+k] = strconv.FormatUint(v, 10)
	}
	ids := slices.Collect(maps.Keys(d.asset))
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == sensorDropOther })
	slices.SortFunc(ids, func(a, b string) int {
		if c := cmp.Compare(d.asset[b], d.asset[a]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	other := d.asset[sensorDropOther]
	for i, id := range ids {
		if i < SensorDropDetailAssets {
			out["asset."+id] = strconv.FormatUint(d.asset[id], 10)
		} else {
			other += d.asset[id]
		}
	}
	if other > 0 {
		out["asset."+sensorDropOther] = strconv.FormatUint(other, 10)
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

// parseDropCounts reads an event the node wrote with dropDetails for
// stream; anything else is not one. It trusts every reason.* and asset.*
// detail it can parse because only the node writes this type for a sensor
// stream on platform/health; asset.other comes back as the key "other".
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
	for k, v := range e.Health.Details {
		n, err := strconv.ParseUint(v, 10, 64)
		switch {
		case strings.HasPrefix(k, "reason.") && err == nil:
			d.reason[strings.TrimPrefix(k, "reason.")] = n
		case strings.HasPrefix(k, "asset.") && err == nil:
			d.asset[strings.TrimPrefix(k, "asset.")] = n
		}
	}
	return d, since, true
}
