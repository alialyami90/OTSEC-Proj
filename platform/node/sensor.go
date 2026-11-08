package node

import (
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

// SensorDropReportEvery is how often, at most, the node writes the
// observation class's drop counts as an intake.drop-counted event, and only
// when they changed (D5-c5-0.9.md section 4).
const SensorDropReportEvery = time.Minute

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
	// written is the counts the last event carried, writtenAt its node
	// time and writtenMono its monotonic time.
	written     dropCounts
	writtenAt   time.Time
	writtenMono time.Duration
	everWritten bool
	refused     map[string]bool // reasons whose alarm is raised
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
	in := &sensorIntake{link: link, stream: stream, since: r.opt.Now().UTC(), refused: map[string]bool{},
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

// ServeSensor reads one connection of the sensor's channel until it ends
// (sensorlink.Link.Serve). It returns an error when the configuration has
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
	if !now.equal(in.written) && (final || !in.everWritten || m-in.writtenMono >= SensorDropReportEvery) {
		at := r.opt.Now().UTC()
		if _, err := (healthSink{r}).Emit(ctx, event.Health{Type: event.HealthDropCounted, Details: dropDetails(in.stream, in.since, now)}); err == nil {
			in.written, in.writtenAt, in.writtenMono, in.everWritten = now, at, m, true
		}
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
		Committed: st.Committed, Refused: st.Refused, Dropped: now.reason, DroppedByAsset: now.asset, DropsSince: in.since, DropsWritten: in.writtenAt}
	if h := st.Heartbeat; h != nil {
		s.Heartbeat = &SensorHeartbeat{AtUTC: h.AtUTC, Counters: h.Counters, RingOldestUTC: h.RingOldestUTC, InterfaceCheck: h.InterfaceCheck}
	}
	r.opt.Status.SetSensor(s)
}

// dropDetails is the intake.drop-counted event's details: the totals since
// since, by reason ("reason.<r>") and by destination asset ("asset.<id>"),
// and their sum ("count").
func dropDetails(stream c5.StreamID, since time.Time, d dropCounts) map[string]string {
	out := map[string]string{"stream": string(stream), "class": string(c5.ClassNetworkObservation),
		"since": since.Format(time.RFC3339Nano), "count": strconv.FormatUint(d.total(), 10)}
	for k, v := range d.reason {
		out["reason."+k] = strconv.FormatUint(v, 10)
	}
	for k, v := range d.asset {
		out["asset."+k] = strconv.FormatUint(v, 10)
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
// stream; anything else is not one.
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
