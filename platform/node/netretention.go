package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/netretain"
)

// AlarmNetRetentionStalled: the alert stream's retention consumer could not
// start or move (a store error, or its store.retention_moved record not
// committed). Nothing is pruned past its cursor meanwhile, so the alert
// class only keeps more. The consumer retries at each tick while it fails
// (netretain's Tick), the alarm is raised once while that lasts, and status
// shows the error until a step succeeds.
const AlarmNetRetentionStalled = "network-retention-stalled"

// AlarmNetRetentionLagging: the retention consumer's monotonic bound is
// more than one retention period behind the wall-clock cutoff, so the alert
// stream keeps more than twice its retention. The cutoff advances no faster than the monotonic
// clock, so downtime, a forward clock correction or a cut to
// alert_retention_days leave a lag that never closes on its own (D3's R1
// on #559, D4-71); a larger window fills the alert quota sooner.
// AlarmNetRetentionLagCleared follows when the lag falls back under.
const (
	AlarmNetRetentionLagging    = "network-retention-lagging"
	AlarmNetRetentionLagCleared = "network-retention-lag-cleared"
)

// AlarmNetRetentionUnrecorded: at start the store's cursor of the retention
// consumer was past its latest store.retention_moved record, so alerts were
// passed with no record: the store and its audit disagree (D3's S1 on
// #559). The consumer is created again at the store's cursor.
const AlarmNetRetentionUnrecorded = "network-retention-unrecorded"

// NetRetentionStatus is the retention consumer as status shows it
// (docs/phase4/D5-c5-0.9.md section 3): its cursor, the last recorded
// cutoff and the wall-clock cutoff, which differ by the node's downtime
// and by any clock step. LagS is how far the consumer's monotonic bound is
// behind the wall-clock cutoff, in seconds (netretain.Status.Lag), and
// Lagging whether that is over one retention period. UnrecordedTo is set when the
// consumer started with the store's cursor past its latest record, whose
// to_seq it is.
type NetRetentionStatus struct {
	Stream       string    `json:"stream"`
	Running      bool      `json:"running"`
	Cursor       uint64    `json:"cursor"`
	CursorSaved  bool      `json:"cursor_saved"`
	Cutoff       time.Time `json:"cutoff,omitzero"`
	WallCutoff   time.Time `json:"wall_cutoff,omitzero"`
	LagS         int64     `json:"lag_s"`
	Lagging      bool      `json:"lagging"`
	UnrecordedTo *uint64   `json:"unrecorded_to,omitempty"`
	// Error is why the last step failed: it stays while the consumer is
	// stalled, and is cleared by the first step that succeeds.
	Error string `json:"error,omitempty"`
}

// SetNetRetention records the retention consumer's state.
func (s *Status) SetNetRetention(n *NetRetentionStatus) {
	s.mu.Lock()
	s.netRetention = n
	s.mu.Unlock()
}

// tickRetention starts the retention consumer if it isn't running, and
// otherwise lets it move. It runs at Start and at every Tick; the consumer
// itself moves at most once an hour.
func (r *Runtime) tickRetention(ctx context.Context) {
	if !r.cfg.NetRetentionOn() {
		return
	}
	stream := NetAlertStream(r.cfg.NetworkSensor.SensorID)
	err := r.retentionStep(ctx)
	st := &NetRetentionStatus{Stream: string(stream), Running: r.retention != nil}
	if err != nil {
		st.Error = err.Error()
	}
	retention := time.Duration(r.cfg.NetworkSensor.AlertRetentionDays) * 24 * time.Hour
	if r.retention != nil {
		s := r.retention.Status()
		st.Cursor, st.CursorSaved, st.Cutoff, st.WallCutoff = uint64(s.Cursor), s.CursorSaved, s.Cutoff, s.WallCutoff
		st.LagS, st.Lagging = int64(s.Lag/time.Second), s.Lag > retention
		if s.Unrecorded {
			to := uint64(s.UnrecordedTo)
			st.UnrecordedTo = &to
		}
	}
	r.opt.Status.SetNetRetention(st)
	alarm := func(code, detail string) {
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: c5.AlarmCode(code), At: r.opt.Now(), Stream: stream, Detail: detail})
	}
	if r.quiet("net retention", err != nil) {
		alarm(AlarmNetRetentionStalled, "the alert stream is not pruned past the retention consumer's cursor: "+err.Error())
	}
	if r.quiet("net retention unrecorded", st.UnrecordedTo != nil) {
		alarm(AlarmNetRetentionUnrecorded, fmt.Sprintf("the retention consumer's store cursor was past its latest store.retention_moved record (to_seq %d): "+
			"alerts were passed with no record; the consumer was created again at seq %d", *st.UnrecordedTo, st.Cursor))
	}
	switch {
	case r.retention == nil: // the lag is unknown until it runs
	case st.Lagging && !r.retentionLag:
		alarm(AlarmNetRetentionLagging, fmt.Sprintf("the retention bound is %ds behind the wall-clock cutoff, more than the retention of %ds: "+
			"the alert stream keeps more than twice its retention", st.LagS, int64(retention/time.Second)))
	case !st.Lagging && r.retentionLag:
		alarm(AlarmNetRetentionLagCleared, fmt.Sprintf("the retention bound is %ds behind the wall-clock cutoff, within the retention", st.LagS))
	}
	if r.retention != nil {
		r.retentionLag = st.Lagging
	}
}

func (r *Runtime) retentionStep(ctx context.Context) error {
	if r.retention != nil {
		return r.retention.Tick(ctx)
	}
	nd, ad := r.find(NetworkDB), r.find(AuditDB)
	if nd == nil || ad == nil {
		return errors.New("the network or audit database is not in the layout")
	}
	ndb, _, nmode := r.view(nd)
	adb, _, amode := r.view(ad)
	if ndb == nil || adb == nil {
		return fmt.Errorf("the network database is %s and the audit database %s", nmode, amode)
	}
	last, err := r.latestRetention(ctx, adb)
	if err != nil {
		return err
	}
	record := func(ctx context.Context, m audit.Retention) error {
		if r.retentionRecord != nil {
			return r.retentionRecord(ctx, m)
		}
		return r.recordRetention(ctx, m)
	}
	c, err := netretain.Start(ctx, netretain.Config{SensorID: r.cfg.NetworkSensor.SensorID,
		Retention: time.Duration(r.cfg.NetworkSensor.AlertRetentionDays) * 24 * time.Hour},
		netretain.Options{Store: ndb, Wall: r.opt.Now, Mono: r.opt.Mono, Record: record,
			Latest: func(ctx context.Context) (*audit.Retention, error) { return r.latestRetention(ctx, adb) }}, last)
	if err != nil {
		return err
	}
	r.retention = c
	return c.Tick(ctx) // evaluates at once, so status has both cutoffs from the start
}

// latestRetention reads the retained audit stream for the sensor's latest
// store.retention_moved record, newest page first, so a start reads back
// only as far as that record: the consumer records at most one move an
// hour, and only when an alert passes (D6 on #559, on the start's cost). A
// record pruned from the audit stream is not found, and the consumer is
// then created again, which only keeps more (netretain.Start).
func (r *Runtime) latestRetention(ctx context.Context, adb interface {
	LastCommitted(context.Context, c5.StreamID) (c5.Seq, error)
	FirstRetained(context.Context, c5.StreamID) (c5.Seq, error)
	Read(context.Context, c5.StreamID, c5.Seq, int) ([]c5.Stored, error)
}) (*audit.Retention, error) {
	const page = 500
	last, err := adb.LastCommitted(ctx, AuditStream)
	if err != nil {
		return nil, err
	}
	first, err := adb.FirstRetained(ctx, AuditStream)
	if err != nil || first == 0 {
		return nil, err
	}
	for hi := last; hi >= first; {
		lo := first - 1
		if hi-lo > page {
			lo = hi - page
		}
		got, err := adb.Read(ctx, AuditStream, lo, int(hi-lo))
		if err != nil {
			return nil, err
		}
		if len(got) == 0 || got[len(got)-1].Key.Seq != hi {
			return nil, fmt.Errorf("audit stream read after %d did not end at %d", lo, hi)
		}
		var recs []*audit.Record
		for _, st := range got {
			// The bytes select the records to parse; one with an escape is
			// parsed too, as its action may be spelt with one.
			if !bytes.Contains(st.Event, []byte(`"store.retention_moved"`)) && !bytes.Contains(st.Event, []byte(`\u`)) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return nil, badRecord{st.Key.Seq, err}
			}
			recs = append(recs, rec)
		}
		if m := netretain.Latest(recs, r.cfg.NetworkSensor.SensorID); m != nil {
			return m, nil
		}
		hi = lo
	}
	return nil, nil
}

// RetentionContract is the stamp of the node's store.retention_moved
// records. The action is new in C8 0.12, so its records carry 0.12, while
// every other node record keeps audit.ContractID (0.11) until the node also
// writes 0.12's keys_digest and admin_keys records: a decision stamped 0.12
// needs both (C8 0.12, item 7). Readers of 0.12 landed in #545, and a chain
// may mix minors record by record.
const RetentionContract = "otsec.audit/0.12"

// recordRetention commits one store.retention_moved record (C8 0.12
// section 2.2): the node's info record, its actor the node, its target the
// sensor. It returns only once the record is committed, so the consumer
// moves its cursor only after it.
func (r *Runtime) recordRetention(ctx context.Context, m audit.Retention) error {
	d := r.find(AuditDB)
	if d == nil {
		return errors.New("no audit database")
	}
	_, log, mode := r.view(d)
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("the audit database is %s", mode)
	}
	rec := audit.Record{Contract: RetentionContract, NodeID: string(r.cfg.NodeID), Time: r.received(),
		Actor:  audit.Actor{Type: authz.PrincipalNode, ID: string(r.cfg.NodeID)},
		Action: audit.ActionStoreRetentionMoved, Outcome: audit.OutcomeInfo,
		Target: &audit.Target{SensorID: r.cfg.NetworkSensor.SensorID}, Retention: &m}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return err
	}
	_, err = log.Append(ctx, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b})
	return err
}
