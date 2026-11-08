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
// class only keeps more, and the node retries at each tick.
const AlarmNetRetentionStalled = "network-retention-stalled"

// NetRetentionStatus is the retention consumer as status shows it
// (docs/phase4/D5-c5-0.9.md section 3): its cursor, the last recorded
// cutoff and the wall-clock cutoff, which differ by the node's downtime
// and by any clock step.
type NetRetentionStatus struct {
	Stream      string    `json:"stream"`
	Running     bool      `json:"running"`
	Cursor      uint64    `json:"cursor"`
	CursorSaved bool      `json:"cursor_saved"`
	Cutoff      time.Time `json:"cutoff,omitzero"`
	WallCutoff  time.Time `json:"wall_cutoff,omitzero"`
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
	if r.retention != nil {
		s := r.retention.Status()
		st.Cursor, st.CursorSaved, st.Cutoff, st.WallCutoff = uint64(s.Cursor), s.CursorSaved, s.Cutoff, s.WallCutoff
	}
	r.opt.Status.SetNetRetention(st)
	if r.quiet("net retention", err != nil) {
		r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmNetRetentionStalled, At: r.opt.Now(), Stream: stream,
			Detail: "the alert stream is not pruned past the retention consumer's cursor: " + err.Error()})
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
	c, err := netretain.Start(ctx, netretain.Config{SensorID: r.cfg.NetworkSensor.SensorID,
		Retention: time.Duration(r.cfg.NetworkSensor.AlertRetentionDays) * 24 * time.Hour},
		netretain.Options{Store: ndb, Wall: r.opt.Now, Mono: r.opt.Mono, Record: r.recordRetention}, last)
	if err != nil {
		return err
	}
	r.retention = c
	return nil
}

// latestRetention reads the retained audit stream for the sensor's latest
// store.retention_moved record. A record pruned from the audit stream is
// not found, and the consumer is then created again, which only keeps more
// (netretain.Start).
func (r *Runtime) latestRetention(ctx context.Context, adb interface {
	LastCommitted(context.Context, c5.StreamID) (c5.Seq, error)
	Read(context.Context, c5.StreamID, c5.Seq, int) ([]c5.Stored, error)
}) (*audit.Retention, error) {
	last, err := adb.LastCommitted(ctx, AuditStream)
	if err != nil {
		return nil, err
	}
	var recs []*audit.Record
	for after := c5.Seq(0); after < last; {
		got, err := adb.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			return nil, fmt.Errorf("audit stream ends at %d, before its last committed seq %d", after, last)
		}
		for _, st := range got {
			after = st.Key.Seq
			// The bytes select the records to parse; one with an escape is
			// parsed too, as its action may be spelt with one.
			if !bytes.Contains(st.Event, []byte(`"store.retention_moved"`)) && !bytes.Contains(st.Event, []byte(`\u`)) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return nil, badRecord{st.Key.Seq, err}
			}
			if rec.Action == audit.ActionStoreRetentionMoved {
				recs = append(recs, rec)
			}
		}
	}
	return netretain.Latest(recs, r.cfg.NetworkSensor.SensorID), nil
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
