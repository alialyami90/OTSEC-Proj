package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// StartupDeadline bounds startup recovery of one database (proposed, A5).
const StartupDeadline = 5 * time.Minute

// RuntimeOptions are what the node binary supplies beyond the
// configuration.
type RuntimeOptions struct {
	Status *Status
	Now    func() time.Time
	// Group is the group-commit window; zero means c5.DefaultGroup.
	Group c5.GroupOptions
	// ClockSync is the node clock's state as the node knows it. Phase 2 has
	// no time-sync probe, so the default is unknown, never a guess.
	ClockSync event.SyncState
}

// Runtime is a started node: every database through C5 startup, a Log per
// open database, and the node's status.
type Runtime struct {
	cfg    *Config
	layout c5.Layout
	opt    RuntimeOptions
	dbs    []*database

	mu      sync.Mutex
	pending []queued // store alarms raised during a commit, for Tick
}

type database struct {
	spec   c5.Database
	env    *store.Env
	policy c5.StartupPolicy
	report c5.Report
	db     *store.DB
	log    *c5.Log
}

// Start runs C5 startup recovery on every database of cfg's layout, the
// audit database first, then writes the audit chain start (on a new node),
// one store.mode_change audit record and health event per database, and
// service.start. A database that ends blocked or failed is reported, not
// fatal: the node keeps running so that status shows why.
func Start(ctx context.Context, cfg *Config, opt RuntimeOptions) (*Runtime, error) {
	if opt.Status == nil {
		return nil, errors.New("node: no status sink")
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Group == (c5.GroupOptions{}) {
		opt.Group = c5.DefaultGroup
	}
	if opt.ClockSync == "" {
		opt.ClockSync = event.SyncUnknown
	}
	layout, err := cfg.Layout()
	if err != nil {
		return nil, err
	}
	consumers, err := cfg.Consumers()
	if err != nil {
		return nil, err
	}
	r := &Runtime{cfg: cfg, layout: layout, opt: opt}
	specs := append([]c5.Database{}, layout.Databases...)
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].ID == AuditDB && specs[j].ID != AuditDB })
	for _, spec := range specs {
		d, err := r.startDB(ctx, spec, consumers)
		if err != nil {
			r.Close()
			return nil, err
		}
		r.dbs = append(r.dbs, d)
	}
	r.recordStart(ctx)
	opt.Status.Write(string(cfg.NodeID))
	return r, nil
}

func (r *Runtime) startDB(ctx context.Context, spec c5.Database, consumers []c5.Consumer) (*database, error) {
	dbID := spec.ID
	opt := store.Options{Dir: r.cfg.Store.Dir, Node: r.cfg.NodeID, Database: spec, Now: r.opt.Now,
		Alarms: func(a c5.Alarm) { r.opt.Status.Alarm(dbID, a); r.storeAlarm(dbID, a) }}
	env, err := store.NewEnv(opt)
	if err != nil {
		return nil, fmt.Errorf("database %s: %w", spec.ID, err)
	}
	var mine []c5.Consumer
	for _, c := range consumers {
		for _, s := range spec.Streams {
			if c.Stream == s.ID {
				mine = append(mine, c)
			}
		}
	}
	d := &database{spec: spec, env: env, policy: c5.StartupPolicy{
		Streams:                spec.Streams,
		Consumers:              mine,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
		Now:                    r.opt.Now,
	}}
	sctx, cancel := context.WithTimeout(ctx, StartupDeadline)
	defer cancel()
	d.report = c5.RunStartup(sctx, env, d.policy)
	if err := r.adopt(d); err != nil {
		return nil, err
	}
	return d, nil
}

// adopt takes a startup or Resume report: alarms to status, the mode, and
// a Log over the store when it is open.
func (r *Runtime) adopt(d *database) error {
	for _, a := range d.report.Alarms {
		r.opt.Status.Alarm(d.spec.ID, a)
	}
	r.opt.Status.SetMode(d.spec.ID, d.report.Mode)
	if d.report.Store == nil {
		d.db, d.log = nil, nil
		return nil
	}
	if d.db != nil && d.log != nil {
		return nil // Resume from drain-only keeps the open store and its Log
	}
	db, ok := store.AsDB(d.report.Store)
	if !ok {
		return fmt.Errorf("database %s: store is %T", d.spec.ID, d.report.Store)
	}
	classes := map[c5.StreamID]c5.StreamClass{}
	last := map[c5.StreamID]c5.Seq{}
	for _, s := range d.spec.Streams {
		classes[s.ID] = s.Class
		n, err := db.LastCommitted(context.Background(), s.ID)
		if err != nil {
			return fmt.Errorf("database %s: %w", d.spec.ID, err)
		}
		last[s.ID] = n
	}
	l, err := c5.NewLog(db, r.cfg.NodeID, classes, r.opt.Group, last)
	if err != nil {
		return err
	}
	d.db, d.log = db, l
	return nil
}

func (r *Runtime) find(id c5.DatabaseID) *database {
	for _, d := range r.dbs {
		if d.spec.ID == id {
			return d
		}
	}
	return nil
}

// recordStart writes the chain start on a new node, the first mode of
// every database, and service.start.
func (r *Runtime) recordStart(ctx context.Context) {
	if a := r.find(AuditDB); a != nil && a.log != nil && a.report.Mode.AcceptsEvents() {
		if n, err := a.db.LastCommitted(ctx, AuditStream); err == nil && n == 0 {
			r.audit(ctx, audit.ActionAuditChainStart, audit.OutcomeInfo, "", "audit chain started for node "+string(r.cfg.NodeID))
		}
	}
	for _, d := range r.dbs {
		r.modeChanged(ctx, d, c5.ModeChange{From: "", To: d.report.Mode, At: r.opt.Now(), Alarms: d.report.Alarms})
	}
	r.audit(ctx, audit.ActionServiceStart, audit.OutcomeInfo, "", "otsec node started")
}

func (r *Runtime) modeChanged(ctx context.Context, d *database, mc c5.ModeChange) {
	var codes []string
	for _, a := range mc.Alarms {
		codes = append(codes, string(a.Code))
	}
	detail := fmt.Sprintf("database %s: %s to %s", d.spec.ID, orNone(mc.From), mc.To)
	if len(codes) > 0 {
		detail += "; alarms " + strings.Join(codes, ",")
	}
	r.audit(ctx, audit.ActionStoreModeChange, audit.OutcomeInfo, string(mc.To), detail)
	r.health(ctx, c5.HealthModeChanged, map[string]string{"database": string(d.spec.ID), "from": orNone(mc.From), "to": string(mc.To)})
}

func orNone(m c5.Mode) string {
	if m == "" {
		return "none"
	}
	return string(m)
}

// storeAlarm turns a store alarm raised while running into a health event.
// It runs inside the store's commit, so it only queues; Tick commits it.
func (r *Runtime) storeAlarm(db c5.DatabaseID, a c5.Alarm) {
	r.mu.Lock()
	r.pending = append(r.pending, queued{db, a})
	r.mu.Unlock()
}

type queued struct {
	db c5.DatabaseID
	a  c5.Alarm
}

// Tick is called periodically by the service (proposed: every 60 s). It
// resumes blocked and drain-only databases (C5 Resume), records every mode
// change, and turns queued store alarms into health events.
func (r *Runtime) Tick(ctx context.Context) {
	for _, d := range r.dbs {
		if d.report.Mode != c5.ModeBlocked && d.report.Mode != c5.ModeDrainOnly {
			continue
		}
		prev := d.report
		sctx, cancel := context.WithTimeout(ctx, StartupDeadline)
		d.report = c5.Resume(sctx, d.env, d.policy, prev)
		cancel()
		if err := r.adopt(d); err != nil {
			r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmOpenFailed, At: r.opt.Now(), Detail: err.Error()})
		}
		if mc, ok := c5.ModeChangeOf(prev, d.report, r.opt.Now()); ok {
			r.modeChanged(ctx, d, mc)
		}
	}
	r.mu.Lock()
	q := r.pending
	r.pending = nil
	r.mu.Unlock()
	for _, x := range q {
		details := map[string]string{"database": string(x.db), "code": string(x.a.Code)}
		if x.a.Class != "" {
			details["class"] = string(x.a.Class)
		}
		if x.a.Stream != "" {
			details["stream"] = string(x.a.Stream)
		}
		r.health(ctx, x.a.Code.HealthType(), details)
	}
	r.opt.Status.Write(string(r.cfg.NodeID))
}

// Collecting reports whether collectors may run: every database must
// accept events (C5 Mode.AcceptsEvents). Each credentialed run still needs
// its own audit receipt (AuditBeforeAct, D1-11).
func (r *Runtime) Collecting() bool {
	for _, d := range r.dbs {
		if !d.report.Mode.AcceptsEvents() {
			return false
		}
	}
	return len(r.dbs) > 0
}

// Log returns the Log of the database that holds stream, or nil if that
// database is not open.
func (r *Runtime) Log(stream c5.StreamID) *c5.Log {
	if d := r.dbFor(stream); d != nil {
		return d.log
	}
	return nil
}

// Store returns the open database that holds stream, or nil. Modules get
// it as C5 interfaces (Outbox, CursorStore, CommitIndex), never as a file.
func (r *Runtime) Store(stream c5.StreamID) *store.DB {
	if d := r.dbFor(stream); d != nil {
		return d.db
	}
	return nil
}

func (r *Runtime) dbFor(stream c5.StreamID) *database {
	for _, d := range r.dbs {
		for _, s := range d.spec.Streams {
			if s.ID == stream {
				return d
			}
		}
	}
	return nil
}

// Mode returns database id's mode.
func (r *Runtime) Mode(id c5.DatabaseID) c5.Mode {
	if d := r.find(id); d != nil {
		return d.report.Mode
	}
	return ""
}

// Close records service.stop, closes every database and releases the
// locks.
func (r *Runtime) Close() error {
	if len(r.dbs) > 0 {
		r.audit(context.Background(), audit.ActionServiceStop, audit.OutcomeInfo, "", "otsec node stopping")
	}
	var errs []error
	for _, d := range r.dbs {
		if d.db != nil {
			errs = append(errs, d.db.Close())
		}
		if d.report.Unlock != nil {
			d.report.Unlock()
		}
	}
	r.dbs = nil
	return errors.Join(errs...)
}

// received is the node clock's reading in C4 form: microseconds, so the
// stated resolution is 1 µs on every OS.
func (r *Runtime) received() event.Received {
	return event.Received{UTC: r.opt.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000, Clock: event.Clock{Sync: r.opt.ClockSync}}
}

// health commits a platform health event to platform/health when the
// evidence database accepts events. Otherwise the event exists only in
// status, which already holds the alarm.
func (r *Runtime) health(ctx context.Context, typ string, details map[string]string) {
	d := r.dbFor(HealthStream)
	if d == nil || d.log == nil || !d.report.Mode.AcceptsEvents() {
		return
	}
	rec, err := r.healthRecord(HealthStream, typ, details)
	if err == nil {
		_, err = d.log.Append(ctx, rec)
	}
	if err != nil {
		r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: HealthStream, Detail: "health event " + typ + ": " + err.Error()})
	}
}

// healthRecord builds a pending C4 platform health event as a C5 record on
// stream, whose class it takes from the layout.
func (r *Runtime) healthRecord(stream c5.StreamID, typ string, details map[string]string) (c5.Record, error) {
	e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: r.cfg.NodeID, Stream: event.Stream(stream)},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: r.received(), Health: &event.Health{Type: typ, Details: details}}
	b, err := json.Marshal(e)
	if err != nil {
		return c5.Record{}, err
	}
	class, ok := r.layout.StreamClasses()[stream]
	if !ok {
		return c5.Record{}, fmt.Errorf("stream %s is not in the layout", stream)
	}
	return c5.Record{Stream: stream, Class: class, Event: b}, nil
}

// audit commits a node-written C8 record. A failure goes to status: the
// audit store may be what failed.
func (r *Runtime) audit(ctx context.Context, action audit.Action, outcome audit.Outcome, reason, detail string) {
	d := r.find(AuditDB)
	if d == nil || d.log == nil || !d.report.Mode.AcceptsEvents() {
		r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: c5.AlarmAuditFull, At: r.opt.Now(), Detail: fmt.Sprintf("%s not recorded: audit database %s", action, r.Mode(AuditDB))})
		return
	}
	rec, err := r.AuditRecord(action, outcome, reason, detail)
	if err == nil {
		_, err = d.log.Append(ctx, rec)
	}
	if err != nil {
		r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: AuditStream, Detail: string(action) + ": " + err.Error()})
	}
}

// AuditRecord builds a pending C8 record with the node as the actor.
func (r *Runtime) AuditRecord(action audit.Action, outcome audit.Outcome, reason, detail string) (c5.Record, error) {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(r.cfg.NodeID), Time: r.received(),
		Actor: audit.Actor{Type: authz.PrincipalSystem, ID: "node"}, Action: action, Outcome: outcome, ReasonCode: reason, Detail: detail}
	b, err := json.Marshal(rec)
	if err != nil {
		return c5.Record{}, err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return c5.Record{}, err
	}
	return c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}, nil
}
