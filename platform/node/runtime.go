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
	// BusyTimeout is the stores' busy_timeout; zero means the store's 5 s.
	// Only tests that hold a database busy on purpose set it.
	BusyTimeout time.Duration
}

// Runtime is a started node: every database through C5 startup, a Log per
// open database, and the node's status.
type Runtime struct {
	cfg      *Config
	keyWatch nodeKeyWatch
	layout   c5.Layout
	opt      RuntimeOptions
	dbs      []*database

	mu      sync.Mutex
	pending []queued                    // store alarms raised during a commit, for Tick
	slowAt  map[c5.DatabaseID]time.Time // when AlarmCommitSlow was last raised, by database
	raised  map[string]bool             // conditions whose alarm is raised (prune.go)
	pruneMu sync.Mutex                  // serializes Prune
	// deferred holds the node records audit could not commit because the
	// audit database had not opened, its open at start being only busy (C5
	// 0.2). The retry in Tick that opens it commits them first, in order
	// and with their own times, so a restart is never missing from the
	// chain (A6 on #147). At most MaxDeferredAudit are kept; dropped
	// counts the rest, and one record names how many.
	deferred []c5.Record
	dropped  int

	// state guards each database's report, store and Log, which Tick
	// replaces while the scheduler and the forwarder read them.
	state sync.RWMutex
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
	consumers = pruneConsumers(consumers)
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
	r.reconcileHolds(ctx)
	opt.Status.Write(string(cfg.NodeID))
	return r, nil
}

func (r *Runtime) startDB(ctx context.Context, spec c5.Database, consumers []c5.Consumer) (*database, error) {
	dbID := spec.ID
	opt := store.Options{Dir: r.cfg.Store.Dir, Node: r.cfg.NodeID, Database: spec, Now: r.opt.Now, Documents: ConfigDocuments, BusyTimeout: r.opt.BusyTimeout,
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
	group := groupFor(spec, r.opt.Group)
	largest, rows := c5.LargestCommit(spec, group), c5.LargestCommitRecords(spec, group)
	d := &database{spec: spec, env: env, policy: c5.StartupPolicy{
		Streams:   spec.Streams,
		Consumers: mine,
		// The reserve covers the database's largest commit (C5 0.5, D4-9,
		// D4-14): twice the WAL bound, and the WAL of one commit at the
		// byte and record caps.
		RecoveryReserveBytes:   c5.RecoveryReserveFor(store.WALBoundBytes, largest, rows),
		WALBoundBytes:          store.WALBoundBytes,
		LargestCommitBytes:     largest,
		LargestCommitRecords:   rows,
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
	last := map[c5.StreamID]c5.Seq{}
	for _, s := range d.spec.Streams {
		n, err := db.LastCommitted(context.Background(), s.ID)
		if err != nil {
			return fmt.Errorf("database %s: %w", d.spec.ID, err)
		}
		last[s.ID] = n
	}
	l, err := c5.NewLogFor(db, r.cfg.NodeID, d.spec, groupFor(d.spec, r.opt.Group), last)
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
	if db, log, mode := r.view(r.find(AuditDB)); log != nil && mode.AcceptsEvents() {
		if n, err := db.LastCommitted(ctx, AuditStream); err == nil && n == 0 {
			r.audit(ctx, audit.ActionAuditChainStart, audit.OutcomeInfo, "", "audit chain started for node "+string(r.cfg.NodeID))
		}
	}
	for _, d := range r.dbs {
		r.modeChanged(ctx, d, c5.ModeChange{From: "", To: d.report.Mode, At: r.opt.Now(), Alarms: d.report.Alarms})
	}
	r.audit(ctx, audit.ActionServiceStart, audit.OutcomeInfo, "", "otsec node started")
}

func (r *Runtime) modeChanged(ctx context.Context, d *database, mc c5.ModeChange) {
	detail := modeDetail(d, mc)
	r.audit(ctx, audit.ActionStoreModeChange, audit.OutcomeInfo, string(mc.To), detail)
	r.modeHealth(ctx, d, mc)
}

// modeDetail is the detail of a store.mode_change record.
func modeDetail(d *database, mc c5.ModeChange) string {
	var codes []string
	for _, a := range mc.Alarms {
		codes = append(codes, string(a.Code))
	}
	detail := fmt.Sprintf("database %s: %s to %s", d.spec.ID, orNone(mc.From), mc.To)
	if len(codes) > 0 {
		detail += "; alarms " + strings.Join(codes, ",")
	}
	return detail
}

// modeHealth is the health event of a mode change.
func (r *Runtime) modeHealth(ctx context.Context, d *database, mc c5.ModeChange) {
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
// change, turns queued store alarms into health events, and prunes
// confirmed events of a class above its runtime target (Prune).
func (r *Runtime) Tick(ctx context.Context) {
	r.sampleCommits()
	for _, d := range r.dbs {
		r.state.Lock()
		prev := d.report
		var next c5.Report
		switch {
		case prev.OpenBusy():
			// A database that failed at an open that was only busy is
			// retried once per tick (C5 0.2, P3-A5); every other failure
			// stays failed until a restart. It has no open store, so the
			// retry, which waits out the busy timeout, runs without the
			// state lock, and Tick is its only writer.
			r.state.Unlock()
			sctx, cancel := context.WithTimeout(ctx, StartupDeadline)
			next = c5.Resume(sctx, d.env, d.policy, prev)
			cancel()
			if next.OpenBusy() {
				// Busy again: the alarm the first failure raised still
				// holds, so it is not raised at every tick.
				continue
			}
			r.state.Lock()
		case prev.Mode == c5.ModeBlocked || prev.Mode == c5.ModeDrainOnly:
			sctx, cancel := context.WithTimeout(ctx, StartupDeadline)
			next = c5.Resume(sctx, d.env, d.policy, prev)
			cancel()
		default:
			r.state.Unlock()
			continue
		}
		d.report = next
		if err := r.adopt(d); err != nil {
			r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmOpenFailed, At: r.opt.Now(), Detail: err.Error()})
		}
		now := d.report
		mc, changed := c5.ModeChangeOf(prev, now, r.opt.Now())
		recorded := false
		if d.spec.ID == AuditDB && prev.OpenBusy() {
			// Still under the state lock, so no other writer can append to
			// the Log adopt just published before the kept records and the
			// recovery are in the chain (D3-6; B6 on #249).
			recorded = r.commitDeferred(ctx, d, mc, changed)
		}
		r.state.Unlock()
		if changed {
			if recorded {
				r.modeHealth(ctx, d, mc)
			} else {
				r.modeChanged(ctx, d, mc)
			}
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
	r.Prune(ctx)
	r.opt.Status.Write(string(r.cfg.NodeID))
}

// Collecting reports whether collectors may run: every database must
// accept events (C5 Mode.AcceptsEvents). Each credentialed run still needs
// its own audit receipt (AuditBeforeAct, D1-11).
func (r *Runtime) Collecting() bool {
	r.state.RLock()
	defer r.state.RUnlock()
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
	_, log, _ := r.view(r.dbFor(stream))
	return log
}

// Store returns the open database that holds stream, or nil. Modules get
// it as C5 interfaces (Outbox, CursorStore, CommitIndex), never as a file.
func (r *Runtime) Store(stream c5.StreamID) *store.DB {
	db, _, _ := r.view(r.dbFor(stream))
	return db
}

// view reads a database's store, Log and mode under the state lock.
func (r *Runtime) view(d *database) (*store.DB, *c5.Log, c5.Mode) {
	if d == nil {
		return nil, nil, ""
	}
	r.state.RLock()
	defer r.state.RUnlock()
	return d.db, d.log, d.report.Mode
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
	_, _, m := r.view(r.find(id))
	return m
}

// Close records service.stop, closes every database and releases the
// locks.
func (r *Runtime) Close() error {
	if len(r.dbs) > 0 {
		r.audit(context.Background(), audit.ActionServiceStop, audit.OutcomeInfo, "", "otsec node stopping")
	}
	r.state.Lock()
	defer r.state.Unlock()
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
	_, log, mode := r.view(d)
	if log == nil || !mode.AcceptsEvents() {
		return
	}
	rec, err := r.healthRecord(HealthStream, typ, details)
	if err == nil {
		_, err = log.Append(ctx, rec)
	}
	if err != nil {
		r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: HealthStream, Detail: "health event " + typ + ": " + err.Error()})
	}
}

// healthRecord builds a pending C4 platform health event as a C5 record on
// stream, whose class it takes from the layout.
func (r *Runtime) healthRecord(stream c5.StreamID, typ string, details map[string]string) (c5.Record, error) {
	return r.healthEventRecord(stream, event.Health{Type: typ, Details: details})
}

// healthEventRecord is healthRecord for a whole C4 health payload.
func (r *Runtime) healthEventRecord(stream c5.StreamID, h event.Health) (c5.Record, error) {
	e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: r.cfg.NodeID, Stream: event.Stream(stream)},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: r.received(), Health: &h}
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

// MaxDeferredAudit bounds the node records kept while the audit database's
// open is busy. A start writes one per database and service.start, so a
// node needs far fewer.
const MaxDeferredAudit = 64

// AlarmAuditNotRecorded: a node record could not be committed because the
// audit database does not accept records. While its open is only busy the
// record is kept and committed when a retry opens it; the alarm says which.
const AlarmAuditNotRecorded = "audit-not-recorded"

// audit commits a node-written C8 record. A failure goes to status: the
// audit store may be what failed.
func (r *Runtime) audit(ctx context.Context, action audit.Action, outcome audit.Outcome, reason, detail string) {
	d := r.find(AuditDB)
	var (
		log *c5.Log
		why string
	)
	if d != nil {
		// One read lock covers the check and the keeping, so a record is
		// either kept before Tick takes the kept queue or committed after
		// the kept records (D3-6).
		r.state.RLock()
		log = d.log
		if mode := d.report.Mode; log == nil || !mode.AcceptsEvents() {
			why = fmt.Sprintf("%s not recorded: audit database %s", action, mode)
			if log == nil && d.report.OpenBusy() {
				why += "; " + r.deferAudit(action, outcome, reason, detail)
			}
		}
		r.state.RUnlock()
	} else {
		why = fmt.Sprintf("%s not recorded: no audit database", action)
	}
	if why != "" {
		r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: AlarmAuditNotRecorded, At: r.opt.Now(), Detail: why})
		return
	}
	rec, err := r.AuditRecord(action, outcome, reason, detail)
	if err == nil {
		_, err = log.Append(ctx, rec)
	}
	if err != nil {
		r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: AuditStream, Detail: string(action) + ": " + err.Error()})
	}
}

// deferAudit keeps a record for commitDeferred, timed now, and says what
// became of it.
func (r *Runtime) deferAudit(action audit.Action, outcome audit.Outcome, reason, detail string) string {
	rec, err := r.AuditRecord(action, outcome, reason, detail)
	if err != nil {
		return "not kept: " + err.Error()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.deferred) >= MaxDeferredAudit {
		r.dropped++
		return fmt.Sprintf("not kept: %d records already wait for the audit database", MaxDeferredAudit)
	}
	r.deferred = append(r.deferred, rec)
	return "kept, to be recorded when a retry opens the audit database"
}

// commitDeferred commits the records kept while the audit database's open
// was busy, once a retry has opened it, and the retry's store.mode_change
// after them, in one AppendBatch. Each kept record keeps the time it was
// made at. A new chain gets its audit.chain_start first, as recordStart
// would have written. Tick calls it holding the state lock, so no other
// record can land between them (D3-6). It reports whether the mode change
// was recorded with them.
func (r *Runtime) commitDeferred(ctx context.Context, d *database, mc c5.ModeChange, changed bool) bool {
	r.mu.Lock()
	q, dropped := r.deferred, r.dropped
	r.deferred, r.dropped = nil, 0
	r.mu.Unlock()
	db, log, mode := d.db, d.log, d.report.Mode
	if log == nil || !mode.AcceptsEvents() {
		if len(q) > 0 || dropped > 0 {
			r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: AlarmAuditNotRecorded, At: r.opt.Now(), Detail: fmt.Sprintf("%d kept records not recorded: audit database %s", len(q)+dropped, mode)})
		}
		return false
	}
	var batch []c5.Record
	add := func(action audit.Action, reason, detail string) {
		rec, err := r.AuditRecord(action, audit.OutcomeInfo, reason, detail)
		if err != nil {
			r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: AuditStream, Detail: string(action) + ": " + err.Error()})
			return
		}
		batch = append(batch, rec)
	}
	if n, err := db.LastCommitted(ctx, AuditStream); err == nil && n == 0 {
		add(audit.ActionAuditChainStart, "", "audit chain started for node "+string(r.cfg.NodeID))
	}
	batch = append(batch, q...)
	if dropped > 0 {
		add(audit.ActionStorageAlarm, "audit_not_recorded",
			fmt.Sprintf("%d node records were not recorded while the audit database's open was busy; status holds their alarms", dropped))
	}
	if changed {
		add(audit.ActionStoreModeChange, string(mc.To), modeDetail(d, mc))
	}
	if len(batch) == 0 {
		return changed
	}
	if _, err := log.AppendBatch(ctx, batch); err != nil {
		r.opt.Status.Alarm(AuditDB, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: AuditStream, Detail: fmt.Sprintf("%d kept records and the recovery: %v", len(batch), err)})
	}
	return changed
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

// AlarmCommitSlow: a database's write transaction took SlowCommit or longer,
// or one has been running that long. Writes hold the write lock and wait for
// the WAL sync, so a disk that syncs in seconds (the hosted Windows runner's
// did, B6 #294) holds every writer and lets a receiver's queue fill and
// datagrams drop; this is the early sign. Level 1, raised at most once per
// CommitAlarmRepeat for a database, and shown by `otsec health`.
const AlarmCommitSlow c5.AlarmCode = "store-commit-slow"

// SlowCommit is the write-transaction time that raises AlarmCommitSlow, and
// CommitAlarmRepeat is how often it is raised again while commits stay slow.
// Variables so that a test can set them.
var (
	SlowCommit        = 5 * time.Second
	CommitAlarmRepeat = 10 * time.Minute
)

// sampleCommits reads each open database's write-transaction times into
// status, once per Tick, and raises AlarmCommitSlow.
func (r *Runtime) sampleCommits() {
	now := r.opt.Now()
	raised := false
	for _, d := range r.dbs {
		db, _, _ := r.view(d)
		if db == nil {
			continue
		}
		cs := db.CommitStats()
		recent := max(db.TakeRecentCommit(), cs.Waiting)
		r.opt.Status.SetCommits(d.spec.ID, CommitStatus{Count: cs.Count, MaxMS: cs.Max.Milliseconds(), RecentMS: recent.Milliseconds(), WaitingMS: cs.Waiting.Milliseconds()})
		if recent < SlowCommit {
			continue
		}
		r.mu.Lock()
		last, seen := r.slowAt[d.spec.ID]
		due := !seen || now.Sub(last) >= CommitAlarmRepeat
		if due {
			if r.slowAt == nil {
				r.slowAt = map[c5.DatabaseID]time.Time{}
			}
			r.slowAt[d.spec.ID] = now
		}
		r.mu.Unlock()
		if due {
			raised = true
			r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: AlarmCommitSlow, At: now,
				Detail: fmt.Sprintf("a write transaction took %v (running now: %v); every writer to this database waits for it, so the disk may be slow, and a receiver's queue can fill", recent.Round(time.Millisecond), cs.Waiting.Round(time.Millisecond))})
		}
	}
	if raised {
		// The rest of Tick writes to the databases, which wait for the slow
		// transaction, so the status file is written now rather than at the
		// end of Tick (B6 on #311, strace-injected fsync delays).
		r.opt.Status.Write(string(r.cfg.NodeID))
	}
}
