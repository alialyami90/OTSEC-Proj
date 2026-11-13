package node

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
)

// The sensor store set and its manager (docs/phase4/D5-sensor-node.md
// section 1.9 items 1, 9 and 10; F-027's F5, F6, F7 and F9). The sensor
// databases are never in Runtime.dbs: the manager opens, resumes, prunes
// and closes them on its own goroutine, and records their mode changes at
// most once an hour. smu, the accessor's lock, is held only to read or
// swap a handle, never across a store call. So r.state, which every Log,
// Store and Mode call of the scheduler and the Syslog intake takes, is
// never held over a sensor database (F5); Prune and its pruneMu cover
// Runtime.dbs only (F6); and a sensor database that will not open fails
// nothing but itself (F7).

// AlarmSensorStoreNotOpen: a sensor database did not open, adopt or
// resume. It stays closed, the node starts and collects without it, and
// the manager tries again at each tick. It is raised once for each stretch
// in which the database is not open.
const AlarmSensorStoreNotOpen c5.AlarmCode = "sensor-store-not-open"

// AlarmSensorFailed: the sensor manager panicked. The panic is recovered,
// and the sensor's work stops until a restart: the manager does no more,
// tickSensor does nothing and the sensor is not served. The node and every
// other stream go on (section 1.9 item 9).
const AlarmSensorFailed = "sensor-failed"

// SensorModeChangeEvery: a sensor database's store.mode_change record and
// its health event are written at most once in it, on the node's monotonic
// clock; the changes between are counted and carried in the next record's
// detail (section 1.10, mode changes 1 an hour for each database).
const SensorModeChangeEvery = time.Hour

// SensorStopTimeout is how long Close waits for the manager (section 1.10).
// Past it, Close goes on, and a sensor database the manager is still in a
// call on is left to the process's exit, which releases its lock.
const SensorStopTimeout = 10 * time.Second

// SensorSeams are a test's way into the sensor store set. A node leaves
// them nil. Each applies to a sensor database only, by its ID, whichever
// path reaches it.
type SensorSeams struct {
	// Startup, when set, replaces C5 startup of a sensor database.
	Startup func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report
	// Resume, when set, replaces C5 Resume of a sensor database.
	Resume func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report
	// Prune, when set, runs before each prune of a sensor database; an
	// error from it ends that prune.
	Prune func(ctx context.Context, db c5.DatabaseID) error
}

// isSensorDB reports whether a database is in the sensor store set.
func isSensorDB(id c5.DatabaseID) bool { return id == NetworkDB }

// runStartup is C5 startup of d, or the test's seam for a sensor database.
func (r *Runtime) runStartup(ctx context.Context, env c5.StartupEnv, d *database) c5.Report {
	if f := r.opt.SensorSeams.Startup; f != nil && isSensorDB(d.spec.ID) {
		return f(ctx, env, d.policy)
	}
	return c5.RunStartup(ctx, env, d.policy)
}

// resume is C5 Resume of d, or the test's seam for a sensor database.
func (r *Runtime) resume(ctx context.Context, d *database, prev c5.Report) c5.Report {
	if f := r.opt.SensorSeams.Resume; f != nil && isSensorDB(d.spec.ID) {
		return f(ctx, d.env, d.policy, prev)
	}
	return c5.Resume(ctx, d.env, d.policy, prev)
}

// sensorManager is the manager's goroutine and what only it touches.
type sensorManager struct {
	kick   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
	// first is closed when the first step has ended (SensorFirstStep), and
	// steps counts the steps ended.
	first chan struct{}
	steps atomic.Uint64
	// notOpen: AlarmSensorStoreNotOpen is raised for the database. raised
	// are the startup alarm codes raised for it in this stretch, so a retry
	// raises each at most once until the database opens (D6's B4).
	notOpen map[c5.DatabaseID]bool
	raised  map[c5.DatabaseID]map[c5.AlarmCode]bool
	// modes is each database's mode-change cap.
	modes map[c5.DatabaseID]*modeCap
	// intakeDown: AlarmSensorIntakeNotStarted is raised (sensor.go).
	intakeDown bool
}

// modeCap is when a database's last mode change was recorded and to which
// mode, and how many changes since were not.
type modeCap struct {
	at   time.Duration
	ever bool
	to   c5.Mode
	held int
}

// SensorFailedDetailBytes caps the panic and stack in sensor-failed's
// detail.
const SensorFailedDetailBytes = 2048

// newSensorManager makes the manager when there is a sensor database. Its
// goroutine starts with startSensorManager.
func (r *Runtime) newSensorManager() {
	m := &sensorManager{first: make(chan struct{}), notOpen: map[c5.DatabaseID]bool{},
		raised: map[c5.DatabaseID]map[c5.AlarmCode]bool{}, modes: map[c5.DatabaseID]*modeCap{}}
	if len(r.sdbs) == 0 {
		close(m.first)
	}
	r.smgr = m
}

// SensorFirstStep returns a channel closed once the sensor manager's first
// step has ended, whatever it found: the sensor store set opened or not,
// the intake started or not. Start returns before it; a node without the
// network_sensor section has it closed at once. It only signals: a test,
// or a reader of status, waits on it before it reads the sensor.
func (r *Runtime) SensorFirstStep() <-chan struct{} { return r.smgr.first }

// startSensorManager starts the manager's goroutine, after Start's own
// work, and kicks it once, so that its first step does not wait for the
// first tick. Without a sensor database there is none.
func (r *Runtime) startSensorManager() {
	m := r.smgr
	if len(r.sdbs) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.kick, m.cancel, m.done = make(chan struct{}, 1), cancel, make(chan struct{})
	m.kick <- struct{}{}
	go func() {
		defer close(m.done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.kick:
			}
			if !r.managerStep(ctx) {
				return
			}
		}
	}()
}

// kickSensorManager asks the manager for a step, and never waits.
func (r *Runtime) kickSensorManager() {
	if m := r.smgr; m != nil && m.kick != nil {
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
}

// managerStep is one step of the manager's loop: the store set, the
// intake, the held mode changes and the prune. A panic anywhere in it is
// recovered: it raises AlarmSensorFailed, naming the sensor, and stops the
// sensor's work until a restart, and managerStep reports false. The node
// and every other stream go on (section 1.9 item 9; D6's B1).
func (r *Runtime) managerStep(ctx context.Context) (ok bool) {
	m := r.smgr
	defer func() {
		if p := recover(); p != nil {
			r.sensorFailed.Store(true)
			detail := fmt.Sprintf("%v\n%s", p, debug.Stack())
			if len(detail) > SensorFailedDetailBytes {
				detail = detail[:SensorFailedDetailBytes] + "..."
			}
			r.opt.Status.Raise("", AlarmSensorFailed, fmt.Sprintf("sensor %s: the sensor's work panicked and is stopped until the node restarts; SER, Syslog and forwarding go on: %s",
				r.sensorID(), detail))
			ok = false
		}
		if m.steps.Add(1) == 1 {
			close(m.first)
		}
	}()
	if r.sensorFailed.Load() {
		return false
	}
	starts := newStartTimes()
	for _, d := range r.sdbs {
		if ctx.Err() != nil {
			return false
		}
		r.stepSensorDB(ctx, d, starts)
	}
	if ctx.Err() != nil {
		return false
	}
	r.startIntake(ctx)
	r.flushModeChanges(ctx)
	r.pruneSensorStores(ctx)
	return true
}

// sensorID is the configured sensor's ID, or "" without the section.
func (r *Runtime) sensorID() string {
	if s := r.cfg.NetworkSensor; s != nil {
		return s.SensorID
	}
	return ""
}

// stepSensorDB opens d when it is not open, or resumes it when it is
// blocked or drain-only, with smu held only to read and swap its handle.
// A step the node's stop has cancelled stops after its store call, and
// writes nothing more.
func (r *Runtime) stepSensorDB(ctx context.Context, d *database, starts *startTimes) {
	r.smu.Lock()
	prev, started := d.report, d.env != nil
	r.smu.Unlock()
	var (
		next *database
		err  error
	)
	switch {
	case !started || (prev.Mode == c5.ModeFailed && !prev.OpenBusy()):
		release(prev)
		next, err = r.startDB(ctx, d.spec, r.consumers, starts)
		if ctx.Err() != nil {
			if next != nil {
				release(next.report)
			}
			return
		}
		if err != nil {
			next = &database{spec: d.spec, report: c5.Report{Mode: c5.ModeFailed}}
			r.opt.Status.SetMode(d.spec.ID, c5.ModeFailed)
		}
	case prev.OpenBusy() || prev.Mode == c5.ModeBlocked || prev.Mode == c5.ModeDrainOnly:
		// Swapped out while Resume runs, so the accessor reports it not
		// open and never waits for it.
		r.smu.Lock()
		cur := *d
		d.out = true
		r.smu.Unlock()
		sctx, cancel := context.WithTimeout(ctx, StartupDeadline)
		cur.report = r.resume(sctx, &cur, prev)
		cancel()
		if ctx.Err() != nil {
			// The stop's release closes prev's store; a new one is closed
			// here.
			if cur.report.Store != prev.Store {
				release(cur.report)
			}
			return
		}
		next = &cur
		if err = r.adopt(next); err != nil {
			release(next.report)
			next = &database{spec: d.spec, report: c5.Report{Mode: c5.ModeFailed}}
			r.opt.Status.SetMode(d.spec.ID, c5.ModeFailed)
		}
	default:
		return
	}
	r.smu.Lock()
	d.env, d.policy, d.report, d.db, d.log, d.out = next.env, next.policy, next.report, next.db, next.log, false
	open := d.db != nil
	r.smu.Unlock()
	m := r.smgr
	switch {
	case !open && !m.notOpen[d.spec.ID]:
		m.notOpen[d.spec.ID] = true
		detail := fmt.Sprintf("sensor database %s is %s; the node collects without it, and tries again at each tick", d.spec.ID, d.report.Mode)
		if err != nil {
			detail += ": " + err.Error()
		}
		r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: AlarmSensorStoreNotOpen, At: r.opt.Now(), Detail: detail})
	case open:
		m.notOpen[d.spec.ID] = false
		delete(m.raised, d.spec.ID)
	}
	if mc, changed := c5.ModeChangeOf(prev, d.report, r.opt.Now()); changed {
		r.sensorModeChanged(ctx, d, mc)
	}
}

// sensorStoreClosed reports whether id is a database of the sensor store
// set that is not open, or is swapped out: one only the manager's startup
// or Resume can raise an alarm for.
func (r *Runtime) sensorStoreClosed(id c5.DatabaseID) bool {
	for _, d := range r.sdbs {
		if d.spec.ID == id {
			db, _, _ := r.view(d)
			return db == nil
		}
	}
	return false
}

// sensorStartupAlarm raises a sensor database's startup or Resume alarm,
// at most once for each code until the database opens, so a database the
// manager retries at every tick never pushes another alarm out of status
// (MaxStatusAlarms; D6's B4). Only the manager's goroutine calls it.
func (r *Runtime) sensorStartupAlarm(id c5.DatabaseID, a c5.Alarm) {
	m := r.smgr
	if m.raised[id] == nil {
		m.raised[id] = map[c5.AlarmCode]bool{}
	}
	if m.raised[id][a.Code] {
		return
	}
	m.raised[id][a.Code] = true
	r.opt.Status.Alarm(id, a)
}

// sensorModeChanged records a sensor database's mode change, at most once
// every SensorModeChangeEvery for each database (F9). A change within it is
// counted, and the next record's detail says how many were not recorded.
func (r *Runtime) sensorModeChanged(ctx context.Context, d *database, mc c5.ModeChange) {
	m := r.modeCapOf(d.spec.ID)
	if m.ever && r.opt.Mono()-m.at < SensorModeChangeEvery {
		m.held++
		return
	}
	r.recordMode(ctx, d, mc, m)
}

// flushModeChanges writes, for each sensor database with held changes
// whose hour has passed, the one record and event the cap allows, naming
// the mode it is in now, so the audit and health streams never show a
// mode the database has left for longer than SensorModeChangeEvery (D3's
// B1).
func (r *Runtime) flushModeChanges(ctx context.Context) {
	for _, d := range r.sdbs {
		m := r.modeCapOf(d.spec.ID)
		if m.held == 0 || r.opt.Mono()-m.at < SensorModeChangeEvery || ctx.Err() != nil {
			continue
		}
		r.smu.Lock()
		now := d.report.Mode
		r.smu.Unlock()
		r.recordMode(ctx, d, c5.ModeChange{From: m.to, To: now, At: r.opt.Now()}, m)
	}
}

func (r *Runtime) modeCapOf(id c5.DatabaseID) *modeCap {
	m := r.smgr.modes[id]
	if m == nil {
		m = &modeCap{}
		r.smgr.modes[id] = m
	}
	return m
}

// recordMode writes one store.mode_change record and its health event,
// carrying the changes held since the last one.
func (r *Runtime) recordMode(ctx context.Context, d *database, mc c5.ModeChange, m *modeCap) {
	if ctx.Err() != nil {
		return
	}
	detail := modeDetail(d, mc)
	details := map[string]string{"database": string(d.spec.ID), "from": orNone(mc.From), "to": string(mc.To)}
	if m.held > 0 {
		detail += fmt.Sprintf("; %d earlier mode changes of this database not recorded (at most one an hour)", m.held)
		details["not_recorded"] = strconv.Itoa(m.held)
	}
	r.audit(ctx, audit.ActionStoreModeChange, audit.OutcomeInfo, string(mc.To), detail)
	r.health(ctx, c5.HealthModeChanged, details)
	m.at, m.ever, m.to, m.held = r.opt.Mono(), true, mc.To, 0
}

// pruneSensorStores prunes the sensor store set as Prune prunes
// Runtime.dbs, on the manager's goroutine.
func (r *Runtime) pruneSensorStores(ctx context.Context) {
	for _, d := range r.sdbs {
		err := r.pruneDB(ctx, d)
		key := "prune " + string(d.spec.ID)
		if err != nil && ctx.Err() == nil {
			if r.quiet(key, true) {
				r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmPruneFailed, At: r.opt.Now(), Step: c5.StepPrune, Detail: "runtime prune: " + err.Error()})
			}
		} else if err == nil {
			r.quiet(key, false)
		}
	}
}

// closeSensorStores stops the manager, waiting at most SensorStopTimeout,
// then closes the sensor databases. When the manager has not stopped, its
// databases are closed when it does, or left to the process's exit, which
// releases their locks; Close does not wait for them.
func (r *Runtime) closeSensorStores() {
	if m := r.smgr; m != nil && m.cancel != nil {
		m.cancel()
		select {
		case <-m.done:
		case <-time.After(SensorStopTimeout):
			r.opt.Status.Raise("", AlarmSensorFailed, fmt.Sprintf("the sensor manager did not stop within %s; its databases are closed when it stops, or at the process's exit", SensorStopTimeout))
			go func() {
				<-m.done
				r.releaseSensorStores()
			}()
			return
		}
	}
	r.releaseSensorStores()
}

// releaseSensorStores closes every sensor database and releases its lock.
func (r *Runtime) releaseSensorStores() {
	r.smu.Lock()
	defer r.smu.Unlock()
	for _, d := range r.sdbs {
		release(d.report)
		d.report, d.db, d.log, d.out = c5.Report{}, nil, nil, false
	}
}
