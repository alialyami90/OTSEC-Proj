package node

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"
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
	// notOpen: AlarmSensorStoreNotOpen is raised for the database.
	notOpen map[c5.DatabaseID]bool
	// modes is each database's mode-change cap.
	modes map[c5.DatabaseID]*modeCap
	// intakeDown: AlarmSensorIntakeNotStarted is raised (sensor.go).
	intakeDown bool
}

// modeCap is when a database's last mode change was recorded, and how
// many changes since were not.
type modeCap struct {
	at   time.Duration
	ever bool
	held int
}

// startSensorManager starts the manager's goroutine. Without a sensor
// database there is none.
func (r *Runtime) startSensorManager() {
	if len(r.sdbs) == 0 || r.smgr == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := r.smgr
	m.kick, m.cancel, m.done = make(chan struct{}, 1), cancel, make(chan struct{})
	go func() {
		defer close(m.done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.kick:
			}
			if !r.sensorStep(ctx, newStartTimes()) {
				return
			}
			r.pruneSensorStores(ctx)
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

// sensorStep opens what is not open of the sensor store set, resumes what
// is blocked or drain-only, and starts the intake if it is not started.
// Start runs the first step, and the
// manager each later one. A panic in it is recovered: it raises
// AlarmSensorFailed and stops the sensor's work, and sensorStep reports
// false.
func (r *Runtime) sensorStep(ctx context.Context, starts *startTimes) (ok bool) {
	if len(r.sdbs) == 0 || r.sensorFailed.Load() {
		return false
	}
	if r.smgr == nil {
		r.smgr = &sensorManager{notOpen: map[c5.DatabaseID]bool{}, modes: map[c5.DatabaseID]*modeCap{}}
	}
	defer func() {
		if p := recover(); p != nil {
			r.sensorFailed.Store(true)
			r.opt.Status.Raise("", AlarmSensorFailed, fmt.Sprintf("the sensor's work panicked and is stopped until the node restarts; SER, Syslog and forwarding go on: %v\n%s", p, debug.Stack()))
			ok = false
		}
	}()
	for _, d := range r.sdbs {
		r.stepSensorDB(ctx, d, starts)
	}
	r.startIntake(ctx)
	return true
}

// stepSensorDB opens d when it is not open, or resumes it when it is
// blocked or drain-only, with smu held only to read and swap its handle.
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
	}
	if mc, changed := c5.ModeChangeOf(prev, d.report, r.opt.Now()); changed {
		r.sensorModeChanged(ctx, d, mc)
	}
}

// sensorModeChanged records a sensor database's mode change, at most once
// every SensorModeChangeEvery for each database (F9). A change within it is
// counted, and the next record's detail says how many were not recorded.
func (r *Runtime) sensorModeChanged(ctx context.Context, d *database, mc c5.ModeChange) {
	m := r.smgr.modes[d.spec.ID]
	if m == nil {
		m = &modeCap{}
		r.smgr.modes[d.spec.ID] = m
	}
	now := r.opt.Mono()
	if m.ever && now-m.at < SensorModeChangeEvery {
		m.held++
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
	m.at, m.ever, m.held = now, true, 0
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
