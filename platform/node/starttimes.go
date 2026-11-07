package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// StartPhases are the node start phases the start timing line names, in
// order (P4-H2). The names are fixed, since CI and D6's workflows read
// them; store phases are summed across the databases. The command's
// PreStart gives config and scm, Start runs the phases up to status, and
// Run the rest, adding its own status write to status. Run's line ends before the scheduler's first collector exchange:
// that waits for the first entry's due time, a minute after start (AP-13),
// so it is not part of starting.
var StartPhases = []string{
	"config",        // the command's LoadConfig (PreStart)
	"scm",           // from the loaded configuration to Run: the SCM handshake as a service
	"store-lock",    // c5 StartupEnv.Lock
	"store-open",    // StartupEnv.Open
	"store-reserve", // StartupEnv.CreateReserve and ReleaseReserve
	"store-startup", // the rest of c5.RunStartup
	"store-adopt",   // Runtime.adopt: alarms, mode and the Log
	"register",      // the command register's verified copy
	"record-start",  // the audit chain start, mode changes and service.start
	"holds",         // reconcileHolds and advanceHolds
	"status",        // the status file
	"forwarding",    // NewForwarding
	"listening",     // NewListening
	"node-keys",     // RecordNodeKeys, CheckNodeKeys and RecordLabTLSFiles
	"scheduler",     // NewScheduler
	"listen",        // Listening.Listen
	"first-check",   // the first forwarding check and listener publish
}

// ReserveParts split store-reserve, in this order, and sum to it (P4-H4).
// The line names them after other, outside the sum to total, so that
// store-reserve measures the same thing before and after the split.
var ReserveParts = []string{
	"reserve-release", // ReleaseReserve
	"reserve-create",  // CreateReserve: creating the file
	"reserve-write",   // CreateReserve: writing its zeros
	"reserve-sync",    // CreateReserve: the file flush
	"reserve-dirsync", // CreateReserve: the folder flush; nothing on Windows
	"reserve-close",   // CreateReserve: the rest, chiefly the file's close
}

// startTimes accumulates the time of each start phase on the monotonic
// clock, never the node clock, which a test clock may drive.
type startTimes struct {
	began time.Time
	d     map[string]time.Duration
}

func newStartTimes() *startTimes {
	return &startTimes{began: time.Now(), d: map[string]time.Duration{}}
}

// add adds the time since from to phase.
func (t *startTimes) add(phase string, from time.Time) { t.d[phase] += time.Since(from) }

// line is the start timing line: scope, the total since began, each phase
// in StartPhases order, other, the part of the total no phase covers, and
// then ReserveParts. Every value is whole milliseconds. It holds no path,
// key or device text.
func (t *startTimes) line(scope string) string {
	total := time.Since(t.began)
	var b strings.Builder
	fmt.Fprintf(&b, "otsec node start: scope=%s total=%dms", scope, total.Milliseconds())
	other := total
	for _, p := range StartPhases {
		fmt.Fprintf(&b, " %s=%dms", p, t.d[p].Milliseconds())
		other -= t.d[p]
	}
	fmt.Fprintf(&b, " other=%dms", max(other, 0).Milliseconds())
	for _, p := range ReserveParts {
		fmt.Fprintf(&b, " %s=%dms", p, t.d[p].Milliseconds())
	}
	return b.String()
}

// PreStart is the part of a node's start before Run, as the otsec command
// measured it on the monotonic clock: Began at the command's entry, and
// Config the time its LoadConfig took. Run's total then counts from Began,
// and the time from the loaded configuration to Run is scm. The zero
// PreStart counts from Run's own start, with config and scm zero.
type PreStart struct {
	Began  time.Time
	Config time.Duration
}

// from makes t count from p.Began, entered being when Run was entered.
func (t *startTimes) from(p PreStart, entered time.Time) {
	if p.Began.IsZero() {
		return
	}
	t.began = p.Began
	t.d["config"] = p.Config
	t.d["scm"] = max(entered.Sub(p.Began)-p.Config, 0)
}

// StartLine is the start timing line of Start's phases, for tests that
// start a Runtime without Run.
func (r *Runtime) StartLine() string { return r.starts.line("runtime") }

// timedEnv is a StartupEnv that adds the time of its lock, open and reserve
// calls to t, and their sum to spent. The reserve calls' time is also split
// into ReserveParts, with store's own times from env.
type timedEnv struct {
	c5.StartupEnv
	env   *store.Env
	t     *startTimes
	spent time.Duration
}

func (e *timedEnv) took(phase string, from time.Time) {
	e.t.add(phase, from)
	e.spent += time.Since(from)
}

func (e *timedEnv) Lock(ctx context.Context) (func(), error) {
	defer e.took("store-lock", time.Now())
	return e.StartupEnv.Lock(ctx)
}

func (e *timedEnv) Open(ctx context.Context) (c5.RecoveryStore, error) {
	defer e.took("store-open", time.Now())
	return e.StartupEnv.Open(ctx)
}

func (e *timedEnv) CreateReserve(ctx context.Context, r c5.Reserve, bytes int64) error {
	from, before := time.Now(), e.env.ReserveTimes()
	defer func() {
		took, after := time.Since(from), e.env.ReserveTimes()
		rest := took
		for p, d := range map[string]time.Duration{
			"reserve-create":  after.Create - before.Create,
			"reserve-write":   after.Write - before.Write,
			"reserve-sync":    after.Sync - before.Sync,
			"reserve-dirsync": after.DirSync - before.DirSync,
		} {
			e.t.d[p] += d
			rest -= d
		}
		e.t.d["reserve-close"] += max(rest, 0)
		e.t.d["store-reserve"] += took
		e.spent += took
	}()
	return e.StartupEnv.CreateReserve(ctx, r, bytes)
}

func (e *timedEnv) ReleaseReserve(ctx context.Context, r c5.Reserve) error {
	from := time.Now()
	defer func() {
		took := time.Since(from)
		e.t.d["reserve-release"] += took
		e.t.d["store-reserve"] += took
		e.spent += took
	}()
	return e.StartupEnv.ReleaseReserve(ctx, r)
}
