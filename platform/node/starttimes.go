package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// StartPhases are the node start phases the start timing line names, in
// order (P4-H2). The names are fixed, since CI and D6's workflows read
// them; store phases are summed across the databases. Start runs the
// phases up to status, and Run the rest, adding its own status write to
// status. Run's line ends before the scheduler's first collector exchange:
// that waits for the first entry's due time, a minute after start (AP-13),
// so it is not part of starting.
var StartPhases = []string{
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
// in StartPhases order, and other, the part of the total no phase covers.
// Every value is whole milliseconds. It holds no path, key or device text.
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
	return b.String()
}

// StartLine is the start timing line of Start's phases, for tests that
// start a Runtime without Run.
func (r *Runtime) StartLine() string { return r.starts.line("runtime") }

// timedEnv is a StartupEnv that adds the time of its lock, open and reserve
// calls to t, and their sum to spent.
type timedEnv struct {
	c5.StartupEnv
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
	defer e.took("store-reserve", time.Now())
	return e.StartupEnv.CreateReserve(ctx, r, bytes)
}

func (e *timedEnv) ReleaseReserve(ctx context.Context, r c5.Reserve) error {
	defer e.took("store-reserve", time.Now())
	return e.StartupEnv.ReleaseReserve(ctx, r)
}
