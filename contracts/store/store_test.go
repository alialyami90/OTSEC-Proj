package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/version"
)

func isCode(err error, c Code) bool { return errors.Is(err, &Error{Code: c}) }

func TestIdentifier(t *testing.T) {
	id, err := version.Parse(Identifier)
	if err != nil || id.Name != "store" || id.Major != 0 || id.Minor != 1 {
		t.Fatalf("Identifier %q: %+v %v", Identifier, id, err)
	}
}

func goodLayout() Layout {
	q := func(c StreamClass) Quota { return Quota{Class: c, Bytes: 1 << 30, WarnFraction: 0.8} }
	return Layout{Databases: []Database{
		{ID: "evidence", Writer: "ied", Streams: []StreamID{"relay1/ser"}, Classes: []StreamClass{ClassAdapterEvidence}, Quotas: []Quota{q(ClassAdapterEvidence)}},
		{ID: "syslog", Writer: "telemetry", Streams: []StreamID{"udp514/2488"}, Classes: []StreamClass{ClassSyslogDatagram, ClassSyslogStream}, Quotas: []Quota{q(ClassSyslogDatagram), q(ClassSyslogStream)}},
		{ID: "audit", Writer: "security", Streams: []StreamID{"audit"}, Classes: []StreamClass{ClassAudit}, Quotas: []Quota{q(ClassAudit)}},
	}}
}

func TestLayout(t *testing.T) {
	if err := goodLayout().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Layout){
		"no writer":          func(l *Layout) { l.Databases[0].Writer = "" },
		"duplicate database": func(l *Layout) { l.Databases[1].ID = "evidence" },
		"stream in two":      func(l *Layout) { l.Databases[1].Streams = append(l.Databases[1].Streams, "relay1/ser") },
		"audit mixed": func(l *Layout) {
			l.Databases[2].Classes = append(l.Databases[2].Classes, ClassPlatform)
			l.Databases[2].Quotas = append(l.Databases[2].Quotas, Quota{ClassPlatform, 1, 0.5})
		},
		"class without quota": func(l *Layout) { l.Databases[1].Quotas = l.Databases[1].Quotas[:1] },
		"quota for absent":    func(l *Layout) { l.Databases[0].Quotas = append(l.Databases[0].Quotas, Quota{ClassAudit, 1, 0.5}) },
		"bad warn fraction":   func(l *Layout) { l.Databases[0].Quotas[0].WarnFraction = 1 },
		"unknown class":       func(l *Layout) { l.Databases[0].Classes[0] = "video" },
		"two audit streams":   func(l *Layout) { l.Databases[2].Streams = append(l.Databases[2].Streams, "audit2") },
		"no audit stream":     func(l *Layout) { l.Databases = l.Databases[:2] },
	} {
		l := goodLayout()
		mutate(&l)
		if err := l.Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%s: Validate = %v, want invalid", name, err)
		}
	}
}

func TestFullActions(t *testing.T) {
	want := map[StreamClass]FullAction{
		ClassAdapterEvidence: StopCollecting,
		ClassSyslogStream:    RefuseNew,
		ClassSyslogDatagram:  DropAndCount,
		ClassAudit:           FailClosed,
		ClassPlatform:        RefuseNew,
	}
	for _, c := range Classes {
		got, err := ActionFor(c)
		if err != nil || got != want[c] {
			t.Errorf("ActionFor(%s) = %s, %v; want %s", c, got, err, want[c])
		}
	}
	if _, err := ActionFor("other"); err == nil {
		t.Error("unknown class accepted")
	}
}

func TestGroupOptionsRequireGrouping(t *testing.T) {
	if err := DefaultGroup.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, o := range []GroupOptions{{1, time.Millisecond}, {0, time.Millisecond}, {100, 0}, {100, 2 * time.Second}} {
		if err := o.Validate(); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

func rec(stream StreamID, s string) Record {
	return Record{Stream: stream, Class: ClassAdapterEvidence, Event: []byte(s)}
}

// gatedCommitter blocks inside CommitBatch until released, so a test can look
// at the caller while the commit has not yet returned.
type gatedCommitter struct {
	*fake
	entered chan struct{}
	release chan struct{}
}

func (g gatedCommitter) CommitBatch(ctx context.Context, s StreamID, recs []Record) (Commit, error) {
	g.entered <- struct{}{}
	<-g.release
	return g.fake.CommitBatch(ctx, s, recs)
}

func TestNoReceiptBeforeCommitReturns(t *testing.T) {
	f := newFake()
	g := gatedCommitter{f, make(chan struct{}, 1), make(chan struct{})}
	l, err := NewLog(g, f.node, GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan Receipt, 1)
	go func() {
		r, err := l.Append(context.Background(), rec("s", "a"))
		if err != nil {
			t.Error(err)
		}
		got <- r
	}()
	<-g.entered // the commit has started and not returned
	select {
	case <-got:
		t.Fatal("Append returned a receipt while its commit had not returned")
	case <-time.After(50 * time.Millisecond):
	}
	close(g.release)
	r := <-got
	if r == nil || r.Key() != (Key{NodeID: f.node, Stream: "s", Seq: 1}) {
		t.Fatalf("receipt %v", r)
	}
	if len(f.events["s"]) != 1 {
		t.Fatal("receipt released for an event the store does not hold")
	}
}

func TestGroupCommit(t *testing.T) {
	f := newFake()
	l, _ := NewLog(f, f.node, GroupOptions{MaxEvents: 10, MaxWait: time.Second}, nil)
	var wg sync.WaitGroup
	keys := make(chan Key, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := l.Append(context.Background(), rec("s", "x"))
			if err != nil {
				t.Error(err)
				return
			}
			keys <- r.Key()
		}()
	}
	wg.Wait()
	close(keys)
	if n := countCalls(f, "CommitBatch"); n != 1 {
		t.Fatalf("10 appends with MaxEvents 10 made %d commits, want 1", n)
	}
	var seqs []Seq
	for k := range keys {
		seqs = append(seqs, k.Seq)
	}
	slices.Sort(seqs)
	if !slices.Equal(seqs, []Seq{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Fatalf("seqs %v", seqs)
	}

	// MaxWait commits a group that never fills.
	f2 := newFake()
	l2, _ := NewLog(f2, f2.node, GroupOptions{MaxEvents: 100, MaxWait: 10 * time.Millisecond}, nil)
	if _, err := l2.Append(context.Background(), rec("s", "y")); err != nil {
		t.Fatal(err)
	}
	if n := countCalls(f2, "CommitBatch"); n != 1 {
		t.Fatalf("timer flush made %d commits", n)
	}
}

func countCalls(f *fake, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}

// orderCommitter fails the test if a stream's commits ever overlap.
type orderCommitter struct {
	*fake
	busy  sync.Mutex
	first chan struct{}
	once  sync.Once
	t     *testing.T
}

func (o *orderCommitter) CommitBatch(ctx context.Context, s StreamID, recs []Record) (Commit, error) {
	if !o.busy.TryLock() {
		o.t.Error("two commits of one stream ran at once")
		return Commit{}, errInjected
	}
	defer o.busy.Unlock()
	o.once.Do(func() { <-o.first }) // hold the first commit until the test lets go
	return o.fake.CommitBatch(ctx, s, recs)
}

func TestGroupsOfAStreamCommitInOrder(t *testing.T) {
	f := newFake()
	o := &orderCommitter{fake: f, first: make(chan struct{}), t: t}
	l, _ := NewLog(o, f.node, GroupOptions{MaxEvents: 2, MaxWait: 5 * time.Millisecond}, nil)
	done := make(chan struct{})
	go func() { l.Append(context.Background(), rec("s", "1")); done <- struct{}{} }()
	time.Sleep(20 * time.Millisecond) // group 1 is flushed and blocked in its commit
	go func() { l.Append(context.Background(), rec("s", "2")); done <- struct{}{} }()
	go func() { l.Append(context.Background(), rec("s", "3")); done <- struct{}{} }()
	time.Sleep(20 * time.Millisecond) // group 2 is full and waiting for group 1
	close(o.first)
	for i := 0; i < 3; i++ {
		<-done
	}
	ev := f.events["s"]
	if len(ev) != 3 || string(ev[0].Event) != "1" {
		t.Fatalf("group order not kept: %q", []string{string(ev[0].Event), string(ev[1].Event), string(ev[2].Event)})
	}
}

func TestCommitFailuresStopTheLog(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(*fake)
		last  map[StreamID]Seq
		want  Code
	}{
		"commit error": {func(f *fake) { f.fail["CommitBatch"] = errInjected }, nil, CodeCommitFailed},
		"NORMAL":       {func(f *fake) { f.sync = SyncNormal }, nil, CodeCommitNotDurable},
		"unknown sync": {func(f *fake) { f.sync = SyncUnknown }, nil, CodeCommitNotDurable},
		"gap":          {func(f *fake) {}, map[StreamID]Seq{"s": 5}, CodeCommitMismatch},
	} {
		f := newFake()
		tc.setup(f)
		l, _ := NewLog(f, f.node, GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond}, tc.last)
		r, err := l.Append(context.Background(), rec("s", "a"))
		if r != nil || !isCode(err, tc.want) {
			t.Errorf("%s: Append = %v, %v; want no receipt and %s", name, r, err, tc.want)
		}
		delete(f.fail, "CommitBatch")
		f.sync = SyncFull
		if _, err := l.Append(context.Background(), rec("s", "b")); !isCode(err, CodeLogStopped) {
			t.Errorf("%s: Append after failure = %v, want log-stopped", name, err)
		}
	}
}

func TestAppendCancelledGivesNoReceipt(t *testing.T) {
	f := newFake()
	l, _ := NewLog(f, f.node, GroupOptions{MaxEvents: 100, MaxWait: time.Second}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := l.Append(ctx, rec("s", "a")); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Append = %v, %v", r, err)
	}
}

func TestForgedReceiptIsUnusable(t *testing.T) {
	type forged struct{ Receipt }
	var r Receipt = forged{}
	defer func() {
		if recover() == nil {
			t.Fatal("a receipt not made by Log yielded a key")
		}
	}()
	_ = r.Key()
}

func TestRecordValidate(t *testing.T) {
	for _, r := range []Record{{Class: ClassAudit, Event: []byte("x")}, {Stream: "s", Event: []byte("x")}, {Stream: "s", Class: ClassAudit}} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}

func TestCursors(t *testing.T) {
	f := newFake()
	f.seed("s", 10, f.now)
	ctx := context.Background()
	if err := f.SaveCursor(ctx, Cursor{"up", "s", 6}); err != nil {
		t.Fatal(err)
	}
	if err := f.SaveCursor(ctx, Cursor{"up", "s", 5}); !isCode(err, CodeCursorRegress) {
		t.Errorf("regress: %v", err)
	}
	if err := f.SaveCursor(ctx, Cursor{"up", "s", 11}); !isCode(err, CodeCursorAhead) {
		t.Errorf("ahead: %v", err)
	}
}

func TestComputeBoundary(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	old := f.now.Add(-2 * time.Hour)
	f.seed("s", 4, old)   // seqs 1-4, outside a 1 h window
	f.seed("s", 6, f.now) // seqs 5-10
	req := Consumer{ID: "central", Stream: "s", Delivery: Required}
	be := Consumer{ID: "rfc5425", Stream: "s", Delivery: BestEffort, ReplayWindow: time.Hour}

	b, err := ComputeBoundary(ctx, f, f, []Consumer{req}, "s", ClassAdapterEvidence, f.now)
	if err != nil || b.Through() != 0 {
		t.Fatalf("required consumer with no cursor: %v %v, want 0", b, err)
	}
	f.SaveCursor(ctx, Cursor{"central", "s", 8})
	b, _ = ComputeBoundary(ctx, f, f, []Consumer{req, be}, "s", ClassAdapterEvidence, f.now)
	if b.Through() != 4 {
		t.Fatalf("required at 8, best-effort window ends at 4: got %d", b.Through())
	}
	// A best-effort cursor means "sent", not "delivered": it never makes
	// events inside the replay window prunable (A4 review of C5, change 1).
	f.SaveCursor(ctx, Cursor{"rfc5425", "s", 10})
	b, _ = ComputeBoundary(ctx, f, f, []Consumer{req, be}, "s", ClassAdapterEvidence, f.now)
	if b.Through() != 4 {
		t.Fatalf("best-effort cursor 10 inside its window moved the boundary to %d, want 4", b.Through())
	}
	if _, err := ComputeBoundary(ctx, f, f, nil, "s", ClassAdapterEvidence, f.now); !isCode(err, CodeNoConsumers) {
		t.Fatalf("no consumers: %v", err)
	}
	for _, c := range []Consumer{{ID: "x", Stream: "s", Delivery: Required, ReplayWindow: time.Hour}, {ID: "x", Stream: "s", Delivery: BestEffort}, {ID: "x", Stream: "s", Delivery: "sometimes"}} {
		if _, err := ComputeBoundary(ctx, f, f, []Consumer{c}, "s", ClassAdapterEvidence, f.now); !isCode(err, CodeInvalid) {
			t.Errorf("consumer %+v accepted", c)
		}
	}
}

// The boundary is read from persisted cursors on every call: a cursor the
// forwarder holds in memory but has not saved moves nothing.
func TestBoundaryIgnoresUnpersistedCursor(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.seed("s", 10, f.now)
	f.SaveCursor(ctx, Cursor{"central", "s", 3})
	inMemory := Cursor{"central", "s", 9} // sent and confirmed, not yet saved
	_ = inMemory
	b, _ := ComputeBoundary(ctx, f, f, []Consumer{{ID: "central", Stream: "s", Delivery: Required}}, "s", ClassAdapterEvidence, f.now)
	if b.Through() != 3 {
		t.Fatalf("boundary %d, want the persisted 3", b.Through())
	}
	f.PruneStep(ctx, b, 100)
	if got := f.retained("s"); got[0] != 4 {
		t.Fatalf("pruned past the persisted cursor: first retained %d", got[0])
	}
}

// Startup.

func policy() StartupPolicy {
	return StartupPolicy{
		Streams:                []StreamSpec{{"s", ClassAdapterEvidence}},
		Consumers:              []Consumer{{ID: "central", Stream: "s", Delivery: Required}},
		RecoveryReserveBytes:   512 << 10,
		LastResortReserveBytes: 128 << 10,
		OpenHeadroomBytes:      96 << 10,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
		Now:                    func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) },
	}
}

// existing returns a fake whose earlier run left a store and both reserves,
// with the disk full.
func existing() *fake {
	f := newFake()
	f.seed("s", 200, f.now)
	f.reserves[ReserveRecovery] = true
	f.reserves[ReserveLastResort] = true
	f.free = 0
	return f
}

func indexOf(calls []string, name string) int { return slices.Index(calls, name) }

func hasAlarm(r Report, c AlarmCode) bool {
	return slices.ContainsFunc(r.Alarms, func(a Alarm) bool { return a.Code == c })
}

func TestStartupOrder(t *testing.T) {
	f := existing()
	r := RunStartup(context.Background(), f, policy())
	if r.Mode != ModeCollecting || r.Err != nil {
		t.Fatalf("mode %s err %v steps %+v", r.Mode, r.Err, r.Steps)
	}
	want := []string{"Lock", "StoreExists", "ReserveExists:recovery", "ReserveExists:last-resort", "ReleaseReserve:recovery", "FreeBytes", "Open", "CheckSettings", "QuickCheck"}
	if got := f.calls[:len(want)]; !slices.Equal(got, want) {
		t.Fatalf("calls %v, want prefix %v", got, want)
	}
	if indexOf(f.calls, "CreateReserve:recovery") < indexOf(f.calls, "Open") {
		t.Fatal("reserve re-created before the store was opened")
	}
	if len(f.violations) > 0 {
		t.Fatal(f.violations)
	}
	if !f.reserves[ReserveRecovery] || !f.reserves[ReserveLastResort] || r.Store == nil || r.Unlock == nil {
		t.Fatalf("after startup: reserves %v store %v", f.reserves, r.Store)
	}
}

func TestStartupNewStore(t *testing.T) {
	f := newFake()
	r := RunStartup(context.Background(), f, policy())
	if r.Mode != ModeCollecting || !f.reserves[ReserveRecovery] || !f.reserves[ReserveLastResort] {
		t.Fatalf("new store: mode %s reserves %v steps %+v", r.Mode, f.reserves, r.Steps)
	}
	if indexOf(f.calls, "ReleaseReserve:recovery") >= 0 {
		t.Fatal("released a reserve that did not exist")
	}
}

// Every step before the open, made to fail, stops startup without opening
// the store. A failed reserve release in particular never continues.
func TestStartupFailsClosedBeforeOpen(t *testing.T) {
	for _, step := range []struct {
		call  string
		step  Step
		alarm AlarmCode
	}{
		{"Lock", StepLock, AlarmLockFailed},
		{"StoreExists", StepInspect, AlarmOpenBlocked},
		{"ReserveExists:recovery", StepInspect, AlarmOpenBlocked},
		{"ReserveExists:last-resort", StepInspect, AlarmOpenBlocked},
		{"ReleaseReserve:recovery", StepReleaseReserve, AlarmReserveReleaseFailed},
		{"FreeBytes", StepHeadroom, AlarmOpenBlocked},
	} {
		f := existing()
		f.fail[step.call] = errInjected
		r := RunStartup(context.Background(), f, policy())
		if r.Mode != ModeFailed || !isCode(r.Err, CodeStartupFailed) || !errors.Is(r.Err, errInjected) {
			t.Errorf("%s: mode %s err %v", step.call, r.Mode, r.Err)
		}
		if indexOf(f.calls, "Open") >= 0 || r.Store != nil {
			t.Errorf("%s failed but the store was opened", step.call)
		}
		last := r.Steps[len(r.Steps)-1]
		if last.Step != step.step || last.Err == nil || !hasAlarm(r, step.alarm) {
			t.Errorf("%s: last step %+v alarms %v", step.call, last, r.Alarms)
		}
	}
}

func TestStartupFailsAtOrAfterOpen(t *testing.T) {
	for _, step := range []struct {
		call  string
		step  Step
		alarm AlarmCode
	}{
		{"Open", StepOpen, AlarmOpenFailed},
		{"CheckSettings", StepSettings, AlarmSettingsInvalid},
		{"QuickCheck", StepIntegrity, AlarmIntegrityFailed},
	} {
		f := existing()
		f.fail[step.call] = errInjected
		r := RunStartup(context.Background(), f, policy())
		if r.Mode != ModeFailed || r.Store != nil || !hasAlarm(r, step.alarm) {
			t.Errorf("%s: mode %s store %v alarms %v", step.call, r.Mode, r.Store, r.Alarms)
		}
		if indexOf(f.calls, "PruneStep") >= 0 || indexOf(f.calls, "CreateReserve:recovery") >= 0 {
			t.Errorf("%s failed but startup went on to prune or re-create reserves", step.call)
		}
	}
}

// Failures after the store is open and checked leave it open for draining,
// with collectors not started.
func TestStartupDegradesToDrainOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fake)
		alarm AlarmCode
	}{
		{"prune", func(f *fake) { f.fail["PruneStep"] = errInjected }, AlarmPruneFailed},
		{"compact", func(f *fake) { f.fail["CompactStep"] = errInjected }, AlarmCompactFailed},
		{"recreate", func(f *fake) { f.fail["CreateReserve:recovery"] = errInjected }, AlarmReserveRecreateFailed},
	} {
		f := existing()
		f.cursors["s"] = map[ConsumerID]Seq{"central": 150}
		f.limit = 200 * f.eventSize // full, so startup prunes
		tc.setup(f)
		r := RunStartup(context.Background(), f, policy())
		if r.Mode != ModeDrainOnly || r.Store == nil || !hasAlarm(r, tc.alarm) || !hasAlarm(r, AlarmDrainOnly) {
			t.Errorf("%s: mode %s store %v alarms %v", tc.name, r.Mode, r.Store, r.Alarms)
		}
	}
}

func TestStartupBlockedWithoutHeadroom(t *testing.T) {
	f := existing()
	f.reserves[ReserveRecovery] = false
	f.reserves[ReserveLastResort] = false // both used up by earlier runs
	f.free = 28672                        // F-013: less than a -shm region
	r := RunStartup(context.Background(), f, policy())
	if r.Mode != ModeBlocked || r.Store != nil || !hasAlarm(r, AlarmOpenBlocked) || !hasAlarm(r, AlarmReserveMissing) {
		t.Fatalf("mode %s alarms %v", r.Mode, r.Alarms)
	}
	if indexOf(f.calls, "Open") >= 0 {
		t.Fatal("store opened below the open headroom")
	}
	if r.Unlock == nil {
		t.Fatal("blocked startup must keep the lock")
	}
}

// F-013's condition: the store exists and the recovery reserve does not.
// Startup releases the last-resort reserve, opens, and recovers.
func TestStartupNoRecoveryReserve(t *testing.T) {
	f := existing()
	f.reserves[ReserveRecovery] = false
	f.cursors["s"] = map[ConsumerID]Seq{"central": 150}
	f.limit = 200 * f.eventSize
	p := policy()
	p.PruneTarget = 0.5
	r := RunStartup(context.Background(), f, p)
	if indexOf(f.calls, "ReleaseReserve:last-resort") > indexOf(f.calls, "Open") || indexOf(f.calls, "ReleaseReserve:last-resort") < 0 {
		t.Fatalf("last-resort reserve not released before open: %v", f.calls)
	}
	if len(f.violations) > 0 {
		t.Fatal(f.violations)
	}
	if r.Mode != ModeCollecting || !hasAlarm(r, AlarmReserveMissing) || !f.reserves[ReserveRecovery] || !f.reserves[ReserveLastResort] {
		t.Fatalf("mode %s reserves %v alarms %v steps %+v", r.Mode, f.reserves, r.Alarms, r.Steps)
	}

	// Nothing confirmed, so nothing can be pruned and the reserve cannot be
	// re-created: the store stays open to drain, collectors stay off.
	f = existing()
	f.reserves[ReserveRecovery] = false
	f.limit = 200 * f.eventSize
	r = RunStartup(context.Background(), f, policy())
	if r.Mode != ModeDrainOnly || r.Store == nil || !hasAlarm(r, AlarmReserveRecreateFailed) {
		t.Fatalf("unconfirmed store: mode %s alarms %v", r.Mode, r.Alarms)
	}
	if got := f.retained("s"); len(got) != 200 {
		t.Fatalf("pruned %d unconfirmed events", 200-len(got))
	}
}

// R-A5-5: a recovery that dies part-way through pruning and is run again
// never prunes past the persisted cursors, because the boundary is
// recomputed from them before every step.
func TestInterruptedPruneNeverPassesCursor(t *testing.T) {
	f := existing()
	f.cursors["s"] = map[ConsumerID]Seq{"central": 120}
	f.limit = 200 * f.eventSize
	f.pruneLimit = 1 // dies after one 50-event step
	p := policy()
	p.PruneTarget = 0.3 // asks for more than the cursor allows
	r := RunStartup(context.Background(), f, p)
	if r.Mode != ModeDrainOnly {
		t.Fatalf("first run: mode %s", r.Mode)
	}
	f.pruneLimit = 0
	RunStartup(context.Background(), f, p) // the restart
	got := f.retained("s")
	if len(got) == 0 || got[0] != 121 || got[len(got)-1] != 200 {
		t.Fatalf("after two runs retained %v..%v, want 121..200", got[0], got[len(got)-1])
	}
}

func TestStartupPolicyValidate(t *testing.T) {
	for name, mutate := range map[string]func(*StartupPolicy){
		"no streams":            func(p *StartupPolicy) { p.Streams = nil },
		"headroom below a -shm": func(p *StartupPolicy) { p.OpenHeadroomBytes = 32 << 10 },
		"last-resort too small": func(p *StartupPolicy) { p.LastResortReserveBytes = p.OpenHeadroomBytes - 1 },
		"no recovery reserve":   func(p *StartupPolicy) { p.RecoveryReserveBytes = 0 },
		"one large prune":       func(p *StartupPolicy) { p.PruneStepEvents = 100000 },
		"prune target 1":        func(p *StartupPolicy) { p.PruneTarget = 1 },
		"bad consumer":          func(p *StartupPolicy) { p.Consumers[0].Delivery = "" },
		"zero compaction step":  func(p *StartupPolicy) { p.CompactStepPages = 0 },
	} {
		p := policy()
		mutate(&p)
		f := existing()
		r := RunStartup(context.Background(), f, p)
		if r.Mode != ModeFailed || len(f.calls) != 0 {
			t.Errorf("%s: mode %s calls %v", name, r.Mode, f.calls)
		}
	}
}

func TestErrorText(t *testing.T) {
	err := errf(CodeCursorAhead, errInjected, "stream %s", "s")
	if !strings.Contains(err.Error(), "cursor-ahead") || !errors.Is(err, errInjected) {
		t.Fatal(err)
	}
}

func capture(b string) *Capture {
	sum := sha256.Sum256([]byte(b))
	return &Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: []byte(b)}
}

func TestAppendBatch(t *testing.T) {
	f := newFake()
	l, _ := NewLog(f, f.node, GroupOptions{MaxEvents: 100, MaxWait: time.Second}, nil)
	// One record waits in a group; the batch must commit after it.
	first := make(chan Receipt)
	go func() { r, _ := l.Append(context.Background(), rec("s", "single")); first <- r }()
	time.Sleep(10 * time.Millisecond)
	report := capture("SER report bytes")
	recs := []Record{rec("s", "row1"), rec("s", "row2"), rec("s", "row3")}
	for i := range recs {
		recs[i].Capture = report
	}
	recs[2].SourceCursor = []byte("row 3")
	got, err := l.AppendBatch(context.Background(), recs)
	if err != nil {
		t.Fatal(err)
	}
	if r := <-first; r.Key().Seq != 1 {
		t.Fatalf("waiting record got seq %d, want 1", r.Key().Seq)
	}
	for i, r := range got {
		if r.Key().Seq != Seq(i+2) {
			t.Fatalf("batch receipt %d has seq %d", i, r.Key().Seq)
		}
	}
	if n := countCalls(f, "CommitBatch"); n != 2 {
		t.Fatalf("%d commits, want 2 (the waiting group, then the batch)", n)
	}
	ev := f.events["s"]
	if ev[3].EvidenceRef != EvidenceRef(report.SHA256) || string(ev[3].SourceCursor) != "row 3" {
		t.Fatalf("batch stored without its capture or cursor: %+v", ev[3])
	}
	if c, err := f.ReadCapture(context.Background(), ev[1].EvidenceRef); err != nil || string(c.Bytes) != "SER report bytes" {
		t.Fatalf("capture: %v %v", c, err)
	}

	for name, bad := range map[string][]Record{
		"empty":         nil,
		"mixed streams": {rec("s", "a"), rec("t", "b")},
		"bad digest":    {{Stream: "s", Class: ClassAdapterEvidence, Event: []byte("x"), Capture: &Capture{SHA256: "00", Bytes: []byte("x")}}},
		"stream colon":  {rec("s:1", "a")},
	} {
		if _, err := l.AppendBatch(context.Background(), bad); !isCode(err, CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewLogRejectsBadNodeID(t *testing.T) {
	for _, n := range []NodeID{"", "Site-A", "site_a", "-a"} {
		if _, err := NewLog(newFake(), n, DefaultGroup, nil); !isCode(err, CodeInvalid) {
			t.Errorf("node %q: %v", n, err)
		}
	}
}

func TestKeyText(t *testing.T) {
	if s := (Key{NodeID: "site-a-node1", Stream: "relay1/ser", Seq: 7}).String(); s != "site-a-node1:relay1/ser:7" {
		t.Fatal(s)
	}
}

func TestReleaseOfLastResortFailingStopsStartup(t *testing.T) {
	f := existing()
	f.reserves[ReserveRecovery] = false
	f.fail["ReleaseReserve:last-resort"] = errInjected
	r := RunStartup(context.Background(), f, policy())
	if r.Mode != ModeFailed || indexOf(f.calls, "Open") >= 0 || !hasAlarm(r, AlarmReserveReleaseFailed) {
		t.Fatalf("mode %s calls %v alarms %v", r.Mode, f.calls, r.Alarms)
	}
}

func TestOnlyCollectingAcceptsEvents(t *testing.T) {
	for m, want := range map[Mode]bool{ModeCollecting: true, ModeDrainOnly: false, ModeBlocked: false, ModeFailed: false} {
		if m.AcceptsEvents() != want {
			t.Errorf("%s.AcceptsEvents() = %v", m, !want)
		}
	}
}

// Leaving blocked: Resume opens the store only once free space reaches the
// headroom, and keeps the lock it already holds.
func TestResumeFromBlocked(t *testing.T) {
	f := existing()
	f.reserves[ReserveRecovery] = false
	f.reserves[ReserveLastResort] = false
	f.free = 28672
	f.cursors["s"] = map[ConsumerID]Seq{"central": 200}
	p := policy()
	r := RunStartup(context.Background(), f, p)
	if r.Mode != ModeBlocked {
		t.Fatalf("mode %s", r.Mode)
	}
	again := Resume(context.Background(), f, p, r) // nothing freed yet
	if again.Mode != ModeBlocked || indexOf(f.calls, "Open") >= 0 {
		t.Fatalf("resumed without headroom: mode %s", again.Mode)
	}
	f.free = 1 << 20 // an operator freed space outside the store
	f.calls = nil
	next := Resume(context.Background(), f, p, again)
	if next.Mode != ModeCollecting || indexOf(f.calls, "Lock") >= 0 || next.Unlock == nil {
		t.Fatalf("mode %s calls %v", next.Mode, f.calls)
	}
	if c, ok := ModeChangeOf(again, next, f.now); !ok || c.From != ModeBlocked || c.To != ModeCollecting {
		t.Fatalf("mode change %+v %v", c, ok)
	}
}

// Leaving drain-only: once forwarding confirms events, Resume prunes them,
// re-creates the reserves and allows collection again.
func TestResumeFromDrainOnly(t *testing.T) {
	f := existing()
	f.reserves[ReserveRecovery] = false
	f.limit = 200 * f.eventSize
	p := policy()
	p.PruneTarget = 0.5                         // pruning to 100 events frees room for the reserve
	r := RunStartup(context.Background(), f, p) // nothing confirmed yet
	if r.Mode != ModeDrainOnly {
		t.Fatalf("mode %s", r.Mode)
	}
	if again := Resume(context.Background(), f, p, r); again.Mode != ModeDrainOnly {
		t.Fatalf("left drain-only with nothing confirmed: %s", again.Mode)
	}
	if err := r.Store.SaveCursor(context.Background(), Cursor{"central", "s", 180}); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	next := Resume(context.Background(), f, p, r)
	if next.Mode != ModeCollecting || !f.reserves[ReserveRecovery] || indexOf(f.calls, "Open") >= 0 {
		t.Fatalf("mode %s reserves %v calls %v", next.Mode, f.reserves, f.calls)
	}
	if got := f.retained("s"); got[0] <= 1 || got[0] > 181 {
		t.Fatalf("first retained %d", got[0])
	}
}

func TestResumeLeavesOtherModesAlone(t *testing.T) {
	for _, m := range []Mode{ModeCollecting, ModeFailed} {
		f := existing()
		if r := Resume(context.Background(), f, policy(), Report{Mode: m}); r.Mode != m || len(f.calls) != 0 {
			t.Errorf("%s: %s %v", m, r.Mode, f.calls)
		}
	}
}
