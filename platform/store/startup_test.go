package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

func steps(r c5.Report) []c5.Step {
	var out []c5.Step
	for _, s := range r.Steps {
		out = append(out, s.Step)
	}
	return out
}

func codes(r c5.Report) []c5.AlarmCode {
	var out []c5.AlarmCode
	for _, a := range r.Alarms {
		out = append(out, a.Code)
	}
	return out
}

func reserveSize(t *testing.T, env *Env, r c5.Reserve) int64 {
	t.Helper()
	st, err := os.Stat(env.reservePath(r))
	if err != nil {
		t.Fatalf("%s reserve: %v", r, err)
	}
	return st.Size()
}

// Case 1 of P2-A5: the reserve is present. A new store creates both
// reserves at their full size; the next startup releases the recovery
// reserve before the open and re-creates it.
func TestStartupWithReserve(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	p := policy(evidenceDB)
	db, r := testStore(t, opt, p, c5.ModeCollecting)
	env, _ := NewEnv(opt)
	if reserveSize(t, env, c5.ReserveRecovery) != p.RecoveryReserveBytes || reserveSize(t, env, c5.ReserveLastResort) != p.LastResortReserveBytes {
		t.Fatal("reserve sizes")
	}
	db.Close()
	r.Unlock()

	db, r = testStore(t, opt, p, c5.ModeCollecting)
	want := []c5.Step{c5.StepLock, c5.StepInspect, c5.StepReleaseReserve, c5.StepHeadroom, c5.StepOpen, c5.StepSettings,
		c5.StepIntegrity, c5.StepPrune, c5.StepCompact, c5.StepRecreateReserves}
	if !slices.Equal(steps(r), want) || len(r.Alarms) != 0 {
		t.Fatalf("steps %v alarms %v", steps(r), codes(r))
	}
	if reserveSize(t, env, c5.ReserveRecovery) != p.RecoveryReserveBytes {
		t.Fatal("recovery reserve not re-created")
	}
}

// Case 2: no reserve on an existing store (F-013's condition). The
// last-resort reserve is released instead, then both come back; with
// neither present the store still opens above the headroom.
func TestStartupWithoutReserve(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	p := policy(evidenceDB)
	db, r := testStore(t, opt, p, c5.ModeCollecting)
	db.Close()
	r.Unlock()
	env, _ := NewEnv(opt)

	os.Remove(env.reservePath(c5.ReserveRecovery))
	db, r = testStore(t, opt, p, c5.ModeCollecting)
	if !slices.Contains(steps(r), c5.StepReleaseLastResort) || !slices.Equal(codes(r), []c5.AlarmCode{c5.AlarmReserveMissing}) {
		t.Fatalf("steps %v alarms %v", steps(r), codes(r))
	}
	if reserveSize(t, env, c5.ReserveRecovery) != p.RecoveryReserveBytes || reserveSize(t, env, c5.ReserveLastResort) != p.LastResortReserveBytes {
		t.Fatal("reserves not re-created")
	}
	db.Close()
	r.Unlock()

	os.Remove(env.reservePath(c5.ReserveRecovery))
	os.Remove(env.reservePath(c5.ReserveLastResort))
	_, r = testStore(t, opt, p, c5.ModeCollecting)
	if !slices.Equal(codes(r), []c5.AlarmCode{c5.AlarmReserveMissing, c5.AlarmReserveMissing}) {
		t.Fatalf("alarms %v", codes(r))
	}
}

// Case 3: the release fails. Startup stops before the open, and the
// database files are not touched.
func TestStartupReleaseFails(t *testing.T) {
	for _, which := range []c5.Reserve{c5.ReserveRecovery, c5.ReserveLastResort} {
		t.Run(string(which), func(t *testing.T) {
			dir := storeDir(t)
			opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
			p := policy(evidenceDB)
			db, r := testStore(t, opt, p, c5.ModeCollecting)
			db.Close()
			r.Unlock()
			env, _ := NewEnv(opt)
			if which == c5.ReserveLastResort {
				os.Remove(env.reservePath(c5.ReserveRecovery))
			}
			// A non-empty directory at the reserve's path cannot be
			// removed, on Windows and Linux alike.
			path := env.reservePath(which)
			os.Remove(path)
			if err := os.MkdirAll(filepath.Join(path, "held"), 0o700); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, dir)
			r = c5.RunStartup(bg, env, p)
			defer unlock(r)
			if r.Mode != c5.ModeFailed || slices.Contains(steps(r), c5.StepOpen) || !slices.Contains(codes(r), c5.AlarmReserveReleaseFailed) {
				t.Fatalf("mode %s steps %v alarms %v", r.Mode, steps(r), codes(r))
			}
			if after := snapshot(t, dir); !maps(before, after) {
				t.Fatalf("store files changed without an open:\n%v\n%v", before, after)
			}
		})
	}
}

// snapshot is the name, size and modification time of every file of the
// database (not the reserves or the lock).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, suffix := range []string{".db", ".db-wal", ".db-shm", ".db-journal"} {
		st, err := os.Stat(filepath.Join(dir, "evidence"+suffix))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out[suffix] = fmt.Sprintf("%v %d", st.ModTime(), st.Size())
	}
	return out
}

func maps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Below the open headroom the store is not opened (blocked), and Resume
// opens it once space is back.
func TestStartupBlockedThenResumed(t *testing.T) {
	dir := storeDir(t)
	free := int64(1 << 10)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB, freeBytes: func() (int64, error) { return free, nil }}
	p := policy(evidenceDB)
	env, _ := NewEnv(opt)
	r := c5.RunStartup(bg, env, p)
	defer unlock(r)
	if r.Mode != c5.ModeBlocked || r.Store != nil {
		t.Fatalf("mode %s", r.Mode)
	}
	if ok, _ := env.StoreExists(bg); ok {
		t.Fatal("store created while blocked")
	}
	free = 1 << 30
	next := c5.Resume(bg, env, p, r)
	if next.Mode != c5.ModeCollecting || next.Store == nil {
		t.Fatalf("resume: %s %v", next.Mode, next.Err)
	}
	next.Store.Close()
	if _, ok := c5.ModeChangeOf(r, next, time.Now()); !ok {
		t.Fatal("no mode change")
	}
}

// A second process, or a second Env in this one, cannot take the lock.
func TestLockIsExclusive(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	_, _ = testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	env, _ := NewEnv(opt)
	r := c5.RunStartup(bg, env, policy(evidenceDB))
	if r.Mode != c5.ModeFailed || r.Steps[0].Step != c5.StepLock || r.Unlock != nil {
		t.Fatalf("second lock: %s %v", r.Mode, r.Steps)
	}
}

// D1-11 against the real store: with the audit database at quota, the act
// (ACC) never runs, and received Syslog still commits.
func TestAuditBeforeActWithAuditFull(t *testing.T) {
	var a alarms
	audDB := withQuota(auditDB, c5.ClassAudit, 3000)
	aud := open1(t, storeDir(t), audDB, &a)
	ev := open1(t, storeDir(t), evidenceDB, nil)
	al := testLog(t, aud)
	el := testLog(t, ev)
	if _, err := al.Append(bg, auditRec("audit.chain.start", "")); err != nil {
		t.Fatal(err)
	}
	ran := 0
	act := func(c5.Receipt) error { ran++; return nil }
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		err = c5.AuditBeforeAct(bg, al, modeChange(i), act)
	}
	if !isCode(err, c5.CodeAuditUnavailable) || !a.has(c5.AlarmAuditFull) {
		t.Fatalf("audit full: %v %v", err, a.got)
	}
	before := ran
	if err := c5.AuditBeforeAct(bg, al, modeChange(100), act); !isCode(err, c5.CodeAuditUnavailable) || ran != before {
		t.Fatalf("act ran without a receipt: %v", err)
	}
	if _, err := el.Append(bg, rec("syslog/relay1", c5.ClassSyslogStream, 0)); err != nil {
		t.Fatalf("syslog with audit full: %v", err)
	}
	if al.Stopped() != nil {
		t.Fatalf("a quota refusal stopped the audit log: %v", al.Stopped())
	}
}

// A commit failure of unknown durability stops the Log, and AuditBeforeAct
// then refuses too (D1-11, second case).
func TestAuditBeforeActAfterCommitFailure(t *testing.T) {
	aud := open1(t, storeDir(t), auditDB, nil)
	al := testLog(t, aud)
	if _, err := al.Append(bg, auditRec("audit.chain.start", "")); err != nil {
		t.Fatal(err)
	}
	aud.opt.hook = func(p string) {
		if p == "commit:commit" {
			aud.conn.ExecContext(context.Background(), "ROLLBACK") // the COMMIT that follows fails
		}
	}
	ran := false
	err := c5.AuditBeforeAct(bg, al, modeChange(1), func(c5.Receipt) error { ran = true; return nil })
	if ran || !isCode(err, c5.CodeAuditUnavailable) || !isCode(al.Stopped(), c5.CodeCommitFailed) {
		t.Fatalf("ran %v err %v stopped %v", ran, err, al.Stopped())
	}
	aud.opt.hook = nil
	if err := c5.AuditBeforeAct(bg, al, modeChange(2), func(c5.Receipt) error { ran = true; return nil }); ran || !isCode(err, c5.CodeAuditUnavailable) {
		t.Fatalf("after stop: ran %v err %v", ran, err)
	}
}

// B6's finding on #299: startup measured a class quota against the live
// pages, which run well over the payload the quota counts. A class holding
// 75% of its quota in payload therefore raised "store-quota-reached" at every
// start although the next append succeeded. Startup now measures class bytes,
// the same count the runtime refusal uses (D4-14).
func TestStartupMeasuresQuotaInClassBytes(t *testing.T) {
	d := evidenceDB
	d.Classes = []c5.StreamClass{c5.ClassAdapterEvidence}
	d.Streams = []c5.StreamSpec{{ID: "relay1/ser", Class: c5.ClassAdapterEvidence}}
	d.Quotas = []c5.Quota{{Class: c5.ClassAdapterEvidence, Bytes: 1 << 20, WarnFraction: 0.8}}
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: d}
	p := policy(d)
	db, r := testStore(t, opt, p, c5.ModeCollecting)
	l := testLog(t, db)
	ctx := context.Background()
	for n := 0; ; n++ {
		held, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
		if err != nil {
			t.Fatal(err)
		}
		if held >= 3<<18 {
			break
		}
		cp := capture(fmt.Sprintf("%d %s", n, string(make([]byte, 2000))))
		rc := rec("relay1/ser", c5.ClassAdapterEvidence, n)
		rc.Capture = &cp
		if _, err := l.Append(ctx, rc); err != nil {
			t.Fatal(err)
		}
	}
	held, _ := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	pages, free, size, err := db.pages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if (pages-free)*size < 1<<20 {
		t.Fatalf("setup: pages %d bytes against a quota of %d, class bytes %d: the pages should run over the quota", (pages-free)*size, 1<<20, held)
	}
	if uses, err := db.ClassUsage(ctx); err != nil || len(uses) != 1 || uses[0].Used != held || uses[0].Limit != 1<<20 {
		t.Fatalf("ClassUsage %+v, %v; class bytes %d", uses, err, held)
	}
	db.Close()
	r.Unlock()

	_, r = testStore(t, opt, p, c5.ModeCollecting)
	if slices.Contains(codes(r), c5.AlarmQuotaReached) {
		t.Fatalf("class at %d of %d bytes raised %v", held, 1<<20, r.Alarms)
	}
}

// B6 on #320: startup measured the database's summed class bytes against its
// summed quotas, so a class with no room left beside a light class raised
// nothing, and a full class restarted silently until its next refused write
// (P5: telemetry failures stay observable). Each class is measured against
// its own quota and the alarm names the class.
func TestStartupAlarmsForAFullClassBesideALightOne(t *testing.T) {
	d := c5.Database{
		ID:      "evidence",
		Writer:  "node",
		Streams: []c5.StreamSpec{{ID: "relay1/ser", Class: c5.ClassAdapterEvidence}, {ID: "platform/health", Class: c5.ClassPlatform}},
		Classes: []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform},
		Quotas: []c5.Quota{
			{Class: c5.ClassAdapterEvidence, Bytes: 256 << 10, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes},
			{Class: c5.ClassPlatform, Bytes: 8 << 20, WarnFraction: 0.8},
		},
	}
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: d}
	p := policy(d)
	db, r := testStore(t, opt, p, c5.ModeCollecting)
	l := testLog(t, db)
	ctx := context.Background()
	for n := 0; ; n++ {
		cp := capture(fmt.Sprintf("%d %s", n, strings.Repeat("x", 40<<10)))
		rc := rec("relay1/ser", c5.ClassAdapterEvidence, n)
		rc.Capture = &cp
		if _, err := l.Append(ctx, rc); err != nil {
			if !isCode(err, c5.CodeQuotaReached) {
				t.Fatal(err)
			}
			break
		}
	}
	held, _ := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	if held+c5.MinRecordBytes <= 256<<10 {
		t.Fatalf("setup: %d of %d bytes held leaves room for a record", held, 256<<10)
	}
	db.Close()
	r.Unlock()

	_, r = testStore(t, opt, p, c5.ModeCollecting)
	var reached []c5.StreamClass
	for _, a := range r.Alarms {
		if a.Code == c5.AlarmQuotaReached {
			reached = append(reached, a.Class)
		}
	}
	if !slices.Equal(reached, []c5.StreamClass{c5.ClassAdapterEvidence}) {
		t.Fatalf("%d of %d bytes held: store-quota-reached for %v, alarms %v", held, 256<<10, reached, r.Alarms)
	}
}

// Pruning looks at each class on its own: a class above the target is
// pruned, a confirmed stream of a class below it is left alone.
func TestStartupPrunesOnlyTheClassAboveTheTarget(t *testing.T) {
	d := c5.Database{
		ID:      "evidence",
		Writer:  "node",
		Streams: []c5.StreamSpec{{ID: "relay1/ser", Class: c5.ClassAdapterEvidence}, {ID: "platform/health", Class: c5.ClassPlatform}},
		Classes: []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform},
		Quotas: []c5.Quota{
			{Class: c5.ClassAdapterEvidence, Bytes: 256 << 10, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes},
			{Class: c5.ClassPlatform, Bytes: 8 << 20, WarnFraction: 0.8},
		},
	}
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: d}
	p := policy(d,
		c5.Consumer{ID: "central-ser", Stream: "relay1/ser", Delivery: c5.Required},
		c5.Consumer{ID: "central-health", Stream: "platform/health", Delivery: c5.Required})
	db, r := testStore(t, opt, p, c5.ModeCollecting)
	l := testLog(t, db)
	ctx := context.Background()
	for n := 0; ; n++ {
		cp := capture(fmt.Sprintf("%d %s", n, strings.Repeat("x", 40<<10)))
		rc := rec("relay1/ser", c5.ClassAdapterEvidence, n)
		rc.Capture = &cp
		if _, err := l.Append(ctx, rc); err != nil {
			break
		}
	}
	for n := 0; n < 20; n++ {
		if _, err := l.Append(ctx, rec("platform/health", c5.ClassPlatform, n)); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []c5.StreamID{"relay1/ser", "platform/health"} {
		last, _ := db.LastCommitted(ctx, s)
		if err := db.SaveCursor(ctx, c5.Cursor{Consumer: map[c5.StreamID]c5.ConsumerID{"relay1/ser": "central-ser", "platform/health": "central-health"}[s], Stream: s, Through: last}); err != nil {
			t.Fatal(err)
		}
	}
	serBefore, _ := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	healthBefore, _ := db.ClassBytes(ctx, c5.ClassPlatform)
	db.Close()
	r.Unlock()

	db, _ = testStore(t, opt, p, c5.ModeCollecting)
	serAfter, _ := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	healthAfter, _ := db.ClassBytes(ctx, c5.ClassPlatform)
	if serAfter >= serBefore || float64(serAfter) > 0.8*(256<<10) {
		t.Errorf("evidence class %d bytes before startup, %d after: not pruned to the target", serBefore, serAfter)
	}
	if healthAfter != healthBefore {
		t.Errorf("platform class %d bytes before startup, %d after: pruned though far below its target", healthBefore, healthAfter)
	}
}
