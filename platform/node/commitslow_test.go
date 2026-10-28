package node

import (
	"testing"
	"time"
)

// A database's write-transaction times reach status at each Tick, and a
// transaction at or over SlowCommit raises store-commit-slow, once per
// CommitAlarmRepeat (B1's question on #294: does a node on a slow disk show
// held commits before datagrams drop?). Evidence class: simulated (the real
// store; the threshold lowered so an ordinary commit counts as slow).
func TestSlowCommitReachesStatusAndAlarms(t *testing.T) {
	slow, repeat := SlowCommit, CommitAlarmRepeat
	t.Cleanup(func() { SlowCommit, CommitAlarmRepeat = slow, repeat })
	// No real commit is slow in the first step: on a loaded hosted runner an
	// ordinary commit took 5.3 s (run 40727005166, Windows), over the default
	// threshold, so the test sets its own instead of assuming the disk's.
	SlowCommit = time.Hour
	c, dir := schedConfig(t, nil)
	r, st, _ := start(t, c, dir)
	defer r.Close()

	alarms := func() (n int) {
		for _, a := range st.Snapshot("n").Alarms {
			if a.Code == string(AlarmCommitSlow) && a.Database == AuditDB {
				n++
			}
		}
		return n
	}
	// Ordinary commits are not slow: the times are shown, no alarm.
	r.Tick(bg)
	if got := st.Snapshot("n").Commits[AuditDB]; got.Count < 1 || got.MaxMS < 0 || alarms() != 0 {
		t.Fatalf("commits %+v, alarms %d", got, alarms())
	}

	SlowCommit, CommitAlarmRepeat = time.Nanosecond, time.Hour
	r.audit(bg, "service.start", "info", "", "a commit to time")
	r.Tick(bg)
	if got := st.Snapshot("n").Commits[AuditDB]; got.RecentMS < 0 || alarms() != 1 {
		t.Fatalf("after a slow commit: %+v, alarms %d", got, alarms())
	}
	// Still slow, but inside the repeat period: not raised again.
	r.audit(bg, "service.start", "info", "", "another commit")
	r.Tick(bg)
	if alarms() != 1 {
		t.Fatalf("raised again inside the repeat period: %d", alarms())
	}
	CommitAlarmRepeat = 0
	r.audit(bg, "service.start", "info", "", "and another")
	r.Tick(bg)
	if alarms() != 2 {
		t.Fatalf("not raised again after the repeat period: %d", alarms())
	}
}
