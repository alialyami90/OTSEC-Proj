package store

import (
	"context"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// A write transaction held for a while (a slow WAL sync, B6 #294) shows in
// CommitStats while it runs and after, and TakeRecentCommit reads and resets
// the longest since the last look. Evidence class: simulated (real SQLite,
// the transaction held by a test hook).
func TestCommitStatsSeeASlowTransaction(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	l := testLog(t, db)
	if _, err := l.Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, 0)); err != nil {
		t.Fatal(err)
	}
	if st := db.CommitStats(); st.Count < 1 || st.Waiting != 0 || st.Max > 250*time.Millisecond {
		t.Fatalf("a fast commit: %+v", st)
	}
	db.TakeRecentCommit()

	const hold = 400 * time.Millisecond
	inTx := make(chan struct{})
	db.opt.hook = func(p string) {
		if strings.HasSuffix(p, ":commit") {
			close(inTx)
			time.Sleep(hold)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, 1))
		done <- err
	}()
	<-inTx
	time.Sleep(hold / 4)
	if w := db.CommitStats().Waiting; w < hold/8 {
		t.Errorf("a transaction in progress shows %v waiting", w)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	db.opt.hook = nil
	st := db.CommitStats()
	if st.Waiting != 0 || st.Max < hold || st.Recent < hold {
		t.Errorf("after the slow commit: %+v, want max and recent of at least %v and nothing waiting", st, hold)
	}
	if got := db.TakeRecentCommit(); got < hold {
		t.Errorf("TakeRecentCommit %v, want at least %v", got, hold)
	}
	if got := db.TakeRecentCommit(); got != 0 {
		t.Errorf("a second TakeRecentCommit %v, want 0", got)
	}
}
