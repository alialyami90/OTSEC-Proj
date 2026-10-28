package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// The syslog restart test (tests/integration/syslogreceive) stalled on a
// Windows runner with the store's commit waiting in BEGIN IMMEDIATE while
// the rig read the database from other connections (job 122616521941). These
// tests ask whether other connections to the file can hold the store's
// writer back. Evidence class: simulated (real SQLite files, this OS).

// readerChurn opens, queries and closes a query_only connection to the
// database in a loop, as the rig's polling does, until stop is closed.
func readerChurn(t *testing.T, path string, stop <-chan struct{}, wg *sync.WaitGroup, reads *atomic.Int64) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		db, err := sql.Open("sqlite", fileURI(path, "_pragma=query_only(1)&_pragma=busy_timeout(5000)"))
		if err != nil {
			t.Error(err)
			return
		}
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n); err != nil {
			t.Error(err)
		}
		db.Close()
		reads.Add(1)
	}
}

// Readers that open and close connections all the time do not hold a commit
// back for long, and no commit fails.
func TestCommitsAreNotHeldBackByReaderChurn(t *testing.T) {
	dir := storeDir(t)
	db := open1(t, dir, evidenceDB, nil)
	l := testLog(t, db)
	path := filepath.Join(dir, "evidence.db")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var reads atomic.Int64
	for range 4 {
		wg.Add(1)
		go readerChurn(t, path, stop, &wg, &reads)
	}
	start := time.Now()
	for i := range 300 {
		if _, err := l.Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, i)); err != nil {
			t.Fatalf("append %d after %v: %v (begin %+v, %d reads)", i, time.Since(start), err, db.BeginStats(), reads.Load())
		}
	}
	elapsed := time.Since(start)
	close(stop)
	wg.Wait()
	st := db.BeginStats()
	t.Logf("300 commits in %v with %d reader connections opened and closed; BEGIN waits: %+v", elapsed, reads.Load(), st)
	if l.Stopped() != nil {
		t.Fatalf("log stopped: %v", l.Stopped())
	}
	if st.Max > 2*time.Second {
		t.Fatalf("a BEGIN IMMEDIATE waited %v for the write lock while only readers were open: %+v", st.Max, st)
	}
}

// A store closed and opened again while another connection to its file is
// still open, one idle and one in the middle of a read, starts and commits.
func TestReopenWithAnotherConnectionStillOpen(t *testing.T) {
	dir := storeDir(t)
	db1, unlock1 := openUnlockable(t, dir)
	if _, err := testLog(t, db1).Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, 0)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence.db")
	other, err := sql.Open("sqlite", fileURI(path, "_pragma=query_only(1)&_pragma=busy_timeout(5000)"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	idle, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	var n int
	if err := idle.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("idle connection read %d events: %v", n, err)
	}
	reading, err := other.QueryContext(context.Background(), "SELECT id FROM events")
	if err != nil {
		t.Fatal(err)
	}
	defer reading.Close()
	if !reading.Next() {
		t.Fatalf("no row to hold a read open: %v", reading.Err())
	}
	// Close checkpoints with TRUNCATE, which waits for a reader that still
	// holds the old snapshot, up to busy_timeout (5 s); it returns then.
	t0 := time.Now()
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}
	closed := time.Since(t0)
	unlock1()
	t0 = time.Now()
	db2 := open1(t, dir, evidenceDB, nil)
	t.Logf("Close took %v with a reader mid-read; the reopen took %v", closed, time.Since(t0))
	if closed > 10*time.Second {
		t.Fatalf("Close took %v with another connection mid-read", closed)
	}
	l := testLog(t, db2)
	for i := 1; i <= 5; i++ {
		if _, err := l.Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, i)); err != nil {
			t.Fatalf("append %d after the reopen: %v (begin %+v)", i, err, db2.BeginStats())
		}
	}
	if st := db2.BeginStats(); st.Max > 2*time.Second {
		t.Fatalf("a BEGIN IMMEDIATE waited %v with another connection open: %+v", st.Max, st)
	}
}

// openUnlockable is open1 for a test that closes the store and opens it
// again: it returns the release of the directory's OS lock.
func openUnlockable(t *testing.T, dir string) (*DB, func()) {
	t.Helper()
	env, err := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(context.Background(), env, policy(evidenceDB))
	if r.Mode != c5.ModeCollecting || r.Store == nil {
		t.Fatalf("startup mode %s: %v %v", r.Mode, r.Err, r.Steps)
	}
	db, ok := AsDB(r.Store)
	if !ok {
		t.Fatalf("store is %T", r.Store)
	}
	return db, r.Unlock
}

// BeginStats sees a wait: another connection holds BEGIN IMMEDIATE while a
// commit waits on it. Waiting is seen during the wait, Count rises by one,
// Max and Total reach at least half the hold, and Waiting is zero after
// (B6 on #295).
func TestBeginStatsSeesAWait(t *testing.T) {
	const hold = 600 * time.Millisecond
	dir := storeDir(t)
	db := open1(t, dir, evidenceDB, nil)
	l := testLog(t, db)
	if _, err := l.Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, 0)); err != nil {
		t.Fatal(err)
	}
	before := db.BeginStats()
	other, err := sql.Open("sqlite", fileURI(filepath.Join(dir, "evidence.db"), "_pragma=busy_timeout(5000)"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	c, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.Append(context.Background(), rec("syslog/relay1", c5.ClassSyslogStream, 1))
		done <- err
	}()
	var waiting time.Duration
	for end := time.Now().Add(hold); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		waiting = max(waiting, db.BeginStats().Waiting)
	}
	c.ExecContext(context.Background(), "ROLLBACK")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	after := db.BeginStats()
	if after.Count != before.Count+1 || after.Max < hold/2 || after.Total-before.Total < hold/2 || waiting < hold/2 || after.Waiting != 0 {
		t.Errorf("BeginStats missed a wait of %v: before %+v, after %+v, Waiting seen %v", hold, before, after, waiting)
	}
}
