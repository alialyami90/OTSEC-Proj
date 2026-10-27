package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// The events layout of C5 0.5 (D4-14). Evidence class: simulated, Linux.

// events and captures are rowid tables with unique indexes on their keys:
// the first format's WITHOUT ROWID tables spilled every row over about 1 KB
// to an overflow page of its own (B1's ruling on #282 for captures).
func TestEventsIsARowidTable(t *testing.T) {
	dir := storeDir(t)
	db := open1(t, dir, evidenceDB, nil)
	var table, index string
	for _, name := range []string{"captures", "captures_key"} {
		var sqlText string
		if err := db.conn.QueryRowContext(context.Background(), `SELECT sql FROM sqlite_master WHERE name = ?`, name).Scan(&sqlText); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToUpper(sqlText), "WITHOUT ROWID") {
			t.Fatalf("%s is WITHOUT ROWID: %s", name, sqlText)
		}
		if name == "captures_key" && (!strings.Contains(sqlText, "UNIQUE") || !strings.Contains(sqlText, "(sha256)")) {
			t.Fatalf("captures_key: %s", sqlText)
		}
	}
	if err := db.conn.QueryRowContext(context.Background(), `SELECT sql FROM sqlite_master WHERE name = 'events'`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(table), "WITHOUT ROWID") {
		t.Fatalf("events is WITHOUT ROWID: %s", table)
	}
	if err := db.conn.QueryRowContext(context.Background(), `SELECT sql FROM sqlite_master WHERE name = 'events_key'`).Scan(&index); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(index, "UNIQUE") || !strings.Contains(index, "(stream, seq)") {
		t.Fatalf("events_key: %s", index)
	}
	l := testLog(t, db)
	if _, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 1)); err != nil {
		t.Fatal(err)
	}
	// A second event with the same (stream, seq) is refused by the index.
	_, err := db.conn.ExecContext(context.Background(), `INSERT INTO events (stream, seq, event, committed_at) VALUES ('relay1/ser', 1, x'00', 0)`)
	if err == nil {
		t.Fatal("a duplicate (stream, seq) was accepted")
	}
}

func legacyStore(t *testing.T) (dir, file string) {
	t.Helper()
	dir = storeDir(t)
	db, first := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB}, policy(evidenceDB), c5.ModeCollecting)
	l := testLog(t, db)
	if _, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 1)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	first.Unlock()
	m, _ := filepath.Glob(filepath.Join(dir, "*.db"))
	if len(m) != 1 {
		t.Fatalf("database files %v", m)
	}
	raw, err := sql.Open("sqlite", m[0])
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE meta SET value = ? WHERE key = 'format'`, legacyFormat); err != nil {
		t.Fatal(err)
	}
	return dir, m[0]
}

// A database of the first format is refused at start with an error that
// names the way out and the open-failed alarm, and the node does not open,
// change or delete it (D4-14): the node comes up failed, not collecting.
func TestLegacyLayoutIsRefusedAtStart(t *testing.T) {
	dir, file := legacyStore(t)
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(bg, env, policy(evidenceDB))
	defer unlock(r)
	if r.Mode != c5.ModeFailed || len(r.Alarms) == 0 || r.Alarms[len(r.Alarms)-1].Code != c5.AlarmOpenFailed {
		t.Fatalf("mode %s, alarms %v, err %v", r.Mode, r.Alarms, r.Err)
	}
	msg := fmt.Sprint(r.Err, " ", r.Alarms[len(r.Alarms)-1].Detail)
	for _, want := range []string{"earlier layout", legacyFormat, "not opened, changed or deleted", "remove the database files"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the refused database file was changed")
	}
	// The offline reader refuses it the same way.
	if _, err := OpenReadOnly(bg, dir, testNode, evidenceDB.ID); err == nil || !strings.Contains(err.Error(), "earlier layout") {
		t.Fatalf("OpenReadOnly on the old layout: %v", err)
	}
}

// hashes returns the SHA-256 of the database file and its -wal and -shm, or
// "absent" for a file that is not there, so a refusal that creates, changes
// or deletes any of the three shows.
func hashes(t *testing.T, file string) [3]string {
	t.Helper()
	var out [3]string
	for i, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(file + suffix)
		switch {
		case os.IsNotExist(err):
			out[i] = "absent"
		case err != nil:
			t.Fatal(err)
		default:
			sum := sha256.Sum256(b)
			out[i] = hex.EncodeToString(sum[:]) + fmt.Sprintf(" (%d bytes)", len(b))
		}
	}
	return out
}

// A refusal writes nothing, even when the old database was left with a hot
// -wal by a crash: an ordinary open folds the -wal into the file and deletes
// it. The database file and its -wal and -shm are the same bytes after the
// node's start and after the offline reader's, and none is created (B1's
// ruling on #282).
func TestLegacyRefusalWritesNothingWithAHotWAL(t *testing.T) {
	src, srcFile := legacyStore(t)
	_ = src
	// A connection that never checkpoints leaves committed pages in the -wal.
	live, err := sql.Open("sqlite", srcFile)
	if err != nil {
		t.Fatal(err)
	}
	live.SetMaxOpenConns(1)
	defer live.Close()
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0"} {
		if _, err := live.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := live.Exec(`INSERT INTO cursors (consumer, stream, through) VALUES ('hot', 'relay1/ser', 1)`); err != nil {
		t.Fatal(err)
	}
	// The crashed node's files, copied while its connection is still open.
	dir := storeDir(t)
	file := filepath.Join(dir, filepath.Base(srcFile))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(srcFile + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file+suffix, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(file + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("the copy has no hot -wal: %v", err)
	}
	before := hashes(t, file)
	env, err := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(bg, env, policy(evidenceDB))
	unlock(r)
	if r.Mode != c5.ModeFailed || !strings.Contains(fmt.Sprint(r.Err, r.Alarms), "earlier layout") {
		t.Fatalf("mode %s, err %v, alarms %v", r.Mode, r.Err, r.Alarms)
	}
	if got := hashes(t, file); got != before {
		t.Fatalf("the refusal changed the files:\nbefore %v\nafter  %v", before, got)
	}
	if _, err := OpenReadOnly(bg, dir, testNode, evidenceDB.ID); err == nil || !strings.Contains(err.Error(), "earlier layout") {
		t.Fatalf("OpenReadOnly on the old layout: %v", err)
	}
	if got := hashes(t, file); got != before {
		t.Fatalf("the offline reader changed the files:\nbefore %v\nafter  %v", before, got)
	}
}

// Once checkpointed, the file grows by no more than DiskBytesPerQuotaByte
// for each byte the class quota counts, across event sizes from a few
// hundred bytes to past a page (B6's sweep in tests/integration/storeholds
// covers 100 B to 64 KiB; this keeps the pin in the store's own tests).
func TestFileGrowthStaysUnderTheDiskFactor(t *testing.T) {
	db := open1(t, storeDir(t), withQuota(evidenceDB, c5.ClassAdapterEvidence, 1<<30), nil)
	l := testLog(t, db)
	ctx := context.Background()
	size := func() int64 {
		used, _, err := db.Usage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return used
	}
	n := 0
	for _, eventBytes := range []int{300, 1100, 1900, 2048, 2400, 3000, 5300, 64 << 10} {
		t.Run(fmt.Sprint(eventBytes), func(t *testing.T) {
			rows := min(128, (900<<10)/eventBytes)
			before, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
			if err != nil {
				t.Fatal(err)
			}
			pagesBefore := size()
			recs := make([]c5.Record, rows)
			for i := range recs {
				n++
				recs[i] = c5.Record{Stream: "relay1/ser", Class: c5.ClassAdapterEvidence, Event: padded(pending("relay1/ser", n), eventBytes)}
			}
			if _, err := l.AppendBatch(ctx, recs); err != nil {
				t.Fatal(err)
			}
			for more := true; more; {
				if more, err = db.CompactStep(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			after, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
			if err != nil {
				t.Fatal(err)
			}
			grew, counted := size()-pagesBefore, after-before
			t.Logf("%d events of %d bytes: pages grew %d for %d quota bytes (%.2f ×), simulated", rows, eventBytes, grew, counted, float64(grew)/float64(counted))
			if float64(grew) > c5.DiskBytesPerQuotaByte*float64(counted) {
				t.Fatalf("the file grew %d bytes for %d quota bytes, over %v ×", grew, counted, c5.DiskBytesPerQuotaByte)
			}
		})
	}
}

// A commit in which every record has a capture of its own, of 1 to 1.5 KB
// (C5 allows it though no producer does), meets the same bound on the file:
// the captures table is a rowid table as events is (B6 on #282, where the
// WITHOUT ROWID table wrote 3.9 KB of WAL a record and grew the file 3.48 ×).
func TestFileGrowthWithACaptureEachStaysUnderTheDiskFactor(t *testing.T) {
	db := open1(t, storeDir(t), withQuota(evidenceDB, c5.ClassAdapterEvidence, 1<<30), nil)
	l := testLog(t, db)
	ctx := context.Background()
	n := 0
	for _, capBytes := range []int{1000, 1200, 1500, 2000, 3000} {
		t.Run(fmt.Sprint(capBytes), func(t *testing.T) {
			before, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
			if err != nil {
				t.Fatal(err)
			}
			used, _, err := db.Usage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			recs := make([]c5.Record, 128)
			for i := range recs {
				n++
				cp := capture(fmt.Sprintf("%d %s", n, strings.Repeat("x", capBytes)))
				recs[i] = c5.Record{Stream: "relay1/ser", Class: c5.ClassAdapterEvidence, Event: pending("relay1/ser", n), Capture: &cp}
			}
			if _, err := l.AppendBatch(ctx, recs); err != nil {
				t.Fatal(err)
			}
			for more := true; more; {
				if more, err = db.CompactStep(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			after, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
			if err != nil {
				t.Fatal(err)
			}
			now, _, err := db.Usage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			grew, counted := now-used, after-before
			t.Logf("128 records with a capture of %d bytes each: pages grew %d for %d quota bytes (%.2f ×), simulated", capBytes, grew, counted, float64(grew)/float64(counted))
			if float64(grew) > c5.DiskBytesPerQuotaByte*float64(counted) {
				t.Fatalf("the file grew %d bytes for %d quota bytes, over %v ×", grew, counted, c5.DiskBytesPerQuotaByte)
			}
		})
	}
}

// padded is ev with its health detail padded so the event is size bytes.
func padded(ev []byte, size int) []byte {
	s := string(ev)
	i := strings.LastIndex(s, `"}}}`)
	if i < 0 {
		i = len(s) - 3
	}
	if pad := size - len(s); pad > 0 {
		s = s[:i] + strings.Repeat("0", pad) + s[i:]
	}
	return []byte(s)
}
