package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// The events layout of C5 0.5 (D4-14). Evidence class: simulated, Linux.

// events is a rowid table with a unique (stream, seq) index: the first
// format's WITHOUT ROWID table spilled every event over about 1 KB to an
// overflow page of its own.
func TestEventsIsARowidTable(t *testing.T) {
	dir := storeDir(t)
	db := open1(t, dir, evidenceDB, nil)
	var table, index string
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
// names the way out and the settings alarm, and the node does not open,
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
	if r.Mode != c5.ModeFailed || len(r.Alarms) == 0 || r.Alarms[len(r.Alarms)-1].Code != c5.AlarmSettingsInvalid {
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
