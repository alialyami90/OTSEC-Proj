package store

import (
	"context"
	c5 "otsec.local/otsec/contracts/store"
	"testing"
	"time"
)

// Options.BusyTimeout is SQLite's busy_timeout on the open connection, and
// zero means the production 5 s.
func TestBusyTimeoutOption(t *testing.T) {
	for name, tc := range map[string]struct {
		set  time.Duration
		want int64
	}{
		"default":   {0, 5000},
		"shortened": {400 * time.Millisecond, 400},
	} {
		t.Run(name, func(t *testing.T) {
			dir := storeDir(t)
			db, _ := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB, BusyTimeout: tc.set}, policy(evidenceDB), c5.ModeCollecting)
			defer db.Close()
			var got int64
			if err := db.conn.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("busy_timeout = %d ms, want %d", got, tc.want)
			}
		})
	}
}
