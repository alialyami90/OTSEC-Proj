package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// runStorageLimit checks two ways the event store can run out of room:
//
//  1. An application quota (PRAGMA max_page_count) set below the disk size.
//  2. A real full filesystem (ENOSPC). Run with -enospc-dir pointing at a
//     small dedicated filesystem; run.sh mounts a 4 MiB tmpfs for this.
//
// For each it records the error the writer sees, whether the database stays
// intact and readable, whether acknowledged events survive, and whether
// writing resumes after space is reclaimed.
func runStorageLimit(args []string) error {
	fs := flag.NewFlagSet("storage-limit", flag.ExitOnError)
	dir := fs.String("dir", os.TempDir(), "scratch directory for the quota case")
	enospcDir := fs.String("enospc-dir", "", "directory on a small dedicated filesystem (skipped if empty)")
	fs.Parse(args)

	if err := quotaCase(*dir); err != nil {
		return err
	}
	if *enospcDir == "" {
		fmt.Println("\nENOSPC case: skipped (no -enospc-dir)")
		return nil
	}
	for _, c := range []struct{ tuned, incremental bool }{{false, false}, {true, false}, {true, true}} {
		if err := enospcCase(*enospcDir, c.tuned, c.incremental); err != nil {
			return err
		}
	}
	return nil
}

// tunedPragmas bound the WAL so committed data cannot sit in the WAL at a
// size that would need the same space again to checkpoint.
var tunedPragmas = []string{
	"PRAGMA wal_autocheckpoint=64",     // pages (256 KiB at 4 KiB pages)
	"PRAGMA journal_size_limit=262144", // truncate WAL back to 256 KiB after checkpoint
}

func quotaCase(dir string) error {
	fmt.Println("case 1: application quota via PRAGMA max_page_count=256 (1 MiB at 4 KiB pages)")
	path := filepath.Join(dir, "quota.db")
	removeDB(path)
	defer removeDB(path)
	db, err := openStore(path, "FULL")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA max_page_count=256"); err != nil {
		return err
	}
	acked, fillErr := fillUntilError(db)
	fmt.Printf("  writes stopped after %d acked events; error: %v\n", acked, fillErr)
	fmt.Printf("  WAL file size at stop: %d bytes (WAL is NOT bounded by max_page_count)\n", fileSize(path+"-wal"))
	if err := report(db, acked); err != nil {
		return err
	}

	// Retention: drop the oldest half, as a platform retention policy would
	// once those events are confirmed forwarded upstream.
	if _, err := db.Exec("DELETE FROM events WHERE seq <= ?", acked/2); err != nil {
		fmt.Printf("  prune oldest half: FAILED: %v\n", err)
		return nil
	}
	more, err := fillUntilError(db)
	fmt.Printf("  after pruning oldest half: %d more events accepted before quota again (%v)\n", more, err)
	return nil
}

func enospcCase(dir string, tuned, incremental bool) error {
	label := "default WAL settings (autocheckpoint 1000 pages)"
	if tuned {
		label = "bounded WAL (autocheckpoint 64 pages, journal_size_limit 256 KiB)"
	}
	if incremental {
		label += ", incremental pruning"
	}
	fmt.Printf("\ncase 2: real full filesystem in %s, %s\n", dir, label)
	path := filepath.Join(dir, "enospc.db")
	ballast := filepath.Join(dir, "reserve.bin")
	removeDB(path)
	os.Remove(ballast)
	defer removeDB(path)
	defer os.Remove(ballast)

	// Reserve 512 KiB the platform can release in an emergency.
	if err := os.WriteFile(ballast, make([]byte, 512<<10), 0o600); err != nil {
		return err
	}
	db, err := openStore(path, "FULL")
	if err != nil {
		return err
	}
	defer db.Close()
	if tuned {
		for _, p := range tunedPragmas {
			if _, err := db.Exec(p); err != nil {
				return err
			}
		}
	}
	acked, fillErr := fillUntilError(db)
	fmt.Printf("  writes stopped after %d acked events; error: %v\n", acked, fillErr)
	fmt.Printf("  at stop: main db %d bytes, WAL %d bytes\n", fileSize(path), fileSize(path+"-wal"))
	if err := report(db, acked); err != nil {
		return err
	}

	prune := func() (string, error) {
		if incremental {
			// Small transactions, checkpointing between them, so pruning never
			// needs more than a few pages of free space.
			n, err := pruneIncrementally(db, acked/2, 50)
			return fmt.Sprintf("50 events per transaction, %d pruned", n), err
		}
		_, err := db.Exec("DELETE FROM events WHERE seq <= ?", acked/2)
		return "one transaction", err
	}
	how, delErr := prune()
	fmt.Printf("  prune oldest half while disk is full (%s): %s\n", how, okOr(delErr))

	os.Remove(ballast)
	fmt.Println("  released 512 KiB reserve file")
	if delErr != nil {
		how, delErr = prune()
		fmt.Printf("  prune oldest half after release (%s): %s\n", how, okOr(delErr))
	}
	_, ckErr := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	fmt.Printf("  wal_checkpoint(TRUNCATE): %s\n", okOr(ckErr))
	more, err := fillUntilError(db)
	fmt.Printf("  after recovery: %d more events accepted before full again (%v)\n", more, err)

	// Reopen from scratch, as a restarted process would.
	db.Close()
	db2, err := openStore(path, "FULL")
	if err != nil {
		fmt.Printf("  reopen after full disk: FAILED: %v\n", err)
		return nil
	}
	defer db2.Close()
	s, err := inspect(db2)
	if err != nil {
		fmt.Printf("  inspect after reopen: FAILED: %v\n", err)
		return nil
	}
	fmt.Printf("  reopen: integrity=%s count=%d max_seq=%d\n", s.integrity, s.count, s.maxSeq)
	return nil
}

// fillUntilError commits 10-event batches until a commit fails and returns
// the number of events committed in this call.
func fillUntilError(db *sql.DB) (int64, error) {
	var n int64
	for {
		if _, err := insertBatch(db, 10, time.Now().UnixNano()); err != nil {
			return n, err
		}
		n += 10
	}
}

func report(db *sql.DB, ackedThisRun int64) error {
	s, err := inspect(db)
	if err != nil {
		fmt.Printf("  read back after failure: FAILED: %v\n", err)
		return nil
	}
	fmt.Printf("  read back: integrity=%s count=%d max_seq=%d (acked events lost: %d)\n",
		s.integrity, s.count, s.maxSeq, max64(0, ackedThisRun-s.count))
	return nil
}

func okOr(err error) string {
	if err != nil {
		return "FAILED: " + err.Error()
	}
	return "ok"
}

func removeDB(path string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(path + suffix)
	}
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// pruneIncrementally deletes events with seq <= upTo, step at a time,
// checkpointing after each step so the WAL never needs much free space.
func pruneIncrementally(db *sql.DB, upTo int64, step int64) (int64, error) {
	var pruned int64
	for {
		res, err := db.Exec(`DELETE FROM events WHERE seq IN
			(SELECT seq FROM events WHERE seq <= ? ORDER BY seq LIMIT ?)`, upTo, step)
		if err != nil {
			return pruned, err
		}
		n, _ := res.RowsAffected()
		pruned += n
		if n == 0 {
			return pruned, nil
		}
		if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return pruned, err
		}
	}
}
