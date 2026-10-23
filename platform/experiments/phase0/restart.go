package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// restartCase checks recovery as a restarted process would do it, which
// A6's cross-review (R-A5-2) showed is needed: with the disk still full a
// reopened store can be read but cannot delete anything.
//
// Each round, a writer child process (bounded WAL, FULL) runs until it dies
// on SQLITE_FULL without closing the database. A fresh "startup" then:
// releases the reserve file, prunes the oldest half (standing in for events
// confirmed by every required consumer) in 50-event transactions,
// checkpoints, and re-creates the reserve. The next round exhausts the disk
// again from that state.
func restartCase(dir string, rounds int, autoVacuum bool) error {
	vacuum := "auto_vacuum=NONE (default)"
	if autoVacuum {
		vacuum = "auto_vacuum=INCREMENTAL"
	}
	fmt.Printf("\ncase 3: restart recovery in %s, %s, %d exhaustions, writer process dies at SQLITE_FULL each time\n", dir, vacuum, rounds)
	path := filepath.Join(dir, "restart.db")
	reserve := filepath.Join(dir, "reserve.bin")
	removeDB(path)
	os.Remove(reserve)
	defer removeDB(path)
	defer os.Remove(reserve)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.WriteFile(reserve, make([]byte, 512<<10), 0o600); err != nil {
		return err
	}
	// auto_vacuum=INCREMENTAL must be set before the first table exists. It
	// lets pruning hand freed pages back to the filesystem, where the WAL
	// needs them; without it, pages freed inside the database cannot hold
	// WAL frames.
	if autoVacuum {
		if err := createIncrementalVacuumDB(path); err != nil {
			return err
		}
	}

	fmt.Println("  round  events-written  writer-exit                         pruned  fs-free-after  reserve-recreated  integrity  contiguous  acked-present  capacity-regained")
	failures := 0
	var prevPruned int64
	for r := 1; r <= rounds; r++ {
		before := lastSeq(path)
		acked, exitMsg, err := writeUntilFull(self, path)
		if err != nil {
			return err
		}
		written := acked - before
		pruned, reserveErr, s, contiguous, present, err := startupRecovery(path, reserve, acked, autoVacuum)
		free := fsFree(dir)
		if err != nil {
			fmt.Printf("  %5d  %14d  %-34s  startup recovery FAILED: %v\n", r, written, exitMsg, err)
			failures++
			continue
		}
		// After a recovery the store must take back at least half of what was
		// pruned; otherwise it "recovered" without regaining capacity.
		regained := r == 1 || written*2 >= prevPruned
		ok := reserveErr == nil && s.integrity == "ok" && contiguous && present && regained
		if !ok {
			failures++
		}
		prevPruned = pruned
		fmt.Printf("  %5d  %14d  %-34s  %6d  %13d  %-17s  %-9s  %-10t  %-13t  %t\n",
			r, written, exitMsg, pruned, free, okOr(reserveErr), s.integrity, contiguous, present, regained)
	}
	if failures > 0 {
		fmt.Printf("  result: FAIL (%d of %d rounds; capacity-regained means the run after a recovery wrote at least half of what that recovery pruned)\n", failures, rounds)
		return nil
	}
	fmt.Println("  result: PASS (every exhaustion recovered at startup, reserve re-created, capacity regained each time)")
	return nil
}

// writeUntilFull runs a writer child until it exits and returns its last ack
// and how it exited.
func writeUntilFull(self, path string) (int64, string, error) {
	cmd := exec.Command(self, "writer", "-db", path, "-sync", "FULL", "-batch", "10", "-tuned")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, "", err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}
	var first, last int64 = -1, 0
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if v, err := strconv.ParseInt(sc.Text(), 10, 64); err == nil {
			if first < 0 {
				first = v - 9 // first ack covers a 10-event batch
			}
			last = v
		}
	}
	cmd.Wait()
	exitMsg := "exited"
	if strings.Contains(stderr.String(), "full") {
		exitMsg = "died on SQLITE_FULL"
	} else if stderr.Len() > 0 {
		exitMsg = strings.TrimSpace(stderr.String())
	}
	if first < 0 {
		return 0, exitMsg, nil
	}
	return last, exitMsg + fmt.Sprintf(" (seq %d-%d)", first, last), nil
}

// startupRecovery is what the node would run at start when the store is at
// its limit.
func startupRecovery(path, reserve string, lastAck int64, autoVacuum bool) (pruned int64, reserveErr error, s storeState, contiguous, present bool, err error) {
	os.Remove(reserve)
	db, err := openStore(path, "FULL")
	if err != nil {
		return 0, nil, s, false, false, err
	}
	defer db.Close()
	for _, p := range tunedPragmas {
		if _, err = db.Exec(p); err != nil {
			return 0, nil, s, false, false, err
		}
	}
	var count int64
	if err = db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		return
	}
	var minSeq int64
	if err = db.QueryRow("SELECT COALESCE(MIN(seq),0) FROM events").Scan(&minSeq); err != nil {
		return
	}
	if pruned, err = pruneIncrementally(db, minSeq+count/2-1, 50); err != nil {
		err = fmt.Errorf("prune after %d: %w", pruned, err)
		return
	}
	// Return freed pages to the filesystem a few at a time, checkpointing
	// between steps, for the same reason pruning is incremental. With
	// auto_vacuum=NONE incremental_vacuum is a no-op and freelist stays full.
	for autoVacuum {
		var free int64
		if err = db.QueryRow("PRAGMA freelist_count").Scan(&free); err != nil {
			return
		}
		if free == 0 {
			break
		}
		if _, err = db.Exec("PRAGMA incremental_vacuum(32)"); err != nil {
			err = fmt.Errorf("incremental_vacuum: %w", err)
			return
		}
		if _, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			err = fmt.Errorf("checkpoint during vacuum: %w", err)
			return
		}
	}
	if _, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		err = fmt.Errorf("checkpoint: %w", err)
		return
	}
	reserveErr = os.WriteFile(reserve, make([]byte, 512<<10), 0o600)
	if reserveErr != nil {
		os.Remove(reserve) // a partial reserve is worse than none: it hides the shortfall
	}
	if s, err = inspect(db); err != nil {
		return
	}
	contiguous = s.count == s.maxSeq-s.minSeq+1
	present = s.maxSeq >= lastAck
	return pruned, reserveErr, s, contiguous, present, nil
}

func createIncrementalVacuumDB(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
		return err
	}
	_, err = db.Exec(schema)
	return err
}

func lastSeq(path string) int64 {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return 0
	}
	defer db.Close()
	var n int64
	db.QueryRow("SELECT COALESCE(MAX(seq),0) FROM events").Scan(&n)
	return n
}
