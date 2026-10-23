package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// runWriter is the child process for crash-durability. It commits batches
// forever and prints the highest committed sequence after each commit. A
// printed sequence is the "acknowledgement": the platform would only tell an
// upstream (or advance a device-side cursor) after this point.
func runWriter(args []string) error {
	fs := flag.NewFlagSet("writer", flag.ExitOnError)
	path := fs.String("db", "", "database path")
	syncMode := fs.String("sync", "FULL", "PRAGMA synchronous value")
	batch := fs.Int("batch", 1, "events per transaction")
	fs.Parse(args)

	db, err := openStore(*path, *syncMode)
	if err != nil {
		return err
	}
	for {
		last, err := insertBatch(db, *batch, time.Now().UnixNano())
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, last) // os.Stdout is unbuffered
	}
}

// runCrashDurability repeatedly SIGKILLs a writer at a random moment and checks
// that every acknowledged event survived, that there are no sequence gaps, and
// that the database passes integrity_check.
//
// This tests process crash only. The OS page cache survives SIGKILL, so it
// says nothing about power loss; that needs a VM or hardware power-cut test.
func runCrashDurability(args []string) error {
	fs := flag.NewFlagSet("crash-durability", flag.ExitOnError)
	iters := fs.Int("iterations", 40, "kill/verify cycles per mode")
	maxRun := fs.Duration("max-run", 2*time.Second, "upper bound of random kill delay")
	dir := fs.String("dir", os.TempDir(), "scratch directory")
	seed := fs.Int64("seed", 1, "random seed for kill delays")
	fs.Parse(args)

	self, err := os.Executable()
	if err != nil {
		return err
	}
	rng := rand.New(rand.NewSource(*seed))
	fmt.Printf("crash-durability: iterations=%d max-run=%s seed=%d\n", *iters, *maxRun, *seed)
	fmt.Println("mode            batch  runs  failures  acked(min/max)  committed-not-acked(max)")

	totalFailures := 0
	for _, mode := range []struct {
		sync  string
		batch int
	}{{"NORMAL", 1}, {"FULL", 1}, {"NORMAL", 100}, {"FULL", 100}} {
		failures := 0
		var minAcked, maxAcked, maxUnacked int64 = -1, 0, 0
		for i := 0; i < *iters; i++ {
			path := filepath.Join(*dir, fmt.Sprintf("crash-%s-%d-%d.db", mode.sync, mode.batch, i))
			for _, suffix := range []string{"", "-wal", "-shm"} {
				os.Remove(path + suffix)
			}
			acked, err := killWriterAt(self, path, mode.sync, mode.batch,
				50*time.Millisecond+time.Duration(rng.Int63n(int64(*maxRun))))
			if err != nil {
				return err
			}
			db, err := openStore(path, mode.sync)
			if err != nil {
				fmt.Printf("  FAIL run %d: reopen: %v\n", i, err)
				failures++
				continue
			}
			s, err := inspect(db)
			db.Close()
			switch {
			case err != nil:
				fmt.Printf("  FAIL run %d: inspect: %v\n", i, err)
				failures++
			case s.integrity != "ok":
				fmt.Printf("  FAIL run %d: integrity_check=%q\n", i, s.integrity)
				failures++
			case s.maxSeq < acked:
				fmt.Printf("  FAIL run %d: acked %d but max seq %d (acked events lost)\n", i, acked, s.maxSeq)
				failures++
			case s.count != s.maxSeq || (s.count > 0 && s.minSeq != 1):
				fmt.Printf("  FAIL run %d: gap: count=%d min=%d max=%d\n", i, s.count, s.minSeq, s.maxSeq)
				failures++
			}
			if minAcked < 0 || acked < minAcked {
				minAcked = acked
			}
			if acked > maxAcked {
				maxAcked = acked
			}
			if d := s.maxSeq - acked; d > maxUnacked {
				maxUnacked = d
			}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				os.Remove(path + suffix)
			}
		}
		totalFailures += failures
		fmt.Printf("%-15s %5d  %4d  %8d  %6d/%-7d  %d\n",
			mode.sync, mode.batch, *iters, failures, minAcked, maxAcked, maxUnacked)
	}
	if totalFailures > 0 {
		return fmt.Errorf("%d failed runs", totalFailures)
	}
	fmt.Println("result: PASS (no acknowledged event lost, no gaps, integrity ok in every run)")
	return nil
}

// killWriterAt starts a writer, SIGKILLs it after delay, and returns the last
// sequence number it acknowledged.
func killWriterAt(self, path, syncMode string, batch int, delay time.Duration) (int64, error) {
	cmd := exec.Command(self, "writer", "-db", path, "-sync", syncMode, "-batch", strconv.Itoa(batch))
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	lastCh := make(chan int64)
	go func() {
		var last int64
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if v, err := strconv.ParseInt(sc.Text(), 10, 64); err == nil {
				last = v
			}
		}
		lastCh <- last
	}()
	time.Sleep(delay)
	cmd.Process.Signal(syscall.SIGKILL)
	last := <-lastCh // pipe drained to EOF: every ack the child wrote is counted
	cmd.Wait()
	return last, nil
}

// runThroughput measures committed events per second for each durability
// mode. Absolute numbers depend on the disk; only the ratios are portable.
func runThroughput(args []string) error {
	fs := flag.NewFlagSet("throughput", flag.ExitOnError)
	dir := fs.String("dir", os.TempDir(), "scratch directory")
	dur := fs.Duration("duration", 3*time.Second, "time per mode")
	fs.Parse(args)

	fmt.Printf("throughput: duration=%s per mode, payload=%d bytes\n", *dur, len(payload))
	fmt.Println("mode     batch  events/s")
	for _, mode := range []struct {
		sync  string
		batch int
	}{{"NORMAL", 1}, {"FULL", 1}, {"NORMAL", 100}, {"FULL", 100}} {
		path := filepath.Join(*dir, "throughput.db")
		for _, suffix := range []string{"", "-wal", "-shm"} {
			os.Remove(path + suffix)
		}
		db, err := openStore(path, mode.sync)
		if err != nil {
			return err
		}
		var n int64
		start := time.Now()
		for time.Since(start) < *dur {
			if _, err := insertBatch(db, mode.batch, time.Now().UnixNano()); err != nil {
				return err
			}
			n += int64(mode.batch)
		}
		db.Close()
		fmt.Printf("%-8s %5d  %8.0f\n", mode.sync, mode.batch, float64(n)/time.Since(start).Seconds())
	}
	return nil
}
