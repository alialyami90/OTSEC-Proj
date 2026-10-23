package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// runWriteAmplification measures bytes written to storage per stored event,
// for the SSD-endurance estimate ADR-0007 asks for. It counts bytes the
// process hands to the OS (WAL frames, checkpoint copies, journal), not what
// the SSD controller then writes, so it is a lower bound on NAND wear.
func runWriteAmplification(args []string) error {
	fs := flag.NewFlagSet("write-amplification", flag.ExitOnError)
	dir := fs.String("dir", os.TempDir(), "scratch directory")
	events := fs.Int("events", 20000, "events per configuration")
	fs.Parse(args)

	fmt.Printf("write-amplification: %d events per configuration, payload=%d bytes, synchronous=FULL\n", *events, len(payload))
	fmt.Println("wal settings                       batch  bytes/event  amplification")
	for _, c := range []struct {
		tuned bool
		batch int
	}{{false, 1}, {false, 10}, {true, 1}, {true, 10}, {true, 100}} {
		path := filepath.Join(*dir, "amp.db")
		removeDB(path)
		if c.tuned {
			if err := createIncrementalVacuumDB(path); err != nil {
				return err
			}
		}
		db, err := openStore(path, "FULL")
		if err != nil {
			return err
		}
		if c.tuned {
			for _, p := range tunedPragmas {
				if _, err := db.Exec(p); err != nil {
					return err
				}
			}
		}
		before := bytesWritten()
		for n := 0; n < *events; n += c.batch {
			if _, err := insertBatch(db, c.batch, time.Now().UnixNano()); err != nil {
				return err
			}
		}
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)") // count the final copy into the database too
		after := bytesWritten()
		db.Close()
		removeDB(path)
		label := "default (autocheckpoint 1000)"
		if c.tuned {
			label = "bounded, auto_vacuum=INCREMENTAL"
		}
		if before < 0 || after < 0 {
			fmt.Printf("%-34s %5d  not measurable on this OS\n", label, c.batch)
			continue
		}
		per := float64(after-before) / float64(*events)
		fmt.Printf("%-34s %5d  %11.0f  %12.1fx\n", label, c.batch, per, per/float64(len(payload)))
	}
	return nil
}
