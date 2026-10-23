// Command p0 holds A5's Phase 0 platform experiments. It is throwaway
// investigation code, not production code: it exists to produce reproducible
// evidence for the persistence, storage-limit, and forwarding decisions
// recorded in platform/PHASE0.md. See README.md in this directory.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	// Child-process roles, started by the harnesses below.
	case "writer":
		err = runWriter(args)
	case "plain-receiver":
		err = runPlainReceiver(args)
	case "acked-receiver":
		err = runAckedReceiver(args)
	// Experiments.
	case "crash-durability":
		err = runCrashDurability(args)
	case "throughput":
		err = runThroughput(args)
	case "storage-limit":
		err = runStorageLimit(args)
	case "syslog-loss":
		err = runSyslogLoss(args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: p0 crash-durability|throughput|storage-limit|syslog-loss [flags]")
	os.Exit(2)
}
