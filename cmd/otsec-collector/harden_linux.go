//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// harden keeps secrets out of core files (T-5): the process is made
// non-dumpable, which also stops ptrace by other processes of the same
// user, and its core size limit is set to zero.
func harden() error {
	if err := checkTraceback(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_CORE: %w", err)
	}
	return nil
}
