//go:build linux

package main

import "golang.org/x/sys/unix"

// hardenedExitCode is 0 when the process is not dumpable and its core limit
// is zero, and non-zero otherwise.
func hardenedExitCode() int {
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || d != 0 {
		return 4
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
		return 5
	}
	return 0
}
