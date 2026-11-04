//go:build otsec_testclock

package main

import (
	"flag"

	"otsec.local/otsec/platform/node"
)

// A test build's -test-clock puts the node on the stepped clock in that
// file (node.UseTestClock, D4-40). A release build has no such flag.
func init() {
	testFlags = func(fs *flag.FlagSet) func() error {
		path := fs.String("test-clock", "", "test builds only: a file holding the node's time (RFC 3339), which the harness steps forward")
		return func() error {
			if *path == "" {
				return nil
			}
			return node.UseTestClock(*path)
		}
	}
}
