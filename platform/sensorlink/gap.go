package sensorlink

import (
	"strings"
	"time"
)

// The gap model while the node runs, INT-D5 2e-2 (docs/phase4/D5-sensor-node.md
// section 1.9 item 5; C13 CH-39, CH-45). The 0.2 intake only, as W is
// (watch.go). Not wired (F-027's gate).

// gapCauses is CH-45's closed set of causes, in the order of their bits in
// the cursor.
var gapCauses = []string{"node-start", "link", "restart", "held", "revoked", "sensor-failed", "silent", "lost", "blind"}

// The causes 2e-2 opens or adds.
const (
	CauseLink         = "link"
	CauseRestart      = "restart"
	CauseSensorFailed = "sensor-failed"
	CauseSilent       = "silent"
	CauseBlind        = "blind"
)

// gapCauseBit is cause's bit, 0 for a token outside the set.
func gapCauseBit(cause string) uint16 {
	for i, c := range gapCauses {
		if c == cause {
			return 1 << i
		}
	}
	return 0
}

// causeNames is bits as CH-45's causes detail: the tokens, space-separated,
// in gapCauses' order.
func causeNames(bits uint16) string {
	var out []string
	for i, c := range gapCauses {
		if bits&(1<<i) != 0 {
			out = append(out, c)
		}
	}
	return strings.Join(out, " ")
}

// HeldGap is the gap held for the floor (CH-18, CH-45): a gap closed
// unwatched whose raise of W, R and the floor is saved before its event
// commits, with every gap other than lost that closed unwatched while it
// waited merged into it.
type HeldGap struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Cause   string    `json:"cause"`
	Causes  uint16    `json:"causes"`
	Gaps    uint64    `json:"gaps"`
	Stepped bool      `json:"stepped,omitempty"`
	Bound   bool      `json:"bound,omitempty"`
}
