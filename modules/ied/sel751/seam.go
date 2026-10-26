// Package sel751 is the C2 adapter for the SEL-751 (D2-1): the session
// dialogue, the parsers, and the egress check on every line. It is hosted
// by the collector (A3), which owns everything that happens before a
// session may start: the role check, the device-observed refusal (D2-4),
// the register signature, the declared-FID gate, one session per device,
// and the failed-auth floor check.
//
// This file is the seam agreed with A3 for Phase 2. The adapter's one entry
// point is Run(ctx, Invocation, Config) adapter.Result (run.go); it never
// returns a Go error, every outcome is a C2 Result, and the collector runs
// Validate, CheckLines and CheckAgainst on it.
package sel751

import (
	"context"
	"net"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
)

// FloorGate is the collector's durable failed-auth state for the run's asset
// (D1-20 as amended; A3 design, C7-A5-3). The collector binds one gate to
// one asset for one run.
type FloorGate interface {
	// BeforeACC returns only once the attempt time is durable. The adapter
	// writes ACC only after it returns nil. On an error nothing is sent, and
	// the session closes with failed.internal and no QUI, since nothing was
	// elevated.
	BeforeACC(ctx context.Context) error
	// Confirmed is called once, when "=>" is received after ACC and before
	// the next line is sent, whether or not the credential was sent (so the
	// prompt-absent path, AP-23, clears it too). "=>>" never calls it. A
	// failure to clear leaves the floor set, which is the safe side, so it
	// returns nothing; the gate logs or alarms inside.
	Confirmed(ctx context.Context)
}

// Secret is the single-use credential slot (HR-3, C-17). The store keeps the
// bytes until the collector closes the handle after Run returns, then zeroes
// them; the adapter never holds a copy.
type Secret interface {
	// Use calls f once with the secret. Inside f the adapter writes it with
	// telnet.Conn.SendSecret: the secret, CR LF, in one Write, once per
	// session. That line does not pass the C3 egress check, since no
	// register line can match a password; the credential slot is its check
	// instead: ACC was sent and passed egress, the next received bytes end
	// in "Password: ?", and nothing else is sent in between (HR-3, C-17).
	// A second Use fails.
	Use(f func(secret []byte) error) error
	// EchoSpans returns the ranges of rx that equal the secret, as
	// half-open [start, end) byte offsets, so the adapter can replace each
	// with the redaction marker. The comparison happens inside the store.
	EchoSpans(rx []byte) [][2]int
}

// Config is everything one run needs besides the invocation.
type Config struct {
	Asset    asset.Asset
	Profile  asset.CapabilityProfile
	Register *register.Package
	// Endpoint is the C1 endpoint ID; the host and port come from the asset.
	Endpoint string
	// Secret is nil for an operation at Level 0.
	Secret Secret
	// Floor is required whenever Secret is set.
	Floor FloorGate
	// Dial opens the connection. The collector's dialer permits only the
	// endpoint's configured host and port (A3 W-3); tests inject the
	// simulator or a replay. Run never calls net.Dial itself.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Now is the clock for transcript times; nil means time.Now.
	Now func() time.Time
	// TIDLE, when set, is called at most once per run, after the run and
	// only when it ended ok or partial, with the port's Telnet time-out,
	// when SHO P 1 read LANG := ENGLISH and TIDLE is a whole number of
	// minutes from 1 to 30 (S22 Table 4.104, TELNET TIMEOUT). The collector
	// uses it for the failed-auth floor (authz.FailureFloor). It is not
	// called for any other value or outcome, which leaves the floor at its
	// longest.
	//
	// TIDLE is the time-out of the relay's own Ethernet Telnet. Through a
	// port server to a serial port, the session's time-out is that port's
	// T_OUT, which SHO P 1 does not show and which may be longer or 0 (A6
	// on #114). Run therefore opens a session only on an endpoint whose C1
	// path is direct, and refuses any other with refused.endpoint_path
	// before connecting (D2-16, H-13), so a reported TIDLE is always a
	// direct path's.
	TIDLE func(time.Duration)

	hooks *hooks // tests only
}
