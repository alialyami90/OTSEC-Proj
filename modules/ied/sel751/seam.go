// Package sel751 is the C2 adapter for the SEL-751 (D2-1): the session
// dialogue, the parsers, and the egress check on every line. It is hosted
// by the collector (A3), which owns everything that happens before a
// session may start: the role check, the device-observed refusal (D2-4),
// the register signature, the declared-FID gate, one session per device,
// and the failed-auth floor check.
//
// This file is the seam agreed with A3 for Phase 2. The adapter's one entry
// point, Run(ctx, Invocation, Config) adapter.Result, follows in a later
// change; it never returns a Go error, every outcome is a C2 Result, and
// the collector runs Validate, CheckLines and CheckAgainst on it.
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
	// Use calls f once with the secret. The adapter writes the secret and a
	// line end inside f. A second Use fails.
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
}
