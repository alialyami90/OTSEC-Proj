package node

import (
	"context"
	"errors"
	"runtime"
	"time"

	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
)

// TickInterval is how often a running node resumes blocked databases,
// turns queued store alarms into health events and rewrites its status.
const TickInterval = 60 * time.Second

// Run runs a node until ctx ends: C5 startup of every database, one
// forwarder per target (NewForwarding, which stops the node on a bad TLS
// reference), the scheduler through the collector at cfg's pipe, and
// Tick every TickInterval and Forwarding.Check every CheckInterval. oslog receives every alarm line (the Event Log under the
// SCM, stderr otherwise). Each tick also does the scheduler's part of a
// quarantine export and clear (Scheduler.QuarantineTick). It returns nil when ctx ends, after service.stop
// is recorded and every database is closed.
func Run(ctx context.Context, cfg *Config, oslog func(string)) error {
	st := NewStatus(StatusPath(cfg), oslog, nil)
	rt, err := Start(ctx, cfg, RuntimeOptions{Status: st})
	if err != nil {
		return err
	}
	defer rt.Close()
	fw, err := NewForwarding(rt)
	if err != nil {
		return err
	}
	sched, err := NewScheduler(ctx, rt, collectorclient.New(CollectorEndpoint(cfg)))
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(TickInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rt.Tick(ctx)
				sched.QuarantineTick(ctx)
			}
		}
	}()
	checked := make(chan struct{})
	go func() {
		defer close(checked)
		t := time.NewTicker(CheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fw.Check(ctx)
			}
		}
	}()
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		fw.Run(ctx)
	}()
	err = sched.Run(ctx)
	<-done
	<-checked
	<-forwarded
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// CollectorEndpoint is the collector's channel and the identity it must
// hold: on Windows the otsec-collector service SID unless the
// configuration names another (W-1).
func CollectorEndpoint(cfg *Config) collectorwire.Endpoint {
	peer := cfg.CollectorPeer
	if peer == "" && runtime.GOOS == "windows" {
		peer = collectorwire.ServiceSID(collectorwire.CollectorService)
	}
	return collectorwire.Endpoint{Address: cfg.CollectorPipe, Peer: peer}
}
