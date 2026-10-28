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
// reference), one Syslog listener per configured listener (NewListening,
// which stops the node on a bad TLS reference or an address it cannot
// bind), the scheduler through the collector at cfg's pipe, and
// Tick every TickInterval and Forwarding.Check every CheckInterval. A
// certificate outside its validity period holds back only its own target or
// listener (HR-13, D4-11); every other TLS fault stops the node. oslog receives every alarm line (the Event Log under the
// SCM, stderr otherwise). Each tick also does the scheduler's part of a
// quarantine export and clear (Scheduler.QuarantineTick). It returns nil when ctx ends, after service.stop
// is recorded and every database is closed.
func Run(ctx context.Context, cfg *Config, oslog func(string)) error {
	st := NewStatus(StatusPath(cfg), oslog, nil)
	// No status file is written until each target and listener has been
	// judged against its certificate's period (below), so the first one
	// never says the node is collecting without showing a link held back
	// (HR-13). Start writes one when the databases are open.
	st.Defer()
	rt, err := Start(ctx, cfg, RuntimeOptions{Status: st})
	if err != nil {
		return err
	}
	defer rt.Close()
	fw, err := NewForwarding(rt)
	if err != nil {
		return err
	}
	ls, err := NewListening(rt)
	if err != nil {
		return err
	}
	// Every reference is resolved now, so the key register is loaded:
	// record its new entries (section 9).
	keysLeft := rt.RecordNodeKeys(ctx)
	rt.CheckNodeKeys()
	rt.RecordLabTLSFiles(ctx)
	sched, err := NewScheduler(ctx, rt, collectorclient.New(CollectorEndpoint(cfg)))
	if err != nil {
		return err
	}
	if err := ls.Listen(); err != nil {
		return err
	}
	// Status shows each target and listener from the start, a link held back
	// for its certificate's period among them (HR-13), not after the first
	// CheckInterval.
	fw.Check(ctx)
	if len(cfg.Listeners) > 0 {
		ls.Publish()
	}
	st.Resume()
	st.Write(string(cfg.NodeID))
	listened := make(chan struct{})
	go func() {
		defer close(listened)
		ls.Run(ctx)
	}()
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
				if keysLeft > 0 {
					keysLeft = rt.RecordNodeKeys(ctx)
				}
				rt.CheckNodeKeys()
				if len(cfg.Listeners) > 0 || cfg.KeyRegister != "" {
					ls.Publish()
					st.Write(string(cfg.NodeID))
				}
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
	<-listened
	ls.Publish()
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
