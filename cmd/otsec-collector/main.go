// Command otsec-collector is the privileged collector service (D2-1,
// ADR-0002; A3 credential design). It holds the credential store, the
// durable collector state and the verified register packages, and it is
// the only process that talks to devices. The node reaches it only through
// the C7 IPC, on a pipe (Windows) or socket (Linux) whose peer is checked on
// both ends (W-1).
//
// Usage:
//
//	otsec-collector run -data <dir>
//
// On Windows the service control manager starts it as NT SERVICE\otsec-collector
// with -data %ProgramData%\OTSEC. Run interactively, it serves in the
// foreground until interrupted; that is for development only.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/store"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: otsec-collector run -data <dir>")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "the platform's data directory")
	fs.Parse(os.Args[2:])
	if fs.NArg() != 0 || *data == "" {
		fmt.Fprintln(os.Stderr, "usage: otsec-collector run -data <dir>")
		os.Exit(2)
	}
	// T-5: no crash dump or core file may hold a secret. This runs before
	// anything reads a store.
	if err := harden(); err != nil {
		fmt.Fprintf(os.Stderr, "otsec-collector: refusing to start: %v\n", err)
		os.Exit(1)
	}
	os.Exit(serve(*data))
}

// running is a started collector.
type running struct {
	srv     *collector.Server
	done    chan error
	once    sync.Once
	stopErr error
}

// stop closes the server and waits for open connections to finish. A second
// call returns the first call's result.
func (r *running) stop() error {
	r.once.Do(func() {
		r.stopErr = r.srv.Close()
		if serr := <-r.done; serr != nil && !errors.Is(serr, collector.ErrServerClosed) {
			r.stopErr = serr
		}
	})
	return r.stopErr
}

// start loads the configuration, opens or (at the first start) creates the
// stores, verifies the register packages, and starts serving. Any failure
// before serving stops the start: the collector never runs on a guess.
func start(data string, log *slog.Logger) (*running, error) {
	alarm := func(err error) { log.Error("ALARM", "err", err) }
	l := newLayout(data)
	cfg, err := loadConfig(l.config)
	if err != nil {
		return nil, err
	}
	created, err := provision(l, cfg.NodeID, time.Now)
	if err != nil {
		return nil, err
	}
	state, err := collector.OpenState(l.state, nil)
	if err != nil {
		return nil, err
	}
	creds, err := collector.OpenCredStore(l.credentials, collector.CredStoreConfig{NodeID: cfg.NodeID, Generations: state})
	if err != nil {
		return nil, err
	}
	key := creds.InstallKey()
	// The fingerprint is public. The admin compares it with the one
	// recorded at commissioning before sealing anything (T-12).
	log.Info("collector install key", "key_id", key.KeyID, "fingerprint", creds.Fingerprint(), "first_start", created)
	// The node checks this file before every request to find a reinstall
	// (D2-15), so the collector does not serve without it.
	if err := publishInstallKey(l, creds); err != nil {
		return nil, fmt.Errorf("install key not published: %w", err)
	}
	regs := collector.NewRegisters(state, cfg.Anchors)
	for i, env := range cfg.Registers {
		pkg, err := regs.Activate(env)
		if err != nil {
			// SC-18: no device I/O for that family, and an alarm.
			alarm(fmt.Errorf("register package %d rejected: %w", i, err))
			continue
		}
		log.Info("register package active", "family", pkg.Family, "revision", pkg.Revision)
	}
	pipe, err := collector.NewPipeline(collector.PipelineConfig{
		NodeID: cfg.NodeID, PolicyVersion: cfg.PolicyVersion, Assets: cfg.Assets,
		State: state, Creds: creds, Registers: regs, Runner: hostedRunner(),
		InstallLimit: cfg.InstallLimit, Alarm: alarm,
		ReadClearFile: clearFileReader(l.admin, []string{cfg.Endpoint.Peer, collectorwire.ServiceSID(collectorwire.CollectorService)}),
	})
	if err != nil {
		return nil, err
	}
	ln, err := collectorwire.Listen(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	return serveOn(ln, pipe, log), nil
}

// clearFileReader reads clear-suspension.json in the administrators'
// folder for an asset.clear_suspension request, checking the folder and
// then the file every time: owned by SYSTEM or Administrators, a protected
// DACL, and nothing more than read for the node or the collector, so
// neither service could have written what it reads (store.CheckProtectedDirFor,
// ReadProtectedFileFor). On Linux, a development platform only, the check
// is the mode. readers are the node's identity and the collector's own.
func clearFileReader(dir string, readers []string) func() ([]byte, error) {
	return func() ([]byte, error) {
		if err := store.CheckProtectedDirFor(dir, readers); err != nil {
			return nil, err
		}
		return store.ReadProtectedFileFor(filepath.Join(dir, collector.ClearSuspensionFileName), collector.MaxClearSuspensionBytes, readers)
	}
}

func serveOn(ln net.Listener, h collector.Handler, log *slog.Logger) *running {
	r := &running{srv: &collector.Server{Handler: h, Log: log}, done: make(chan error, 1)}
	go func() { r.done <- r.srv.Serve(ln) }()
	return r
}

// hostedRunner is the adapter the collector hosts. A2's sel751.Run is wired
// in when it lands; until then every run is refused with not_invocable and
// only credential requests are served.
func hostedRunner() collector.Runner { return nil }
