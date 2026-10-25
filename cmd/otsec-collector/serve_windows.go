//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"otsec.local/otsec/modules/security/collectorwire"
)

func defaultDataDir() string { return filepath.Join(os.Getenv("ProgramData"), "OTSEC") }

// defaultEndpoint fills in the production pipe and the node's service SID.
func defaultEndpoint(c ipcConfig) (collectorwire.Endpoint, error) {
	ep := collectorwire.Endpoint{Address: c.Address, Peer: c.NodePeer}
	if ep.Address == "" {
		ep.Address = collectorwire.DefaultPipe
	}
	if ep.Peer == "" {
		ep.Peer = collectorwire.ServiceSID(collectorwire.NodeService)
	}
	return ep, nil
}

// serve runs under the service control manager, logging to the Event Log
// under the source otsec-collector, which the installer registers. Run
// interactively, it serves in the foreground until interrupted.
func serve(data string) int {
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "otsec-collector: %v\n", err)
		return 1
	}
	if !isService {
		return foreground(data)
	}
	el, err := eventlog.Open(collectorwire.CollectorService)
	if err != nil {
		return 1
	}
	defer el.Close()
	log := slog.New(&eventHandler{l: el})
	if err := svc.Run(collectorwire.CollectorService, &service{data: data, log: log}); err != nil {
		log.Error("otsec-collector: service", "err", err)
		return 1
	}
	return 0
}

type service struct {
	data string
	log  *slog.Logger
}

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	r, err := start(s.data, s.log)
	if err != nil {
		s.log.Error("otsec-collector: refusing to start", "err", err)
		return false, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				if err := r.stop(); err != nil {
					s.log.Error("otsec-collector: stop", "err", err)
					return false, 2
				}
				return false, 0
			}
		case err := <-r.done:
			s.log.Error("otsec-collector: server stopped", "err", err)
			return false, 3
		}
	}
}

func foreground(data string) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r, err := start(data, log)
	if err != nil {
		log.Error("otsec-collector: refusing to start", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-r.done:
		log.Error("otsec-collector: server stopped", "err", err)
		return 1
	}
	if err := r.stop(); err != nil {
		log.Error("otsec-collector: stop", "err", err)
		return 1
	}
	return 0
}

// eventHandler writes slog records to the Event Log, one event each.
type eventHandler struct {
	l     *eventlog.Log
	attrs []slog.Attr
}

func (h *eventHandler) Enabled(_ context.Context, lv slog.Level) bool { return lv >= slog.LevelInfo }

func (h *eventHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	add := func(a slog.Attr) bool { fmt.Fprintf(&b, " %s=%v", a.Key, a.Value); return true }
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)
	switch {
	case r.Level >= slog.LevelError:
		return h.l.Error(1, b.String())
	case r.Level >= slog.LevelWarn:
		return h.l.Warning(1, b.String())
	default:
		return h.l.Info(1, b.String())
	}
}

func (h *eventHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &eventHandler{l: h.l, attrs: append(slices.Clone(h.attrs), as...)}
}

func (h *eventHandler) WithGroup(string) slog.Handler { return h }
