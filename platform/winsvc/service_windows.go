//go:build windows

package winsvc

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// IsService reports whether the process was started by the SCM.
func IsService() (bool, error) { return svc.IsWindowsService() }

// Run runs work as the otsec-node service until the SCM stops it. work
// gets a context that ends on Stop or Shutdown, and an OS log that writes
// to the Windows Event Log. The service reports stopped only after work
// has returned, so the store is closed and service.stop recorded first.
func Run(work func(ctx context.Context, oslog func(string)) error) error {
	el, err := eventlog.Open(NodeService)
	if err != nil {
		return err
	}
	defer el.Close()
	return svc.Run(NodeService, &handler{work: work, log: el})
}

type handler struct {
	work func(ctx context.Context, oslog func(string)) error
	log  *eventlog.Log
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.work(ctx, func(s string) { h.log.Warning(1, s) }) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				h.log.Error(2, "otsec node stopped: "+err.Error())
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32((30 * time.Second).Milliseconds())}
				cancel()
				if err := <-done; err != nil {
					h.log.Error(2, "otsec node stopped: "+err.Error())
					return false, 1
				}
				return false, 0
			}
		}
	}
}
