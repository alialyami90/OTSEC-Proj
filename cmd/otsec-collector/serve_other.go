//go:build !windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"otsec.local/otsec/modules/security/collectorwire"
)

func defaultDataDir() string { return "" }

// defaultEndpoint: on Linux, the development platform, the socket and the
// node's uid must both be set.
func defaultEndpoint(c ipcConfig) (collectorwire.Endpoint, error) {
	if c.Address == "" || c.NodePeer == "" {
		return collectorwire.Endpoint{}, errMissingIPC
	}
	return collectorwire.Endpoint{Address: c.Address, Peer: c.NodePeer}, nil
}

// serve runs in the foreground until SIGINT or SIGTERM.
func serve(data string) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r, err := start(data, log)
	if err != nil {
		log.Error("otsec-collector: refusing to start", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
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
