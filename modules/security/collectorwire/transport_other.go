//go:build !linux && !windows

package collectorwire

import (
	"context"
	"net"
)

// Listen is not supported on this operating system.
func Listen(Endpoint) (net.Listener, error) { return nil, ErrUnsupported }

// Dial is not supported on this operating system.
func Dial(context.Context, Endpoint) (net.Conn, error) { return nil, ErrUnsupported }

// CurrentIdentity is not supported on this operating system.
func CurrentIdentity() (string, error) { return "", ErrUnsupported }
