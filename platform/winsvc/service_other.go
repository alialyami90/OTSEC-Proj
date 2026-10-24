//go:build !windows

package winsvc

import (
	"context"
	"errors"
)

// ErrUnsupported is returned off Windows: Linux runs the node in the
// foreground under its init system.
var ErrUnsupported = errors.New("winsvc: Windows only")

// InstallOptions are the installer's inputs (Windows only).
type InstallOptions struct {
	NodeExe, CollectorExe, Config string
}

func IsService() (bool, error)                                      { return false, nil }
func Run(func(ctx context.Context, oslog func(string)) error) error { return ErrUnsupported }
func Install(InstallOptions) error                                  { return ErrUnsupported }
func Uninstall() error                                              { return ErrUnsupported }
