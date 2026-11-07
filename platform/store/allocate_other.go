//go:build !linux && !windows

package store

import (
	"errors"
	"os"
)

// allocateFile has no single call here, so CreateReserve writes zeros.
func allocateFile(*os.File, int64) error { return errors.ErrUnsupported }
