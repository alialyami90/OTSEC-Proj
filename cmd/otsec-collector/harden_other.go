//go:build !linux && !windows

package main

import "errors"

func harden() error { return errors.New("no crash-dump controls on this operating system") }
