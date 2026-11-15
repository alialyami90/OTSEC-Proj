//go:build !linux && !windows

package collector

// readTCPInfo has no read on this platform: unsupported.
func readTCPInfo(uintptr) (sockCounts, error) { return sockCounts{}, nil }
