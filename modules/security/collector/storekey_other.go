//go:build !windows

package collector

// keyProtection names how the store key is protected on this platform. A
// store written on another platform, or with another protection, is refused.
//
// Linux is the development and CI platform (A3-collector.md). The store key
// is written as it is, and the file's mode (0600, in a 0700 directory) is
// its only protection. Phase 2 credentials there are test values only
// (D2-5); a production node runs Windows, which uses DPAPI.
const keyProtection = "none-development"

func protectKey(key []byte) ([]byte, error) { return append([]byte(nil), key...), nil }

func unprotectKey(b []byte) ([]byte, error) {
	if len(b) != storeKeyLen {
		return nil, errStoreKeyLength
	}
	return append([]byte(nil), b...), nil
}
