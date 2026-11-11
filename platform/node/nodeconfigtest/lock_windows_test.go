//go:build windows

package nodeconfigtest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// However LockTLS ends, tls_dir can be removed by this account: locked, after
// UnlockTLS; refused for want of elevation, at once, with no UnlockTLS first.
// The refusal left tls_dir read only for this account, so a test that then
// skipped failed its TempDir cleanup and left the directory behind (P4-PC-1,
// on a desktop that is not elevated). The refused case runs only in a
// process that is not elevated: GitHub Actions' runners are.
func TestLockTLSLeavesTLSDirRemovable(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "store")
	c := New("site-a-node1", storeDir)
	if _, err := c.WritePKI("127.0.0.1", "test-ca", "test-client"); err != nil {
		t.Fatal(err)
	}
	// Registered after TempDir's, so it runs first: if the check below
	// fails, the directory is still removed.
	t.Cleanup(func() { c.UnlockTLS() })
	err := c.LockTLS()
	switch {
	case errors.Is(err, ErrNeedsElevation):
		t.Logf("refused, as it is without elevation: %v", err)
	case err != nil:
		t.Fatal(err)
	default:
		if err := c.UnlockTLS(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(c.TLSDir); err != nil {
		t.Fatalf("tls_dir cannot be removed: %v", err)
	}
}
