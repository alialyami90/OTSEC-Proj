//go:build !windows

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// On Linux, a development platform only, the For checks admit group read
// in place of the readers and refuse any write bit and anything for
// others; a link is refused.
func TestProtectedForModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "admin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "clear.json")
	if err := os.WriteFile(file, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o400, true}, {0o440, true}, {0o600, false}, {0o460, false}, {0o444, false}, {0o441, false}} {
		os.Chmod(dir, 0o700)
		os.Chmod(file, c.mode)
		os.Chmod(dir, 0o550)
		_, err := ReadProtectedFileFor(file, 64, []string{"S-1-5-80-1"})
		if (err == nil) != c.ok {
			t.Errorf("file %04o: %v, want ok %v", c.mode, err, c.ok)
		}
	}
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o500, true}, {0o550, true}, {0o700, false}, {0o570, false}, {0o555, false}, {0o551, false}} {
		os.Chmod(dir, c.mode)
		err := CheckProtectedDirFor(dir, nil)
		if (err == nil) != c.ok {
			t.Errorf("directory %04o: %v, want ok %v", c.mode, err, c.ok)
		}
	}
	os.Chmod(dir, 0o550)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtectedDirFor(link, nil); err == nil {
		t.Fatal("a linked directory accepted")
	}
	flink := filepath.Join(t.TempDir(), "flink")
	if err := os.Symlink(file, flink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedFileFor(flink, 64, nil); err == nil {
		t.Fatal("a linked file accepted")
	}
	if err := CheckProtectedDir(dir); err == nil {
		t.Fatal("the plain check accepted group access")
	}
}
