//go:build !windows

package nodeconfigtest

import (
	"errors"
	"os"
	"path/filepath"
)

// LockTLS makes tls_dir and its files what D2-12 requires of an installed
// node: readable by the owner, writable by nobody (files 0400, directory
// 0500). Tests change the files first, then lock.
func (c *Config) LockTLS() error { return c.chmodTLS(0o400, 0o500) }

// ShareTLS is LockTLS for a directory another service also reads, as
// the installer lays out OTSEC\config\admin: group read stands in for the
// reader, so files 0440 and the directory 0550. reader is for Windows.
func (c *Config) ShareTLS(reader string) error { return c.chmodTLS(0o440, 0o550) }

// UnlockTLS undoes LockTLS so the files can be changed or removed.
func (c *Config) UnlockTLS() error { return c.chmodTLS(0o600, 0o700) }

// LoosenTLS gives this account write access to one file in tls_dir, or to
// tls_dir itself when name is empty, after LockTLS.
func (c *Config) LoosenTLS(name string) error {
	if name == "" {
		return os.Chmod(c.TLSDir, 0o700)
	}
	if err := os.Chmod(c.TLSDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(c.TLSDir, name), 0o600); err != nil {
		return err
	}
	return os.Chmod(c.TLSDir, 0o500)
}

// OwnTLS is Windows only: on Linux the owner is always this account.
func (c *Config) OwnTLS(name string) error {
	return errors.New("nodeconfigtest: OwnTLS is Windows only")
}

func (c *Config) chmodTLS(file, dir os.FileMode) error {
	if err := os.Chmod(c.TLSDir, 0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(c.TLSDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := os.Chmod(filepath.Join(c.TLSDir, e.Name()), file); err != nil {
				return err
			}
		}
	}
	return os.Chmod(c.TLSDir, dir)
}
