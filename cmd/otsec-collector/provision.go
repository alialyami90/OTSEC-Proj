package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"otsec.local/otsec/modules/security/collector"
)

// errLostState is returned when a store is missing and the installer's
// first-start marker is not there: the state was lost, and creating a new
// one would reopen every failed-auth floor, restart collector_seq and make
// an install key no admin has pinned.
var errLostState = errors.New("collector state or credential store is missing and this is not a first start")

// provision creates both stores at the first start. It does so only when
// both are absent and the installer's marker is present, then removes the
// marker. It must run as the collector's own account, because the
// credential store key is protected for that account (DPAPI user scope).
// It reports whether it created the stores.
func provision(l layout, nodeID string, now func() time.Time) (bool, error) {
	state, sErr := exists(l.state)
	creds, cErr := exists(l.credentials)
	if sErr != nil || cErr != nil {
		return false, errors.Join(sErr, cErr)
	}
	switch {
	case state && creds:
		return false, nil
	case state != creds:
		return false, fmt.Errorf("%w: only one of %s and %s exists", errLostState, l.state, l.credentials)
	}
	marker, err := exists(l.provision)
	if err != nil {
		return false, err
	}
	if !marker {
		return false, fmt.Errorf("%w: no %s", errLostState, l.provision)
	}
	if err := collector.InitState(l.state, time.Now()); err != nil {
		return false, err
	}
	if err := collector.InitCredStore(l.credentials, nodeID, now); err != nil {
		return false, err
	}
	if err := os.Remove(l.provision); err != nil {
		return true, fmt.Errorf("stores created, but the first-start marker could not be removed: %w", err)
	}
	return true, nil
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// installKeySchema names the shape of install-key.json, so that a reader
// can refuse a file it does not know.
const installKeySchema = "otsec.collector.install_key/0.1"

// publishedKey is install-key.json: the public install key and its
// fingerprint, for the node to read before every request (D2-15) and to
// publish (T-12). Nothing in it is secret; its integrity is what the
// admin's pinned fingerprint checks.
type publishedKey struct {
	Schema      string `json:"schema"`
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"` // standard base64, 32 bytes (seal.InstallKey)
	Fingerprint string `json:"fingerprint"`
}

// publishInstallKey writes install-key.json at every start, before the
// collector serves. It writes a temporary file, syncs it and renames it over
// the old one, so a reader sees the old file or the new one, never part of
// one. The public directory is the installer's (A5), and a missing one is an
// error, not a skip.
func publishInstallKey(l layout, s *collector.CredStore) error {
	k := s.InstallKey()
	b, err := json.MarshalIndent(publishedKey{installKeySchema, k.KeyID, k.PublicKey, s.Fingerprint()}, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.publicKey + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, l.publicKey)
}
