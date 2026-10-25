package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// publishInstallKey writes the public install key and its fingerprint for
// the node to publish, when the public directory exists. It holds nothing
// secret; its integrity is what the admin's pinned fingerprint checks.
func publishInstallKey(l layout, s *collector.CredStore) error {
	if ok, err := exists(filepath.Dir(l.publicKey)); err != nil || !ok {
		return err
	}
	k := s.InstallKey()
	b, err := json.MarshalIndent(struct {
		KeyID       string `json:"key_id"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}{k.KeyID, k.PublicKey, s.Fingerprint()}, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.publicKey + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, l.publicKey)
}
