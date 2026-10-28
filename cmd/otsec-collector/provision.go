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
	if now == nil {
		now = time.Now
	}
	state, sErr := exists(l.state)
	creds, cErr := exists(l.credentials)
	if sErr != nil || cErr != nil {
		return false, errors.Join(sErr, cErr)
	}
	switch {
	case state && creds:
		// A marker left by a start that crashed after creating the stores
		// would turn a later loss of both into a silent first start, so it
		// goes now (A6 on #106).
		if err := os.Remove(l.provision); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("the stores exist, but a leftover first-start marker could not be removed: %w", err)
		}
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
	if err := collector.InitState(l.state, now()); err != nil {
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
// collector serves, through collector.ReplaceFile: a reader sees the old file
// or the new one, never part of one. The node reads it before every request,
// and the replace rides out a read in progress for a bounded time (A6 on
// #106); a key that still cannot be published stops the start. The public
// directory is the installer's (A5), and a missing one is an error, not a
// skip.
func publishInstallKey(l layout, s *collector.CredStore) error {
	k := s.InstallKey()
	b, err := json.MarshalIndent(publishedKey{installKeySchema, k.KeyID, k.PublicKey, s.Fingerprint()}, "", "  ")
	if err != nil {
		return err
	}
	if err := collector.ReplaceFile(l.publicKey, append(b, '\n'), 0o644); err != nil {
		os.Remove(l.publicKey + ".tmp")
		return err
	}
	return nil
}
