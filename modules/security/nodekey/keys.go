package nodekey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Provider names where a tls-key entry's key lives.
type Provider string

const (
	// ProviderCNGSoftware is a CNG machine key in the Microsoft Software
	// Key Storage Provider (Windows).
	ProviderCNGSoftware Provider = "cng-software"
	// ProviderCNGPlatform is a CNG machine key in the Microsoft Platform
	// Crypto Provider, the TPM (Windows, where T-2 shows it works).
	ProviderCNGPlatform Provider = "cng-platform"
	// ProviderLabFiles is a PKCS #8 file (LabFiles): lab and tests only.
	ProviderLabFiles Provider = "lab-files"
)

var providers = []Provider{ProviderCNGSoftware, ProviderCNGPlatform, ProviderLabFiles}

// Keys creates, opens and deletes a provider's keys by name. Every key is
// ECDSA P-256 and cannot be exported: Open returns a crypto.Signer.
type Keys interface {
	Provider() Provider
	// Create makes a new key. It refuses a name that already exists.
	Create(name string) (crypto.Signer, error)
	// Open returns the key with this name, or an error wrapping
	// ErrNoKey.
	Open(name string) (crypto.Signer, error)
	// Delete removes the key. A missing key is not an error.
	Delete(name string) error
}

// ErrNoKey is wrapped when a provider holds no key of the name asked for.
var ErrNoKey = errors.New("nodekey: no such key")

// ErrKeyMismatch is wrapped by OpenPinned when the provider holds another
// key under the name: one whose public key is not the one asked for.
var ErrKeyMismatch = errors.New("nodekey: the provider holds another key under the name")

// OpenPinned opens the key with this name in keys and returns its signer
// only when the key's public half, as PKIX DER, is spki. Otherwise it frees
// the provider handle of the signer keys.Open returned, before it returns,
// and the error wraps ErrKeyMismatch; so no caller ever holds a handle it
// refused (D4-106 item 3). An error of Open, ErrNoKey among them, is
// returned as it is.
//
// It frees only the signer its keys.Open returned, so a Keys must return a
// signer nobody else holds, as CNG and LabFiles do (a new handle, or a new
// key, at each call). A Keys that handed back a signer in use would have it
// freed here, and that signer's Sign would then fail, which fails closed.
func OpenPinned(keys Keys, name string, spki []byte) (crypto.Signer, error) {
	signer, err := keys.Open(name)
	if err != nil {
		return nil, err
	}
	if got, err := x509.MarshalPKIXPublicKey(signer.Public()); err != nil || !bytes.Equal(got, spki) {
		release(signer)
		return nil, fmt.Errorf("%w: %s", ErrKeyMismatch, name)
	}
	return signer, nil
}

var keyNamePattern = regexp.MustCompile(`^otsec-nodekey_[a-z0-9]{8,40}-v[1-9][0-9]{0,8}$`)

// KeyName is the provider's name for ref's key at version: the register
// cannot choose it, so no entry can point at another entry's key.
func KeyName(ref string, version uint32) string {
	return fmt.Sprintf("otsec-%s-v%d", ref, version)
}

// LabFiles keeps keys as PKCS #8 files, mode 0600, in Dir. It is for Linux
// tests and the lab only: a file key is as exposed as any file the node can
// read, which is exactly what section 9 replaces. A5 constructs it only
// behind the lab flag.
type LabFiles struct{ Dir string }

func (LabFiles) Provider() Provider { return ProviderLabFiles }

func (l LabFiles) path(name string) (string, error) {
	if !keyNamePattern.MatchString(name) {
		return "", fmt.Errorf("nodekey: key name %q", name)
	}
	return filepath.Join(l.Dir, name+".p8"), nil
}

func (l LabFiles) Create(name string) (crypto.Signer, error) {
	p, err := l.path(name)
	if err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("nodekey: create %s: %w", name, err)
	}
	_, err = f.Write(der)
	clear(der)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p)
		return nil, fmt.Errorf("nodekey: create %s: %w", name, err)
	}
	return k, nil
}

func (l LabFiles) Open(name string) (crypto.Signer, error) {
	p, err := l.path(name)
	if err != nil {
		return nil, err
	}
	der, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoKey, name)
	}
	if err != nil {
		return nil, fmt.Errorf("nodekey: open %s: %w", name, err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	clear(der)
	if err != nil {
		// The parser's message is not passed on: it can describe the key.
		return nil, fmt.Errorf("nodekey: %s is not a PKCS #8 key", name)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("nodekey: %s is not an ECDSA P-256 key", name)
	}
	return ec, nil
}

func (l LabFiles) Delete(name string) error {
	p, err := l.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nodekey: delete %s: %w", name, err)
	}
	return nil
}
