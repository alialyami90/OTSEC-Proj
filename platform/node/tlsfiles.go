package node

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/platform/store"
)

// MaxTLSFileBytes bounds each file a TLS reference names.
const MaxTLSFileBytes = 1 << 20

// TLS reference files in tls_dir (a Phase 2 interim, lab only; A3's node
// key register, credential design section 9, replaces it):
//
//	<trust_anchor_ref>.pem        the CA set that verifies the collector
//	<client_credential_ref>.crt   the node's client certificate chain
//	<client_credential_ref>.key   its private key
const (
	TrustAnchorSuffix = ".pem"
	ClientCertSuffix  = ".crt"
	ClientKeySuffix   = ".key"
)

// TargetTLS resolves target t's TLS references in tls_dir and returns the
// forwarder's TLS configuration from forward.ClientTLS, which refuses a
// required target whose permitted_peer is not the client certificate's
// name. The key file must pass store.CheckPrivateFile. Nothing is cached:
// the node calls it at start, so a changed or removed file takes effect at
// the next start and a bad one stops it.
func (c *Config) TargetTLS(t *syslog.Target) (*tls.Config, error) {
	if t.TLS == nil {
		return nil, fmt.Errorf("target %s: no tls section", t.Name)
	}
	if fi, err := os.Lstat(c.TLSDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("target %s: tls_dir %s is not a directory (a link is refused): %v", t.Name, c.TLSDir, err)
	}
	pemBytes, err := c.readTLSFile(t.TLS.TrustAnchorRef + TrustAnchorSuffix)
	if err != nil {
		return nil, fmt.Errorf("target %s: trust anchors: %w", t.Name, err)
	}
	roots := x509.NewCertPool()
	n := 0
	for rest := pemBytes; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("target %s: trust anchors hold a %s block; only certificates belong there", t.Name, b.Type)
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("target %s: trust anchors: %w", t.Name, err)
		}
		roots.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("target %s: trust anchor file %s holds no certificate", t.Name, t.TLS.TrustAnchorRef+TrustAnchorSuffix)
	}
	var client *tls.Certificate
	if ref := t.TLS.ClientCredentialRef; ref != "" {
		keyPath := filepath.Join(c.TLSDir, ref+ClientKeySuffix)
		if err := store.CheckPrivateFile(keyPath); err != nil {
			return nil, fmt.Errorf("target %s: client key: %w", t.Name, err)
		}
		certPEM, err := c.readTLSFile(ref + ClientCertSuffix)
		if err != nil {
			return nil, fmt.Errorf("target %s: client certificate: %w", t.Name, err)
		}
		keyPEM, err := c.readTLSFile(ref + ClientKeySuffix)
		if err != nil {
			return nil, fmt.Errorf("target %s: client key: %w", t.Name, err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		clear(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("target %s: client credential %s: %w", t.Name, ref, err)
		}
		client = &pair
	}
	return forward.ClientTLS(t, roots, client)
}

// readTLSFile reads name in tls_dir: a plain file, not a link or other
// reparse point (Lstat, D2-12), of at most MaxTLSFileBytes.
func (c *Config) readTLSFile(name string) ([]byte, error) {
	if c.TLSDir == "" {
		return nil, errors.New("tls_dir is not set")
	}
	path := filepath.Join(c.TLSDir, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a plain file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxTLSFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxTLSFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, MaxTLSFileBytes)
	}
	return b, nil
}
