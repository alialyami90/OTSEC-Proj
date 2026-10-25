package node

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"

	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/platform/store/protect"
)

// MaxTLSFileBytes bounds each file a TLS reference names.
const MaxTLSFileBytes = 1 << 20

// TLS reference files in tls_dir (D2-12: a Phase 2 interim, lab only; A3's
// node key register, credential design section 9, replaces it):
//
//	<trust_anchor_ref>.pem        the CA set that verifies the collector
//	<client_credential_ref>.crt   the node's client certificate chain
//	<client_credential_ref>.key   its private key, unencrypted at rest
const (
	TrustAnchorSuffix = ".pem"
	ClientCertSuffix  = ".crt"
	ClientKeySuffix   = ".key"
)

// TargetTLS resolves target t's TLS references in tls_dir and returns the
// forwarder's TLS configuration from forward.ClientTLS, which refuses a
// required target whose permitted_peer is not the client certificate's
// name (D2-12):
//
//   - tls_dir must pass protect.CheckDir: the store directory rule,
//     junctions and links refused, and no write for the node;
//   - every file is read with protect.ReadFile: checked on the
//     opened handle, a regular file on disk, at most MaxTLSFileBytes,
//     owner and ACE rule, no write for the node;
//   - no error quotes file content, so a parse failure says only which
//     file failed.
//
// Nothing is cached and nothing falls back: the node calls it at start, and
// a missing or bad file stops it.
func (c *Config) TargetTLS(t *syslog.Target) (*tls.Config, error) {
	if t.TLS == nil {
		return nil, fmt.Errorf("target %s: no tls section", t.Name)
	}
	if c.TLSDir == "" {
		return nil, fmt.Errorf("target %s: tls_dir is not set", t.Name)
	}
	if err := protect.CheckDir(c.TLSDir); err != nil {
		return nil, fmt.Errorf("target %s: tls_dir: %w", t.Name, err)
	}
	anchors := t.TLS.TrustAnchorRef + TrustAnchorSuffix
	b, err := c.readTLSFile(anchors)
	if err != nil {
		return nil, fmt.Errorf("target %s: trust anchors: %w", t.Name, err)
	}
	roots := x509.NewCertPool()
	n := 0
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("target %s: %s holds a block that is not a certificate", t.Name, anchors)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("target %s: %s holds a certificate that does not parse", t.Name, anchors)
		}
		roots.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("target %s: %s holds no certificate", t.Name, anchors)
	}
	var client *tls.Certificate
	if ref := t.TLS.ClientCredentialRef; ref != "" {
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
			// The parser's message is not passed on: it can describe the
			// key's bytes.
			return nil, fmt.Errorf("target %s: %s and %s do not form a certificate and its key", t.Name, ref+ClientCertSuffix, ref+ClientKeySuffix)
		}
		client = &pair
	}
	return forward.ClientTLS(t, roots, client)
}

func (c *Config) readTLSFile(name string) ([]byte, error) {
	if c.TLSDir == "" {
		return nil, errors.New("tls_dir is not set")
	}
	return protect.ReadFile(filepath.Join(c.TLSDir, name), MaxTLSFileBytes)
}
