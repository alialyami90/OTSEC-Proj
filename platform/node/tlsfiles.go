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
	"otsec.local/otsec/modules/telemetry/receive"
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
//
// With key_register the references resolve from the node key register
// instead (keyTargetTLS), under the same rule: nothing falls back.
func (c *Config) TargetTLS(t *syslog.Target) (*tls.Config, error) {
	if t.TLS == nil {
		return nil, fmt.Errorf("target %s: no tls section", t.Name)
	}
	if c.KeyRegister != "" {
		return c.keyTargetTLS(t)
	}
	if c.TLSDir == "" {
		return nil, fmt.Errorf("target %s: tls_dir is not set", t.Name)
	}
	if err := protect.CheckDir(c.TLSDir); err != nil {
		return nil, fmt.Errorf("target %s: tls_dir: %w", t.Name, err)
	}
	roots, err := c.readCAs(t.TLS.TrustAnchorRef)
	if err != nil {
		return nil, fmt.Errorf("target %s: trust anchors: %w", t.Name, err)
	}
	var client *tls.Certificate
	if ref := t.TLS.ClientCredentialRef; ref != "" {
		pair, err := c.readKeyPair(ref)
		if err != nil {
			return nil, fmt.Errorf("target %s: client credential: %w", t.Name, err)
		}
		client = pair
	}
	return forward.ClientTLS(t, roots, client)
}

// ListenerTLS resolves a syslog-tls listener's references in tls_dir, under
// TargetTLS's rules, and returns receive.ServerTLS's configuration: the
// listener's certificate and key from <credential_ref>.crt and .key, and,
// with sender_ca_ref, the CA set a sender's certificate must chain to.
func (c *Config) ListenerTLS(l Listener) (*tls.Config, error) {
	if l.TLS == nil {
		return nil, fmt.Errorf("listener %s: no tls section", l.ID)
	}
	if c.KeyRegister != "" {
		return c.keyListenerTLS(l)
	}
	if c.TLSDir == "" {
		return nil, fmt.Errorf("listener %s: tls_dir is not set", l.ID)
	}
	if err := protect.CheckDir(c.TLSDir); err != nil {
		return nil, fmt.Errorf("listener %s: tls_dir: %w", l.ID, err)
	}
	cert, err := c.readKeyPair(l.TLS.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("listener %s: credential: %w", l.ID, err)
	}
	var senders *x509.CertPool
	if ref := l.TLS.SenderCARef; ref != "" {
		if senders, err = c.readCAs(ref); err != nil {
			return nil, fmt.Errorf("listener %s: sender CAs: %w", l.ID, err)
		}
	}
	cfg, err := receive.ServerTLS(cert, senders, l.TLS.RequireSenderCert)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	return cfg, nil
}

// readCAs reads <ref>.pem, which must hold certificates only, at least one.
func (c *Config) readCAs(ref string) (*x509.CertPool, error) {
	name := ref + TrustAnchorSuffix
	b, err := c.readTLSFile(name)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	n := 0
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s holds a block that is not a certificate", name)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s holds a certificate that does not parse", name)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%s holds no certificate", name)
	}
	return pool, nil
}

// readKeyPair reads <ref>.crt and <ref>.key. No error quotes either file.
func (c *Config) readKeyPair(ref string) (*tls.Certificate, error) {
	certPEM, err := c.readTLSFile(ref + ClientCertSuffix)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	keyPEM, err := c.readTLSFile(ref + ClientKeySuffix)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if err != nil {
		// The parser's message is not passed on: it can describe the key's
		// bytes.
		return nil, fmt.Errorf("%s and %s do not form a certificate and its key", ref+ClientCertSuffix, ref+ClientKeySuffix)
	}
	return &pair, nil
}

func (c *Config) readTLSFile(name string) ([]byte, error) {
	if c.TLSDir == "" {
		return nil, errors.New("tls_dir is not set")
	}
	return protect.ReadFile(filepath.Join(c.TLSDir, name), MaxTLSFileBytes)
}
