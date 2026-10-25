package forward

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/syslog"
)

// ClientTLS builds the TLS configuration for a relp-tls target (TB5, SC-16,
// D2-9). The node calls it when it loads the target, with the CA set that
// trust_anchor_ref names and the client certificate that
// client_credential_ref names.
//
//   - TLS 1.2 or later. The collector's chain is verified against roots
//     only, never the system roots, and its certificate must name
//     tls.server_name. When the target has SPKI pins, the collector's key
//     must match one. Nothing is skipped and nothing falls back.
//   - The client certificate is given exactly when the target names one.
//     It is always sent when the collector asks, whatever CA list the
//     collector offers.
//   - For a required target, the client certificate must carry
//     durable_ack.permitted_peer as one of the names a collector's name
//     check may match: a DNS name or the common name. A6 found that librelp
//     1.11.0 name mode matches the CN even when the certificate has SANs
//     for other names (#76). A durable_ack copied from another node's
//     target fails here (A3 #81 S-2).
//   - The client certificate must be for client authentication (an
//     extended key usage that names it, or none) and valid now. The
//     collector refuses it otherwise; this gives the reason at load.
func ClientTLS(t *syslog.Target, roots *x509.CertPool, client *tls.Certificate) (*tls.Config, error) {
	if t == nil {
		return nil, fmt.Errorf("%w: no target", ErrConfig)
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if t.Transport != syslog.TransportRELPTLS || t.TLS == nil {
		return nil, fmt.Errorf("%w: target %s is not relp-tls", ErrConfig, t.Name)
	}
	if roots == nil {
		return nil, fmt.Errorf("%w: target %s: no trust anchors; the system roots are never used", ErrConfig, t.Name)
	}
	if (client != nil) != (t.TLS.ClientCredentialRef != "") {
		return nil, fmt.Errorf("%w: target %s: a client certificate is given exactly when client_credential_ref is set", ErrConfig, t.Name)
	}
	if client != nil {
		leaf, err := leafOf(client)
		if err != nil {
			return nil, fmt.Errorf("%w: target %s: client certificate: %v", ErrConfig, t.Name, err)
		}
		// The collector refuses these at the handshake too; checking at
		// load gives the admin the reason instead of a TLS alert (A3 #89).
		// An EKU extension with only OIDs Go does not know leaves
		// ExtKeyUsage empty; it still restricts the key (A3 #94).
		hasEKU := len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0
		if hasEKU && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
			return nil, fmt.Errorf("%w: target %s: the node's client certificate is not for client authentication", ErrConfig, t.Name)
		}
		if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return nil, fmt.Errorf("%w: target %s: the node's client certificate is valid from %s to %s", ErrConfig, t.Name, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		if d := t.DurableAck; d != nil && !slices.Contains(certNames(leaf), d.PermittedPeer) {
			return nil, fmt.Errorf("%w: target %s: the collector permits %q, and the node's client certificate names %q", ErrConfig, t.Name, d.PermittedPeer, certNames(leaf))
		}
	}
	pins := map[string]bool{}
	for _, p := range t.TLS.SPKIPins {
		pins[p] = true
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: t.TLS.ServerName,
		// Runs after the chain and name have been verified.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(pins) == 0 {
				return nil
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("forward: collector sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !pins[base64.StdEncoding.EncodeToString(sum[:])] {
				return errors.New("forward: collector key matches no SPKI pin")
			}
			return nil
		},
	}
	if client != nil {
		c := *client
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
	}
	return cfg, nil
}

func leafOf(c *tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	if len(c.Certificate) == 0 {
		return nil, errors.New("empty chain")
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// certNames returns every name a collector's name check may match in a
// certificate: its DNS names and its common name.
func certNames(c *x509.Certificate) []string {
	names := slices.Clone(c.DNSNames)
	if c.Subject.CommonName != "" && !slices.Contains(names, c.Subject.CommonName) {
		names = append(names, c.Subject.CommonName)
	}
	return names
}

// DialTLS returns a Config.Dial for a relp-tls target with a configuration
// from ClientTLS. The handshake, including every verification step, ends
// within timeout.
func DialTLS(t *syslog.Target, cfg *tls.Config, timeout time.Duration) func(ctx context.Context) (net.Conn, error) {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	return func(ctx context.Context) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return d.DialContext(ctx, "tcp", addr)
	}
}

// DialTCP returns a Config.Dial for a plain relp target, which Validate
// allows only best-effort, insecure and lab-only.
func DialTCP(t *syslog.Target, timeout time.Duration) (func(ctx context.Context) (net.Conn, error), error) {
	if t.Transport != syslog.TransportRELP {
		return nil, fmt.Errorf("%w: target %s is %s; plain TCP is for relp only", ErrConfig, t.Name, t.Transport)
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }, nil
}
