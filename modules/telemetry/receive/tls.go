package receive

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ServerTLS builds the TLS configuration of a syslog-tls listener (RFC
// 5425). The node calls it when it loads the listener, with the listener's
// certificate and, for mutual authentication, the CA set that verifies
// senders.
//
//   - TLS 1.2 or later.
//   - The listener's certificate must be for server authentication (an
//     extended key usage that names it, or none) and valid now, so a sender
//     that checks it does not refuse it for a reason the node could have
//     given at load.
//   - With clients nil, no client certificate is asked for, and every
//     event says tls-server-only. With clients set, a sender that presents
//     a certificate must chain to clients, never to the system roots, and
//     is refused at the handshake otherwise; requireClient refuses a sender
//     that presents none. A sender that proved its certificate gets
//     tls-mutual, and its events carry the certificate's SHA-256 (C4 0.2).
//     The certificate is not tied to an asset (C1 pinned-key is not
//     built), so the event's asset is still bound by sender address.
func ServerTLS(cert *tls.Certificate, clients *x509.CertPool, requireClient bool) (*tls.Config, error) {
	if cert == nil {
		return nil, fmt.Errorf("%w: no listener certificate", ErrConfig)
	}
	leaf, err := leafOf(cert)
	if err != nil {
		return nil, fmt.Errorf("%w: listener certificate: %v", ErrConfig, err)
	}
	hasEKU := len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0
	if hasEKU && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, fmt.Errorf("%w: the listener certificate is not for server authentication", ErrConfig)
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("%w: the listener certificate is valid from %s to %s", ErrConfig, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if requireClient && clients == nil {
		return nil, fmt.Errorf("%w: client certificates required, but no CA set verifies them", ErrConfig)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.NoClientCert,
	}
	if clients != nil {
		cfg.ClientCAs = clients
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		if requireClient {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
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
