package nodeconfigtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"otsec.local/otsec/platform/store"
)

// PKI is a throwaway test CA with a collector certificate and the node's
// client certificate. Nothing in it is used outside tests.
type PKI struct {
	Roots  *x509.CertPool
	Server tls.Certificate
	Client tls.Certificate
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// Period is a test certificate's validity. A zero field takes the default:
// valid from an hour ago, for a day.
type Period struct{ NotBefore, NotAfter time.Time }

func (p Period) fill() (nb, na time.Time) {
	nb, na = p.NotBefore, p.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(24 * time.Hour)
	}
	return nb, na
}

// Validity sets the periods of the certificates WritePKIValid makes.
type Validity struct{ CA, Server, Client Period }

// WritePKI makes a test CA, a collector certificate for serverName (an IP
// literal or a DNS name) and a client certificate whose CN and DNS name are
// the node ID, and writes the files the node's TLS references name into
// c.TLSDir (created owner-only with store.CreateDir):
//
//	<trustAnchor>.pem, <clientCredential>.crt, <clientCredential>.key
func (c *Config) WritePKI(serverName, trustAnchor, clientCredential string) (*PKI, error) {
	return c.WritePKIValid(serverName, trustAnchor, clientCredential, Validity{})
}

// WritePKIValid is WritePKI with the validity periods of v, for tests of
// certificates that are expired, not yet valid or about to end.
func (c *Config) WritePKIValid(serverName, trustAnchor, clientCredential string, v Validity) (*PKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caNB, caNA := v.CA.fill()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "otsec-test-ca"},
		NotBefore: caNB, NotAfter: caNA,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(der)
	p := &PKI{Roots: x509.NewCertPool(), ca: ca, caKey: caKey}
	p.Roots.AddCert(ca)
	if p.Server, err = p.IssueValid(serverName, x509.ExtKeyUsageServerAuth, v.Server); err != nil {
		return nil, err
	}
	if p.Client, err = p.IssueValid(c.NodeID, x509.ExtKeyUsageClientAuth, v.Client); err != nil {
		return nil, err
	}
	if err := store.CreateDir(c.TLSDir, ""); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.Client.PrivateKey)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		trustAnchor + ".pem":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}),
		clientCredential + ".crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Client.Certificate[0]}),
		clientCredential + ".key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(c.TLSDir, name), b, 0o600); err != nil {
			return nil, err
		}
	}
	return p, nil
}

var serial = big.NewInt(100)

// Issue signs a certificate named name (CN, and a SAN: an IP address for an
// IP literal, a DNS name otherwise) for usage.
func (p *PKI) Issue(name string, usage x509.ExtKeyUsage) (tls.Certificate, error) {
	return p.IssueValid(name, usage, Period{})
}

// IssueValid is Issue with the validity period per.
func (p *PKI) IssueValid(name string, usage x509.ExtKeyUsage, per Period) (tls.Certificate, error) {
	nb, na := per.fill()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial.Add(serial, big.NewInt(1))
	tmpl := &x509.Certificate{SerialNumber: new(big.Int).Set(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

// WriteListenerCredential issues a server certificate for host and writes
// it and its key into c.TLSDir as <ref>.crt and <ref>.key, the files a TLS
// listener's credential_ref names.
func (c *Config) WriteListenerCredential(p *PKI, ref, host string) (tls.Certificate, error) {
	return c.WriteListenerCredentialValid(p, ref, host, Period{})
}

// WriteListenerCredentialValid is WriteListenerCredential with the validity
// period per.
func (c *Config) WriteListenerCredentialValid(p *PKI, ref, host string, per Period) (tls.Certificate, error) {
	return c.WriteListenerCredentialUsage(p, ref, host, x509.ExtKeyUsageServerAuth, per)
}

// WriteListenerCredentialUsage is WriteListenerCredentialValid for a
// certificate whose extended key usage is usage, so a test can make one that
// is not for server authentication.
func (c *Config) WriteListenerCredentialUsage(p *PKI, ref, host string, usage x509.ExtKeyUsage, per Period) (tls.Certificate, error) {
	cert, err := p.IssueValid(host, usage, per)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	for name, b := range map[string][]byte{
		ref + ".crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		ref + ".key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(filepath.Join(c.TLSDir, name), b, 0o600); err != nil {
			return tls.Certificate{}, err
		}
	}
	return cert, nil
}

// WriteClientCredential issues another client certificate for the node,
// with the validity period per, and writes it into c.TLSDir as <ref>.crt
// and <ref>.key, for a second target.
func (c *Config) WriteClientCredential(p *PKI, ref string, per Period) (tls.Certificate, error) {
	cert, err := p.IssueValid(c.NodeID, x509.ExtKeyUsageClientAuth, per)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	for name, b := range map[string][]byte{
		ref + ".crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		ref + ".key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(filepath.Join(c.TLSDir, name), b, 0o600); err != nil {
			return tls.Certificate{}, err
		}
	}
	return cert, nil
}

// ServerTLS is the collector's TLS configuration as D2-9 commissions it:
// the node's chain to the test CA, and its name on a one-name
// permitted-peer list.
func (p *PKI) ServerTLS(permitted string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{p.Server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.Roots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			leaf := cs.PeerCertificates[0]
			if leaf.Subject.CommonName == permitted || slices.Contains(leaf.DNSNames, permitted) {
				return nil
			}
			return errors.New("nodeconfigtest: peer not permitted")
		},
	}
}

// ErrNeedsElevation is LockTLS's error on Windows when the process may not
// make Administrators the owner; a test skips on it.
var ErrNeedsElevation = errors.New("nodeconfigtest: making Administrators the owner needs an elevated process")
