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

// WritePKI makes a test CA, a collector certificate for serverName (an IP
// literal or a DNS name) and a client certificate whose CN and DNS name are
// the node ID, and writes the files the node's TLS references name into
// c.TLSDir (created owner-only with store.CreateDir):
//
//	<trustAnchor>.pem, <clientCredential>.crt, <clientCredential>.key
func (c *Config) WritePKI(serverName, trustAnchor, clientCredential string) (*PKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "otsec-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(der)
	p := &PKI{Roots: x509.NewCertPool(), ca: ca, caKey: caKey}
	p.Roots.AddCert(ca)
	if p.Server, err = p.Issue(serverName, x509.ExtKeyUsageServerAuth); err != nil {
		return nil, err
	}
	if p.Client, err = p.Issue(c.NodeID, x509.ExtKeyUsageClientAuth); err != nil {
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
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial.Add(serial, big.NewInt(1))
	tmpl := &x509.Certificate{SerialNumber: new(big.Int).Set(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
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
