package security

// HR-13 (D4-11 item 2, #274): ServerTLS and ClientTLS wrap
// ErrCertificatePeriod only when the certificate's validity period is its
// only fault, so a node that holds one link back for an expired or
// not-yet-valid certificate still stops at start for every other refusal.
// B6's own cases: each other refusal combined with each period fault, and
// the period fault alone. Test certificates made here; evidence class:
// desk.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/modules/telemetry/receive"
)

type b6CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newB6CA(t *testing.T) *b6CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "b6-test-ca"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &b6CA{c, key, pool}
}

// issue makes a leaf named cn, valid over [from, until], with the given
// extended key usages and unknown EKU OIDs.
func (ca *b6CA) issue(t *testing.T, cn string, usage []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier, from, until time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: from, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usage, UnknownExtKeyUsage: unknown}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// periods are the two period faults, and the valid control.
func b6Periods() map[string][2]time.Time {
	now := time.Now()
	return map[string][2]time.Time{
		"expired":       {now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		"not yet valid": {now.Add(time.Hour), now.Add(2 * time.Hour)},
		"valid":         {now.Add(-time.Hour), now.Add(time.Hour)},
	}
}

var b6UnknownEKU = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 7}}

func TestB6ServerTLSPeriodIsTheOnlyFault(t *testing.T) {
	ca := newB6CA(t)
	server := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for pname, p := range b6Periods() {
		period := pname != "valid"
		for _, c := range []struct {
			name          string
			usage         []x509.ExtKeyUsage
			unknown       []asn1.ObjectIdentifier
			clients       *x509.CertPool
			requireClient bool
			otherFault    bool
		}{
			{"serverAuth", server, nil, ca.pool, true, false},
			{"no EKU", nil, nil, nil, false, false},
			{"clientAuth only", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil, false, true},
			{"unknown EKU only", nil, b6UnknownEKU, nil, false, true},
			{"client certificates required, no CA set", server, nil, nil, true, true},
		} {
			cert := ca.issue(t, "listener.test", c.usage, c.unknown, p[0], p[1])
			_, err := receive.ServerTLS(&cert, c.clients, c.requireClient)
			wantErr, wantPeriod := period || c.otherFault, period && !c.otherFault
			if (err != nil) != wantErr || (err != nil && !errors.Is(err, receive.ErrConfig)) || errors.Is(err, receive.ErrCertificatePeriod) != wantPeriod {
				t.Errorf("%s, %s: %v; want refused %v, ErrCertificatePeriod %v", pname, c.name, err, wantErr, wantPeriod)
			}
		}
	}
}

func TestB6ClientTLSPeriodIsTheOnlyFault(t *testing.T) {
	ca := newB6CA(t)
	tg, err := syslog.ParseTarget([]byte(`{"schema": "otsec.syslog/0.2", "name": "b6-siem", "host": "127.0.0.1", "port": 2514,
  "transport": "relp-tls", "format": "rfc5424", "framing": "relp", "class": "required", "max_message_octets": 2048, "facility": 16,
  "tls": {"server_name": "collector.test", "trust_anchor_ref": "b6-test-ca", "client_credential_ref": "b6-test-node"},
  "relp_window": 8,
  "durable_ack": {"verified_utc": "2026-10-24T09:00:00Z", "evidence_ref": "b6-test/durable-ack", "peer_check": "name",
    "permitted_peer": "site-a-node1", "ack_after": "durable-write"}}`))
	if err != nil {
		t.Fatal(err)
	}
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	for pname, p := range b6Periods() {
		period := pname != "valid"
		for _, c := range []struct {
			name, cn   string
			usage      []x509.ExtKeyUsage
			unknown    []asn1.ObjectIdentifier
			otherFault bool
		}{
			{"clientAuth", "site-a-node1", client, nil, false},
			{"no EKU", "site-a-node1", nil, nil, false},
			{"serverAuth only", "site-a-node1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, true},
			{"unknown EKU only", "site-a-node1", nil, b6UnknownEKU, true},
			{"not the permitted peer", "site-b-node1", client, nil, true},
			{"serverAuth only and not the permitted peer", "site-b-node1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, true},
		} {
			cert := ca.issue(t, c.cn, c.usage, c.unknown, p[0], p[1])
			_, err := forward.ClientTLS(tg, ca.pool, &cert)
			wantErr, wantPeriod := period || c.otherFault, period && !c.otherFault
			if (err != nil) != wantErr || (err != nil && !errors.Is(err, forward.ErrConfig)) || errors.Is(err, forward.ErrCertificatePeriod) != wantPeriod {
				t.Errorf("%s, %s: %v; want refused %v, ErrCertificatePeriod %v", pname, c.name, err, wantErr, wantPeriod)
			}
		}
	}
	// The two sentinels are the packages' own: neither matches the other.
	if errors.Is(forward.ErrCertificatePeriod, receive.ErrCertificatePeriod) || errors.Is(forward.ErrCertificatePeriod, forward.ErrConfig) {
		t.Error("forward.ErrCertificatePeriod is another sentinel")
	}
}
