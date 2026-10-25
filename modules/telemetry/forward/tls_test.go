package forward

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
)

func TestClientTLSRefuses(t *testing.T) {
	p := newPKI(t)
	tg := newTarget(t, 2514, nil)
	other := p.issue(t, "site-b-node1", nil, x509.ExtKeyUsageClientAuth)
	sanOther := p.issue(t, "site-b-node1", []string{"site-b-node1"}, x509.ExtKeyUsageClientAuth)
	for name, c := range map[string]struct {
		tg     *syslog.Target
		roots  *x509.CertPool
		client *tls.Certificate
	}{
		"no trust anchors":      {tg, nil, &p.client},
		"no client certificate": {tg, p.roots, nil},
		"another node's cert":   {tg, p.roots, &other},
		"another node's SAN":    {tg, p.roots, &sanOther},
		"empty client chain":    {tg, p.roots, &tls.Certificate{}},
		"not relp-tls":          {newTarget(t, 2514, plainRELP), p.roots, nil},
		"cert without a ref": {newTarget(t, 2514, func(x *syslog.Target) {
			x.Class, x.DurableAck, x.ReplaySeconds, x.TLS.ClientCredentialRef = syslog.ClassBestEffort, nil, 3600, ""
		}), p.roots, &p.client},
	} {
		if _, err := ClientTLS(c.tg, c.roots, c.client); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The permitted peer may be the CN or a SAN: librelp matches either.
	both := p.issue(t, "site-a-node1", []string{"site-a-node1.example"}, x509.ExtKeyUsageClientAuth)
	if _, err := ClientTLS(tg, p.roots, &both); err != nil {
		t.Errorf("CN with another SAN: %v", err)
	}
	san := p.issue(t, "other-cn", []string{"site-a-node1"}, x509.ExtKeyUsageClientAuth)
	if _, err := ClientTLS(tg, p.roots, &san); err != nil {
		t.Errorf("SAN: %v", err)
	}
}

func plainRELP(x *syslog.Target) {
	x.Transport, x.Class, x.TLS, x.DurableAck, x.ReplaySeconds = syslog.TransportRELP, syslog.ClassBestEffort, nil, nil, 3600
	f := false
	x.DeviceContent = &f
	x.Acknowledgement = &syslog.Acknowledgement{By: "a4-test-admin", At: "2026-10-24T09:00:00Z", Reason: "unit test", Scope: syslog.LabOnly}
}

// dial runs one handshake against a relptest server with server TLS cfg.
func dial(t *testing.T, srvCfg *tls.Config, tg func(*syslog.Target), p *pki, client *tls.Certificate) error {
	t.Helper()
	srv, err := relptest.Start(srvCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	target := newTarget(t, srv.Addr().Port, tg)
	cfg, err := ClientTLS(target, p.roots, client)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialTLS(target, cfg, 2*time.Second)(t.Context())
	if err != nil {
		return err
	}
	defer c.Close()
	// TLS 1.3 reports a refused client certificate on the first read.
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("1 open 30 relp_version=0\ncommands=syslog\n")); err != nil {
		return err
	}
	_, err = c.Read(make([]byte, 64))
	return err
}

// The forwarder checks the collector's chain, name and key (D2-9), and the
// collector checks the node's.
func TestTLSPeerChecks(t *testing.T) {
	p := newPKI(t)
	if err := dial(t, p.serverTLS(string(node)), nil, p, &p.client); err != nil {
		t.Fatalf("good handshake: %v", err)
	}
	stranger := newPKI(t) // another CA
	wrongName := p.serverTLS(string(node))
	wrongName.Certificates = []tls.Certificate{p.issue(t, "elsewhere.test", []string{"elsewhere.test"}, x509.ExtKeyUsageServerAuth)}
	untrusted := p.serverTLS(string(node))
	untrusted.Certificates = []tls.Certificate{stranger.server}
	clientOnly := p.serverTLS(string(node))
	clientOnly.Certificates = []tls.Certificate{p.issue(t, "collector.test", []string{"collector.test"}, x509.ExtKeyUsageClientAuth)}
	oldTLS := p.serverTLS(string(node))
	oldTLS.MinVersion, oldTLS.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	for name, c := range map[string]struct {
		srv *tls.Config
		tg  func(*syslog.Target)
	}{
		"collector name is not server_name": {wrongName, nil},
		"collector chain from another CA":   {untrusted, nil},
		"collector cert not for servers":    {clientOnly, nil},
		"TLS below 1.2":                     {oldTLS, nil},
		"collector key matches no pin":      {p.serverTLS(string(node)), func(x *syslog.Target) { x.TLS.SPKIPins = []string{pin(stranger.server)} }},
		"collector permits another node":    {p.serverTLS("site-b-node1"), nil},
	} {
		err := dial(t, c.srv, c.tg, p, &p.client)
		if err == nil {
			t.Errorf("%s: handshake succeeded", name)
		}
		t.Logf("%s: %v", name, err)
	}
	if err := dial(t, p.serverTLS(string(node)), func(x *syslog.Target) { x.TLS.SPKIPins = []string{pin(p.server)} }, p, &p.client); err != nil {
		t.Errorf("matching pin: %v", err)
	}
}

func pin(c tls.Certificate) string {
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestDialTCPOnlyForPlainRELP(t *testing.T) {
	if _, err := DialTCP(newTarget(t, 2514, nil), time.Second); !errors.Is(err, ErrConfig) {
		t.Errorf("relp-tls target: %v", err)
	}
	if _, err := DialTCP(newTarget(t, 2514, plainRELP), time.Second); err != nil {
		t.Errorf("plain relp: %v", err)
	}
}
