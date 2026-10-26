package syslogreceive

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
)

// C4 0.2 sender.tls_leaf_sha256 through the real listener and store (A4,
// #167). Ground truth is the client side: the SHA-256 of the DER leaf the
// test's sender presented, computed here, never read back from the
// listener. A sender without a verified certificate has no fingerprint.

func leafOf(c tls.Certificate) string {
	s := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(s[:])
}

// checkStoredValid decodes every stored event with the C4 reader, so a
// tls-mutual event without its fingerprint, or a fingerprint on another
// origin_auth, fails here as it would for any reader.
func checkStoredValid(t *testing.T, ev []stored) {
	t.Helper()
	for i, s := range ev {
		e, err := event.Decode(s.Raw)
		if err != nil {
			t.Errorf("stored event %d does not decode: %v", i, err)
			continue
		}
		if e.Schema != "otsec.event/0.2" {
			t.Errorf("stored event %d is %s", i, e.Schema)
		}
	}
}

func TestTLSLeafIsTheSendersCertificate(t *testing.T) {
	srvCA, cliCA := newCA(t, "a6 server ca"), newCA(t, "a6 sender ca")
	srv := srvCA.leaf(t, "a6 listener", x509.ExtKeyUsageServerAuth)
	x := cliCA.leaf(t, "a6 sender x", x509.ExtKeyUsageClientAuth)
	y := cliCA.leaf(t, "a6 sender y", x509.ExtKeyUsageClientAuth)
	// z sends its CA after its leaf: the fingerprint is still the leaf's.
	z := cliCA.leaf(t, "a6 sender z", x509.ExtKeyUsageClientAuth)
	z.Certificate = append(z.Certificate, cliCA.ca.Raw)
	if leafOf(x) == leafOf(y) {
		t.Fatal("two certificates with one fingerprint")
	}
	for _, require := range []bool{false, true} {
		t.Run(fmt.Sprintf("require=%v", require), func(t *testing.T) {
			cfg, err := receive.ServerTLS(&srv, cliCA.pool, require)
			if err != nil {
				t.Fatal(err)
			}
			g := start(t, asset.SyslogTLS, cfg, receive.Limits{})
			type send struct {
				name  string
				certs []tls.Certificate
				auth  string
				leaf  string
			}
			sends := []send{
				{"x", []tls.Certificate{x}, "tls-mutual", leafOf(x)},
				{"y", []tls.Certificate{y}, "tls-mutual", leafOf(y)},
				{"z with its CA", []tls.Certificate{z}, "tls-mutual", leafOf(z)},
				{"x again", []tls.Certificate{x}, "tls-mutual", leafOf(x)},
			}
			if !require {
				sends = append(sends, send{"anonymous", nil, "tls-server-only", ""})
			}
			for i, s := range sends {
				c, err := dialTLS(t, ipA, g.addr, clientTLS(srvCA.pool, s.certs...))
				if err != nil {
					t.Fatal(err)
				}
				fmt.Fprintf(c, "<13>%s\n", s.name)
				if ev := g.waitN(i+1, 5*time.Second); len(ev) != i+1 {
					t.Fatalf("%s: %d stored", s.name, len(ev))
				}
				c.Close()
			}
			ev := g.events()
			for i, s := range sends {
				checkBytes(t, i, ev[i], []byte("<13>"+s.name))
				if ev[i].OriginAuth != s.auth || ev[i].Leaf != s.leaf {
					t.Errorf("%s: origin_auth %s leaf %q, want %s %q", s.name, ev[i].OriginAuth, ev[i].Leaf, s.auth, s.leaf)
				}
			}
			checkStoredValid(t, ev)
		})
	}
}

func TestNoLeafWithoutTLS(t *testing.T) {
	for _, tr := range []asset.Transport{asset.SyslogTCP, asset.SyslogUDP} {
		t.Run(string(tr), func(t *testing.T) {
			g := start(t, tr, nil, receive.Limits{})
			network := "tcp"
			if tr == asset.SyslogUDP {
				network = "udp"
			}
			c := dialFrom(t, ipA, network, g.addr)
			fmt.Fprint(c, "<13>plain\n")
			ev := g.waitN(1, 5*time.Second)
			if len(ev) != 1 {
				t.Fatalf("%d stored", len(ev))
			}
			if ev[0].OriginAuth != "none" || ev[0].Leaf != "" {
				t.Errorf("origin_auth %s leaf %q", ev[0].OriginAuth, ev[0].Leaf)
			}
			checkStoredValid(t, ev)
		})
	}
}

// TestNormalizeTiesTheCertificateToTLSMutual: the builder refuses a
// certificate without tls-mutual and tls-mutual without a certificate, and
// hashes the bytes it was given, all of them.
func TestNormalizeTiesTheCertificateToTLSMutual(t *testing.T) {
	in := func(auth event.OriginAuth, cert []byte) normalize.SyslogInput {
		return normalize.SyslogInput{Node: node, Stream: event.Stream(sStream), Message: []byte("<13>m"), Sender: "127.0.0.1",
			Auth: auth, SenderCert: cert, EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC, Received: received()}
	}
	cert := []byte("not a certificate, but bytes with a trailing zero\x00")
	for _, c := range []struct {
		auth event.OriginAuth
		cert []byte
	}{{event.AuthTLSMutual, nil}, {event.AuthTLSMutual, []byte{}}, {event.AuthTLSServerOnly, cert}, {event.AuthNone, cert}} {
		if _, err := normalize.Syslog(in(c.auth, c.cert)); !errors.Is(err, normalize.ErrInput) {
			t.Errorf("%s with %d certificate bytes: %v", c.auth, len(c.cert), err)
		}
	}
	for _, auth := range []event.OriginAuth{event.AuthNone, event.AuthTLSServerOnly} {
		e, err := normalize.Syslog(in(auth, nil))
		if err != nil || e.Source.Sender.TLSLeafSHA256 != "" {
			t.Errorf("%s: %v leaf %q", auth, err, e.Source.Sender.TLSLeafSHA256)
		}
	}
	e, err := normalize.Syslog(in(event.AuthTLSMutual, cert))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(cert)
	if e.Source.Sender.TLSLeafSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("leaf %q, want the SHA-256 of all %d bytes", e.Source.Sender.TLSLeafSHA256, len(cert))
	}
	if err := e.ValidatePending(); err != nil {
		t.Error(err)
	}
}
