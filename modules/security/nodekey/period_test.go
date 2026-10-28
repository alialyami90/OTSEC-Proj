package nodekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// A certificate outside its validity period is a fault of its own (HR-13,
// D4-11): Certificate and TrustAnchors wrap ErrCertificatePeriod only when
// nothing else is wrong, and LoadCertificate and LoadTrustAnchors leave the
// period to the caller.

func TestPeriodIsTheSoleFault(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	expired := now.Add(91 * 24 * time.Hour)      // the leaf ends after 90 days
	notYet := now.Add(-2 * time.Hour)            // the leaf starts an hour before now
	anchorsGone := now.Add(400 * 24 * time.Hour) // the CA ends after 365 days

	r, keys := installed(t, ca)
	for name, at := range map[string]time.Time{"expired": expired, "not yet valid": notYet} {
		if cert, _, err := r.Certificate(clientRef, keys, at); !errors.Is(err, ErrCertificatePeriod) || cert != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if pool, _, err := r.TrustAnchors(anchorsRef, anchorsGone); !errors.Is(err, ErrCertificatePeriod) || pool != nil {
		t.Errorf("expired anchors: %v", err)
	}
	if _, _, err := r.Certificate(clientRef, keys, now); err != nil {
		t.Errorf("a valid certificate: %v", err)
	}

	// An expired certificate with another fault is refused for that fault,
	// so a caller that holds a link back on ErrCertificatePeriod still stops
	// for it.
	for name, spoil := range map[string]func(keys LabFiles) (Keys, error){
		"another provider": func(keys LabFiles) (Keys, error) { return otherProvider{keys}, nil },
		"no provider":      func(LabFiles) (Keys, error) { return nil, nil },
		"key deleted":      func(keys LabFiles) (Keys, error) { return keys, keys.Delete(KeyName(clientRef, 1)) },
		"key replaced": func(keys LabFiles) (Keys, error) {
			if err := keys.Delete(KeyName(clientRef, 1)); err != nil {
				return nil, err
			}
			_, err := keys.Create(KeyName(clientRef, 1))
			return keys, err
		},
	} {
		r, keys := installed(t, ca)
		k, err := spoil(keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Certificate(clientRef, k, expired); err == nil || errors.Is(err, ErrCertificatePeriod) {
			t.Errorf("expired, with %s: %v", name, err)
		}
	}
}

func TestLoadersLeaveThePeriodToTheCaller(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	r, keys := installed(t, ca)

	cert, e, err := r.LoadCertificate(clientRef, keys)
	if err != nil || cert == nil || cert.Leaf == nil || e.Version != 1 {
		t.Fatalf("LoadCertificate: %v", err)
	}
	// The leaf is the caller's to judge: it is outside its period at these
	// times, and the loader returned it all the same.
	if !now.Add(91 * 24 * time.Hour).After(cert.Leaf.NotAfter) {
		t.Fatal("the test certificate does not end within 91 days")
	}
	pool, e, err := r.LoadTrustAnchors(anchorsRef)
	if err != nil || pool == nil || e.Version != 1 {
		t.Fatalf("LoadTrustAnchors: %v", err)
	}

	// Loading does not weaken the other checks.
	if _, _, err := r.LoadCertificate(clientRef, nil); err == nil {
		t.Error("LoadCertificate with no provider")
	}
	if _, _, err := r.LoadCertificate(clientRef, otherProvider{keys}); err == nil {
		t.Error("LoadCertificate with another provider")
	}
	if err := keys.Delete(KeyName(clientRef, 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.LoadCertificate(clientRef, keys); err == nil {
		t.Error("LoadCertificate with the key deleted")
	}
	if _, _, err := r.LoadCertificate(anchorsRef, keys); err == nil {
		t.Error("trust anchors loaded as a key")
	}
	if _, _, err := r.LoadTrustAnchors(clientRef); err == nil {
		t.Error("a key loaded as trust anchors")
	}
	if _, _, err := r.LoadTrustAnchors("nodekey_notthere1"); err == nil {
		t.Error("a missing reference loaded")
	}
}

// An expired anchor stays in the pool: a verification that chains to it
// fails on the expiry, so the set of trusted peers is the one the register
// holds and the link refuses the peer (D4-11 item 5). The leaf is valid at
// the time checked, so the anchor is the only thing that fails.
func TestLoadedExpiredAnchorRefusesItsPeer(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "short test ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	short, _ := x509.ParseCertificate(der)
	sca := &testCA{cert: short, key: k}

	keys := LabFiles{Dir: t.TempDir()}
	r := NewRegister(testNode)
	csr, err := r.Request(keys, clientRef, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(clientRef, [][]byte{sca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(30*24*time.Hour))}, admin, now); err != nil {
		t.Fatal(err)
	}
	if err := r.SetAnchors(anchorsRef, [][]byte{short.Raw}, admin, now); err != nil {
		t.Fatal(err)
	}
	cert, _, err := r.LoadCertificate(clientRef, keys)
	if err != nil {
		t.Fatal(err)
	}
	pool, _, err := r.LoadTrustAnchors(anchorsRef)
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for name, at := range map[string]time.Time{"now": now, "leaf valid, anchor expired": now.Add(20 * 24 * time.Hour)} {
		opts.CurrentTime = at
		_, err := cert.Leaf.Verify(opts)
		if (name == "now") != (err == nil) {
			t.Errorf("%s: verification %v", name, err)
		}
	}
	if _, _, err := r.TrustAnchors(anchorsRef, now.Add(20*24*time.Hour)); !errors.Is(err, ErrCertificatePeriod) {
		t.Errorf("the strict loader on the expired anchor: %v", err)
	}
}
