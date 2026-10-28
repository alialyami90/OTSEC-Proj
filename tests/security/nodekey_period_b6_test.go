package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/nodekey"
)

// B6, independent of B3's period_test.go (#298, HR-13, D4-11). Under
// key_register the node holds back one link when a certificate is outside
// its period, so the register's refusal may wrap ErrCertificatePeriod only
// when the period is the sole fault. Each period (expired, not yet valid,
// valid, and the two edges) is crossed with each other fault, and every
// cell is checked: no error only for a valid certificate with no fault, the
// sentinel only for a period fault alone, and the loaders refuse exactly
// what the strict resolvers refuse apart from the period. Every key and
// certificate is made here (D2-5). Evidence class: simulated.

const (
	b6Node    = "site-b6-node1"
	b6Admin   = "admin@site-b6"
	b6Client  = "nodekey_b6client1"
	b6Anchors = "nodekey_b6anchors1"
)

var b6Now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type b6CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func b6NewCA(t *testing.T, serial int64, notBefore, notAfter time.Time) *b6CA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "b6 test ca"},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &b6CA{cert: c, key: k}
}

// b6Register holds an active client key whose leaf runs from b6Now-1h to
// b6Now+90d, and the CA (b6Now-1h to b6Now+365d) as the anchors.
func b6Register(t *testing.T) (*nodekey.Register, nodekey.LabFiles, *x509.Certificate, *b6CA) {
	t.Helper()
	ca := b6NewCA(t, 1, b6Now.Add(-time.Hour), b6Now.Add(365*24*time.Hour))
	keys := nodekey.LabFiles{Dir: t.TempDir()}
	r := nodekey.NewRegister(b6Node)
	csrDER, err := r.Request(keys, b6Client, pkix.Name{CommonName: b6Node}, b6Admin, b6Now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject,
		NotBefore: b6Now.Add(-time.Hour), NotAfter: b6Now.Add(90 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(b6Client, [][]byte{der}, b6Admin, b6Now); err != nil {
		t.Fatal(err)
	}
	if err := r.SetAnchors(b6Anchors, [][]byte{ca.cert.Raw}, b6Admin, b6Now); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return r, keys, leaf, ca
}

// b6Provider is the lab key store under another provider's name.
type b6Provider struct{ nodekey.LabFiles }

func (b6Provider) Provider() nodekey.Provider { return nodekey.ProviderCNGSoftware }

// b6Failing is the lab key store whose Open fails, as a store that cannot
// be reached would.
type b6Failing struct{ nodekey.LabFiles }

func (b6Failing) Open(string) (crypto.Signer, error) { return nil, errors.New("key store unavailable") }

func b6Periods(leaf *x509.Certificate) map[string]struct {
	at    time.Time
	valid bool
} {
	return map[string]struct {
		at    time.Time
		valid bool
	}{
		"valid":               {b6Now, true},
		"at NotBefore":        {leaf.NotBefore, true},
		"at NotAfter":         {leaf.NotAfter, true},
		"a second before":     {leaf.NotBefore.Add(-time.Second), false},
		"a second after":      {leaf.NotAfter.Add(time.Second), false},
		"expired":             {b6Now.Add(91 * 24 * time.Hour), false},
		"not yet valid (2 h)": {b6Now.Add(-2 * time.Hour), false},
		"long expired (2 yr)": {b6Now.Add(2 * 365 * 24 * time.Hour), false},
	}
}

func TestB6CertificatePeriodIsTheSoleFault(t *testing.T) {
	faults := map[string]func(t *testing.T, r *nodekey.Register, keys nodekey.LabFiles) (string, nodekey.Keys){
		"none":        func(*testing.T, *nodekey.Register, nodekey.LabFiles) (string, nodekey.Keys) { return b6Client, nil },
		"no provider": func(*testing.T, *nodekey.Register, nodekey.LabFiles) (string, nodekey.Keys) { return b6Client, nil },
		"another provider": func(_ *testing.T, _ *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			return b6Client, b6Provider{k}
		},
		"store unavailable": func(_ *testing.T, _ *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			return b6Client, b6Failing{k}
		},
		"key deleted": func(t *testing.T, _ *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			if err := k.Delete(nodekey.KeyName(b6Client, 1)); err != nil {
				t.Fatal(err)
			}
			return b6Client, k
		},
		"key replaced": func(t *testing.T, _ *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			if err := k.Delete(nodekey.KeyName(b6Client, 1)); err != nil {
				t.Fatal(err)
			}
			if _, err := k.Create(nodekey.KeyName(b6Client, 1)); err != nil {
				t.Fatal(err)
			}
			return b6Client, k
		},
		"retired": func(t *testing.T, r *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			if err := r.Retire(b6Client, b6Admin, b6Now); err != nil {
				t.Fatal(err)
			}
			return b6Client, k
		},
		"anchors named as a key": func(_ *testing.T, _ *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			return b6Anchors, k
		},
		"missing reference": func(_ *testing.T, _ *nodekey.Register, k nodekey.LabFiles) (string, nodekey.Keys) {
			return "nodekey_b6absent1", k
		},
	}
	cells := 0
	for fault, spoil := range faults {
		_, _, leaf, _ := b6Register(t)
		for period, p := range b6Periods(leaf) {
			r, keys, ileaf, _ := b6Register(t)
			ref, k := spoil(t, r, keys)
			if fault == "none" {
				k = keys
			}
			cert, e, err := r.Certificate(ref, k, p.at)
			ok := fault == "none" && p.valid
			if (err == nil) != ok || (err == nil) != (cert != nil && e != nil) {
				t.Errorf("Certificate, %s, %s: cert %v, err %v", fault, period, cert != nil, err)
			}
			if sole := fault == "none" && !p.valid; errors.Is(err, nodekey.ErrCertificatePeriod) != sole {
				t.Errorf("Certificate, %s, %s: wraps ErrCertificatePeriod %v, want %v (%v)", fault, period, !sole, sole, err)
			}
			// The loader refuses what Certificate refuses apart from the
			// period, and never for the period.
			lc, le, lerr := r.LoadCertificate(ref, k)
			if (lerr == nil) != (fault == "none") || (lerr == nil) != (lc != nil && le != nil) || errors.Is(lerr, nodekey.ErrCertificatePeriod) {
				t.Errorf("LoadCertificate, %s, %s: %v", fault, period, lerr)
			}
			if lerr == nil && (le.Version != 1 || !slices.Equal(lc.Leaf.Raw, ileaf.Raw)) {
				t.Errorf("LoadCertificate, %s: version %d, or another leaf", fault, le.Version)
			}
			cells++
		}
	}
	if cells != len(faults)*8 {
		t.Fatalf("%d cells", cells)
	}
}

// garbage is not a certificate. The register refuses it on Parse and
// Validate; it is put into the entry here only to fix the order of the
// checks, so that a set with an unreadable certificate after an expired one
// is refused for the unreadable one.
var garbage = []byte{0x30, 0x03, 0x02, 0x01, 0x01}

func TestB6TrustAnchorsPeriodIsTheSoleFault(t *testing.T) {
	type set struct {
		name    string
		build   func(t *testing.T, r *nodekey.Register, ca *b6CA) string
		fault   bool
		expired func(at time.Time, ca *b6CA, second *b6CA) bool
	}
	caExpired := func(at time.Time, ca *b6CA, _ *b6CA) bool {
		return at.Before(ca.cert.NotBefore) || at.After(ca.cert.NotAfter)
	}
	// A second anchor whose period ends earlier: it is the only one expired
	// between its end and the first's.
	var second *b6CA
	sets := []set{
		{"one anchor", func(*testing.T, *nodekey.Register, *b6CA) string { return b6Anchors }, false, caExpired},
		{"two anchors, the second expires first", func(t *testing.T, r *nodekey.Register, ca *b6CA) string {
			second = b6NewCA(t, 7, b6Now.Add(-time.Hour), b6Now.Add(30*24*time.Hour))
			if err := r.SetAnchors(b6Anchors, [][]byte{ca.cert.Raw, second.cert.Raw}, b6Admin, b6Now); err != nil {
				t.Fatal(err)
			}
			return b6Anchors
		}, false, func(at time.Time, ca *b6CA, s *b6CA) bool { return caExpired(at, ca, nil) || caExpired(at, s, nil) }},
		{"unreadable after the first", func(t *testing.T, r *nodekey.Register, _ *b6CA) string {
			b6Spoil(t, r, func(c [][]byte) [][]byte { return append(c, garbage) })
			return b6Anchors
		}, true, caExpired},
		{"unreadable before the first", func(t *testing.T, r *nodekey.Register, _ *b6CA) string {
			b6Spoil(t, r, func(c [][]byte) [][]byte { return append([][]byte{garbage}, c...) })
			return b6Anchors
		}, true, caExpired},
		{"retired", func(t *testing.T, r *nodekey.Register, _ *b6CA) string {
			if err := r.Retire(b6Anchors, b6Admin, b6Now); err != nil {
				t.Fatal(err)
			}
			return b6Anchors
		}, true, caExpired},
		{"a key named as anchors", func(*testing.T, *nodekey.Register, *b6CA) string { return b6Client }, true, caExpired},
		{"missing reference", func(*testing.T, *nodekey.Register, *b6CA) string { return "nodekey_b6absent1" }, true, caExpired},
	}
	times := map[string]time.Time{
		"valid":                 b6Now,
		"second ended, ca not":  b6Now.Add(60 * 24 * time.Hour),
		"ca ended":              b6Now.Add(400 * 24 * time.Hour),
		"not yet valid (2 h)":   b6Now.Add(-2 * time.Hour),
		"a second after ca end": b6Now.Add(365*24*time.Hour + time.Second),
		"at ca end":             b6Now.Add(365 * 24 * time.Hour),
	}
	for _, s := range sets {
		for when, at := range times {
			r, _, _, ca := b6Register(t)
			ref := s.build(t, r, ca)
			expired := s.expired(at, ca, second)
			pool, e, err := r.TrustAnchors(ref, at)
			ok := !s.fault && !expired
			if (err == nil) != ok || (err == nil) != (pool != nil && e != nil) {
				t.Errorf("TrustAnchors, %s, %s: pool %v, err %v", s.name, when, pool != nil, err)
			}
			if sole := !s.fault && expired; errors.Is(err, nodekey.ErrCertificatePeriod) != sole {
				t.Errorf("TrustAnchors, %s, %s: wraps ErrCertificatePeriod %v, want %v (%v)", s.name, when, !sole, sole, err)
			}
			lp, le, lerr := r.LoadTrustAnchors(ref)
			if (lerr == nil) != !s.fault || (lerr == nil) != (lp != nil && le != nil) || errors.Is(lerr, nodekey.ErrCertificatePeriod) {
				t.Errorf("LoadTrustAnchors, %s, %s: %v", s.name, when, lerr)
			}
		}
	}
}

// b6Spoil changes the active anchors' certificates in place, past the
// register's own checks.
func b6Spoil(t *testing.T, r *nodekey.Register, f func([][]byte) [][]byte) {
	t.Helper()
	for i := range r.Entries {
		if e := &r.Entries[i]; e.Ref == b6Anchors && e.State == nodekey.StateActive {
			e.Certificates = f(e.Certificates)
			return
		}
	}
	t.Fatal("no active anchors")
}

// An expired anchor stays in the loaded pool (D4-11 item 5): a leaf that
// chains only to it does not verify once it has ended, and verifies before.
// The pool from the loader and the pool from the strict resolver hold the
// same anchors while both are valid.
func TestB6LoadedPoolKeepsTheExpiredAnchor(t *testing.T) {
	r, _, leaf, ca := b6Register(t)
	pool, _, err := r.LoadTrustAnchors(b6Anchors)
	if err != nil {
		t.Fatal(err)
	}
	strict, _, err := r.TrustAnchors(b6Anchors, b6Now)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.Equal(strict) {
		t.Error("the loaded pool is not the strict pool at a valid time")
	}
	opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	opts.CurrentTime = b6Now
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("valid: %v", err)
	}
	// Past the CA's end, the leaf is long expired too; check the anchor's
	// expiry on its own with the CA verifying itself.
	opts.CurrentTime = ca.cert.NotAfter.Add(time.Second)
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	var invalid x509.CertificateInvalidError
	if _, err := ca.cert.Verify(opts); !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Errorf("the expired anchor in the loaded pool: %v", err)
	}
}
