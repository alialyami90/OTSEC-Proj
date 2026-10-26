package nodekey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Every key and certificate here is made by the test (D2-5).

const (
	testNode   = "site-a-node1"
	admin      = "admin@site-a"
	clientRef  = "nodekey_relpclient1"
	anchorsRef = "nodekey_relpanchors1"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t testing.TB, name string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k}
}

// issue signs a certificate for the CSR's key, as an administrator's CA
// would.
func (ca *testCA) issue(t testing.TB, csrDER []byte, eku x509.ExtKeyUsage, notAfter time.Time) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the request is not signed by its key: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject,
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{eku},
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{csr.Subject.CommonName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// installed is a register with an active client key from ca and ca as
// trust anchors, and the lab key store holding the key.
func installed(t testing.TB, ca *testCA) (*Register, LabFiles) {
	t.Helper()
	keys := LabFiles{Dir: t.TempDir()}
	r := NewRegister(testNode)
	csr, err := r.Request(keys, clientRef, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(clientRef, [][]byte{ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(90*24*time.Hour))}, admin, now); err != nil {
		t.Fatal(err)
	}
	if err := r.SetAnchors(anchorsRef, [][]byte{ca.cert.Raw}, admin, now); err != nil {
		t.Fatal(err)
	}
	return r, keys
}

func roundTrip(t testing.TB, r *Register) *Register {
	t.Helper()
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(b, testNode)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestClientKeyHandshake: a key made by Request, certified by a CA and
// installed, resolves to a certificate whose signer completes a mutual TLS
// handshake, and the trust anchors verify the peer. The key is used where
// it lives: the register holds no private key.
func TestClientKeyHandshake(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	r, keys := installed(t, ca)
	r = roundTrip(t, r)
	cert, e, err := r.Certificate(clientRef, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != 1 || e.Provider != ProviderLabFiles {
		t.Fatalf("entry %+v", e)
	}
	roots, _, err := r.TrustAnchors(anchorsRef, now)
	if err != nil {
		t.Fatal(err)
	}
	// The register holds the public key and certificates only.
	b, _ := r.Marshal()
	priv, _ := keys.Open(KeyName(clientRef, 1))
	d := priv.(*ecdsa.PrivateKey).D.Bytes()
	if bytes.Contains(b, d) || strings.Contains(string(b), "PRIVATE") {
		t.Fatal("the register holds the private key")
	}

	// A server certified by the same CA, requiring a client certificate.
	srvKeys := LabFiles{Dir: t.TempDir()}
	sr := NewRegister(testNode)
	srvCSR, err := sr.Request(srvKeys, "nodekey_listener01", pkix.Name{CommonName: "127.0.0.1"}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := sr.Install("nodekey_listener01", [][]byte{ca.issue(t, srvCSR, x509.ExtKeyUsageServerAuth, now.Add(time.Hour))}, admin, now); err != nil {
		t.Fatal(err)
	}
	srvCert, _, err := sr.Certificate("nodekey_listener01", srvKeys, now)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*srvCert}, ClientCAs: roots,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12, Time: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			peer <- err.Error()
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			peer <- err.Error()
			return
		}
		peer <- tc.ConnectionState().PeerCertificates[0].Subject.CommonName
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{Certificates: []tls.Certificate{*cert}, RootCAs: roots,
		ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, Time: clock})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := <-peer; got != testNode {
		t.Fatalf("server saw %q", got)
	}
}

// TestRotation: a second request and install make version 2 active and
// retire version 1, which no longer resolves; the old key stays until an
// administrator deletes it.
func TestRotation(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	r, keys := installed(t, ca)
	csr, err := r.Request(keys, clientRef, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	// While version 2 is pending, version 1 still resolves.
	if _, e, err := r.Certificate(clientRef, keys, now); err != nil || e.Version != 1 {
		t.Fatalf("during the request: %v %+v", err, e)
	}
	if _, err := r.Request(keys, clientRef, pkix.Name{CommonName: testNode}, admin, now); err == nil {
		t.Fatal("a second pending request accepted")
	}
	if err := r.Install(clientRef, [][]byte{ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(time.Hour))}, admin, now); err != nil {
		t.Fatal(err)
	}
	r = roundTrip(t, r)
	if _, e, err := r.Certificate(clientRef, keys, now); err != nil || e.Version != 2 {
		t.Fatalf("after the install: %v %+v", err, e)
	}
	states := map[uint32]State{}
	for _, e := range r.Entries {
		if e.Ref == clientRef {
			states[e.Version] = e.State
		}
	}
	if states[1] != StateRetired || states[2] != StateActive {
		t.Fatalf("states %v", states)
	}
	if _, err := keys.Open(KeyName(clientRef, 1)); err != nil {
		t.Fatalf("the old key went with the install: %v", err)
	}
	// Anchors rotate the same way.
	other := newCA(t, "otsec test ca 2")
	if err := r.SetAnchors(anchorsRef, [][]byte{other.cert.Raw}, admin, now); err != nil {
		t.Fatal(err)
	}
	if _, e, err := r.TrustAnchors(anchorsRef, now); err != nil || e.Version != 2 {
		t.Fatalf("anchors: %v %+v", err, e)
	}
	// Retiring leaves nothing to resolve.
	if err := r.Retire(clientRef, admin, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Certificate(clientRef, keys, now); err == nil {
		t.Fatal("a retired reference resolved")
	}
	if err := r.Retire(clientRef, admin, now); err == nil {
		t.Fatal("a reference with no active version retired")
	}
}

// TestCertificateRefusals: resolution fails closed, and never uses a key
// the register does not name.
func TestCertificateRefusals(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	for name, c := range map[string]struct {
		setup func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time)
	}{
		"another provider": {func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time) {
			return otherProvider{keys}, now
		}},
		"no provider": {func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time) { return nil, now }},
		"key deleted": {func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time) {
			keys.Delete(KeyName(clientRef, 1))
			return keys, now
		}},
		"key replaced": {func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time) {
			keys.Delete(KeyName(clientRef, 1))
			if _, err := keys.Create(KeyName(clientRef, 1)); err != nil {
				t.Fatal(err)
			}
			return keys, now
		}},
		"expired": {func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time) {
			return keys, now.Add(91 * 24 * time.Hour)
		}},
		"not yet valid": {func(t *testing.T, r *Register, keys LabFiles) (Keys, time.Time) {
			return keys, now.Add(-2 * time.Hour)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r, keys := installed(t, ca)
			k, at := c.setup(t, r, keys)
			if cert, _, err := r.Certificate(clientRef, k, at); err == nil || cert != nil {
				t.Fatalf("resolved: %v", err)
			}
		})
	}
	r, keys := installed(t, ca)
	if _, _, err := r.Certificate(anchorsRef, keys, now); err == nil {
		t.Fatal("trust anchors resolved as a key")
	}
	if _, _, err := r.TrustAnchors(clientRef, now); err == nil {
		t.Fatal("a key resolved as trust anchors")
	}
	if _, _, err := r.TrustAnchors("nodekey_notthere1", now); err == nil {
		t.Fatal("a missing reference resolved")
	}
	if _, _, err := r.TrustAnchors(anchorsRef, now.Add(400*24*time.Hour)); err == nil {
		t.Fatal("expired anchors resolved")
	}
	// A pending key never resolves.
	p := NewRegister(testNode)
	if _, err := p.Request(keys, "nodekey_pendingonly", pkix.Name{CommonName: testNode}, admin, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Certificate("nodekey_pendingonly", keys, now); err == nil {
		t.Fatal("a pending key resolved")
	}
}

// otherProvider is keys under another provider's name.
type otherProvider struct{ LabFiles }

func (otherProvider) Provider() Provider { return ProviderCNGSoftware }

// TestInstallRefusals: only a certificate for the pending key, valid now,
// is installed, and a refused install changes nothing.
func TestInstallRefusals(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	keys := LabFiles{Dir: t.TempDir()}
	r := NewRegister(testNode)
	csr, err := r.Request(keys, clientRef, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	otherKeys := LabFiles{Dir: t.TempDir()}
	o := NewRegister(testNode)
	otherCSR, _ := o.Request(otherKeys, clientRef, pkix.Name{CommonName: testNode}, admin, now)
	before, _ := r.Marshal()
	for name, chain := range map[string][][]byte{
		"another key's certificate": {ca.issue(t, otherCSR, x509.ExtKeyUsageClientAuth, now.Add(time.Hour))},
		"expired":                   {ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute))},
		"garbage":                   {[]byte("not a certificate")},
		"empty":                     nil,
	} {
		if err := r.Install(clientRef, chain, admin, now); err == nil {
			t.Errorf("%s installed", name)
		}
		if after, _ := r.Marshal(); !bytes.Equal(before, after) {
			t.Fatalf("%s changed the register", name)
		}
	}
	if err := r.Install("nodekey_notthere1", [][]byte{ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(time.Hour))}, admin, now); err == nil {
		t.Fatal("install without a pending key")
	}
	if err := r.Install(clientRef, [][]byte{ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(time.Hour))}, "admin site a", now); err == nil {
		t.Fatal("install by a malformed principal")
	}
}

// TestRequestRefusals: a refused request leaves no key and no entry.
func TestRequestRefusals(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	r, keys := installed(t, ca)
	before, _ := r.Marshal()
	for name, ref := range map[string]string{"anchors reference": anchorsRef, "bad reference": "nodekey_X"} {
		if _, err := r.Request(keys, ref, pkix.Name{CommonName: testNode}, admin, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := r.Request(keys, "nodekey_badadmin01", pkix.Name{CommonName: testNode}, "", now); err == nil {
		t.Fatal("request with no administrator accepted")
	}
	if _, err := keys.Open(KeyName("nodekey_badadmin01", 1)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a refused request left its key: %v", err)
	}
	if after, _ := r.Marshal(); !bytes.Equal(before, after) {
		t.Fatal("a refused request changed the register")
	}
	if err := r.SetAnchors(clientRef, [][]byte{ca.cert.Raw}, admin, now); err == nil {
		t.Fatal("anchors set on a key reference")
	}
	if err := r.SetAnchors("nodekey_noanchors1", nil, admin, now); err == nil {
		t.Fatal("empty anchors accepted")
	}
}

// TestParseRefusals: any bad entry refuses the whole register.
func TestParseRefusals(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	good, _ := installed(t, ca)
	other := newCA(t, "otsec test ca 2")
	edit := func(f func(r *Register)) []byte {
		b, _ := good.Marshal()
		var r Register
		json.Unmarshal(b, &r)
		f(&r)
		out, _ := json.Marshal(r)
		return out
	}
	key := func(r *Register) *Entry { return &r.Entries[0] }
	anchors := func(r *Register) *Entry { return &r.Entries[1] }
	many := func(r *Register) {
		for len(r.Entries) <= MaxEntries {
			e := *anchors(r)
			e.Version = uint32(len(r.Entries) + 1)
			e.State = StateRetired
			r.Entries = append(r.Entries, e)
		}
	}
	for name, b := range map[string][]byte{
		"other node":            edit(func(r *Register) { r.NodeID = "site-a-node2" }),
		"format":                edit(func(r *Register) { r.Format = "otsec.nodekey-register/0.2" }),
		"no entries":            edit(func(r *Register) { r.Entries = nil }),
		"too many entries":      edit(many),
		"bad ref":               edit(func(r *Register) { key(r).Ref = "cred_relpclient1" }),
		"version 0":             edit(func(r *Register) { key(r).Version = 0 }),
		"unknown kind":          edit(func(r *Register) { key(r).Kind = "password" }),
		"unknown state":         edit(func(r *Register) { key(r).State = "maybe" }),
		"unknown provider":      edit(func(r *Register) { key(r).Provider = "hsm" }),
		"fingerprint":           edit(func(r *Register) { key(r).Fingerprint = strings.Repeat("0", 64) }),
		"anchors fingerprint":   edit(func(r *Register) { anchors(r).Certificates = [][]byte{other.cert.Raw} }),
		"certificate for other": edit(func(r *Register) { key(r).Certificates = [][]byte{other.cert.Raw} }),
		"no public key":         edit(func(r *Register) { key(r).PublicKey = nil }),
		"active without cert":   edit(func(r *Register) { key(r).Certificates = nil }),
		"pending with cert":     edit(func(r *Register) { key(r).State = StatePending }),
		"anchors with provider": edit(func(r *Register) { anchors(r).Provider = ProviderLabFiles }),
		"anchors pending":       edit(func(r *Register) { anchors(r).State = StatePending }),
		"anchors empty": edit(func(r *Register) {
			anchors(r).Certificates = nil
			anchors(r).Fingerprint = (&Entry{Kind: KindTrustAnchors}).fingerprint()
		}),
		"garbage certificate": edit(func(r *Register) { anchors(r).Certificates = [][]byte{[]byte("x")} }),
		"too many certificates": edit(func(r *Register) {
			e := anchors(r)
			for len(e.Certificates) <= MaxCertificates {
				e.Certificates = append(e.Certificates, ca.cert.Raw)
			}
			e.Fingerprint = e.fingerprint()
		}),
		"two active": edit(func(r *Register) {
			e := *anchors(r)
			e.Version = 2
			r.Entries = append(r.Entries, e)
		}),
		"version twice": edit(func(r *Register) {
			e := *anchors(r)
			e.State = StateRetired
			r.Entries = append(r.Entries, e)
		}),
		"two kinds": edit(func(r *Register) {
			e := *anchors(r)
			e.Ref, e.Version, e.State = clientRef, 2, StateRetired
			r.Entries = append(r.Entries, e)
		}),
		"two pending": edit(func(r *Register) {
			e := *key(r)
			e.State, e.Certificates, e.Version = StatePending, nil, 2
			f := e
			f.Version = 3
			r.Entries = append(r.Entries, e, f)
		}),
		"installed_by":    edit(func(r *Register) { key(r).InstalledBy = "admin site a" }),
		"installed_at":    edit(func(r *Register) { key(r).InstalledAt = "2026-10-26T12:00:00+03:00" }),
		"unknown field":   []byte(strings.Replace(string(edit(func(*Register) {})), `"format"`, `"private_key":"x","format"`, 1)),
		"duplicate field": []byte(strings.Replace(string(edit(func(*Register) {})), `"format"`, `"node_id":"site-a-node1","format"`, 1)),
		"oversize":        append(edit(func(*Register) {}), bytes.Repeat([]byte(" "), MaxRegisterBytes)...),
	} {
		if _, err := Parse(b, testNode); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Parse(edit(func(*Register) {}), testNode); err != nil {
		t.Fatalf("the unedited register: %v", err)
	}
}

func TestExpiring(t *testing.T) {
	ca := newCA(t, "otsec test ca")
	r, _ := installed(t, ca) // the client certificate expires in 90 days, the CA in 365
	if got := r.Expiring(now, 30*24*time.Hour); len(got) != 0 {
		t.Fatalf("30 days: %v", got)
	}
	if got := r.Expiring(now, 100*24*time.Hour); len(got) != 1 || got[0] != clientRef {
		t.Fatalf("100 days: %v", got)
	}
	if got := r.Expiring(now, 400*24*time.Hour); len(got) != 2 {
		t.Fatalf("400 days: %v", got)
	}
}

func TestLabFiles(t *testing.T) {
	keys := LabFiles{Dir: t.TempDir()}
	name := KeyName(clientRef, 1)
	if _, err := keys.Open(name); !errors.Is(err, ErrNoKey) {
		t.Fatalf("missing key: %v", err)
	}
	k, err := keys.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Create(name); err == nil {
		t.Fatal("an existing key created again")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(keys.Dir, name+".p8"))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	o, err := keys.Open(name)
	if err != nil || !o.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatalf("open: %v", err)
	}
	for _, bad := range []string{"../x", "otsec-nodekey_x-v1", "otsec-nodekey_relpclient1-v0", "nodekey_relpclient1"} {
		if _, err := keys.Create(bad); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	os.WriteFile(filepath.Join(keys.Dir, KeyName(clientRef, 2)+".p8"), []byte("garbage"), 0o600)
	if _, err := keys.Open(KeyName(clientRef, 2)); err == nil || strings.Contains(err.Error(), "garbage") {
		t.Fatalf("garbage key: %v", err)
	}
	if err := keys.Delete(name); err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(name); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}
