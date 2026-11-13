package linkkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/nodekey"
)

// Every key and certificate here is made by the test (D2-5).

const (
	testNode  = "site-a-node1"
	admin     = "admin@site-a"
	linkRef   = "nodekey_sensorlink1"
	clientRef = "nodekey_relpclient1"
	anchorRef = "nodekey_relpanchors1"
)

var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// readFile stands in for protect.ReadFile: it refuses more than max bytes.
func readFile(p string, max int64) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, max)
	}
	return os.ReadFile(p)
}

// labOnly opens the lab-files provider in dir and refuses every other.
func labOnly(dir string) func(nodekey.Provider) (nodekey.Keys, error) {
	return func(p nodekey.Provider) (nodekey.Keys, error) {
		if p != nodekey.ProviderLabFiles {
			return nil, fmt.Errorf("provider %s is not available", p)
		}
		return nodekey.LabFiles{Dir: dir}, nil
	}
}

func spkiOf(t testing.TB, pub crypto.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pinOf(spki []byte) string {
	h := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(h[:])
}

// entryFor is an active entry for the key with this public key.
func entryFor(t testing.TB, ref string, version uint32, pub crypto.PublicKey) Entry {
	t.Helper()
	spki := spkiOf(t, pub)
	return Entry{Ref: ref, Kind: KindLinkKey, Version: version, State: nodekey.StateActive,
		Provider: nodekey.ProviderLabFiles, PublicKey: spki, Fingerprint: fingerprint(spki),
		InstalledBy: admin, InstalledAt: now.Format(time.RFC3339)}
}

// fixture is a lab key store holding a link key, and its file.
type fixture struct {
	keys   nodekey.LabFiles
	signer crypto.Signer
	file   *File
	dir    string // where the file is written
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	keys := nodekey.LabFiles{Dir: t.TempDir()}
	s, err := keys.Create(nodekey.KeyName(linkRef, 1))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{keys: keys, signer: s, dir: t.TempDir(),
		file: &File{Format: Format, NodeID: testNode, Entries: []Entry{entryFor(t, linkRef, 1, s.Public())}}}
}

// write puts b in the fixture's directory and returns the path.
func (f *fixture) write(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(f.dir, "linkkey.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// encode is the fixture's file as JSON, without Marshal's checks, so a
// test can write a file that fails them.
func encode(t testing.TB, f *File) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) load(t testing.TB, b []byte, reg RegisterKeys) (*Key, error) {
	t.Helper()
	return Load(readFile, f.write(t, b), testNode, labOnly(f.keys.Dir), reg)
}

// TestLoad: the file's active key opens, its pin is the hash of the
// signer's own public key, and every entry is returned for the node's
// records. The file round-trips through Marshal.
func TestLoad(t *testing.T) {
	f := newFixture(t)
	old := entryFor(t, linkRef, 2, f.signer.Public())
	old.State = nodekey.StateRetired
	f.file.Entries = append(f.file.Entries, old)
	b, err := f.file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.load(t, b, NoRegister())
	if err != nil {
		t.Fatal(err)
	}
	if want := pinOf(spkiOf(t, f.signer.Public())); k.Pin != want {
		t.Errorf("pin %s, want %s", k.Pin, want)
	}
	if !bytes.Equal(spkiOf(t, k.Signer.Public()), spkiOf(t, f.signer.Public())) {
		t.Error("the signer is not the link key")
	}
	if k.Entry.Version != 1 || k.Entry.State != nodekey.StateActive || len(k.Entries) != 2 {
		t.Errorf("entry %+v, %d entries", k.Entry, len(k.Entries))
	}
	digest := sha256.Sum256([]byte("otsec link key test"))
	sig, err := k.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(f.signer.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Errorf("the signer does not sign with the link key: %v", err)
	}
}

// TestLoadMissing: no file is ErrMissing, never a node with no link key
// and no fault. Control: the missing file taken as no key (nil, nil).
func TestLoadMissing(t *testing.T) {
	f := newFixture(t)
	k, err := Load(readFile, filepath.Join(f.dir, "absent.json"), testNode, labOnly(f.keys.Dir), NoRegister())
	if k != nil || !errors.Is(err, ErrMissing) {
		t.Fatalf("missing file: %v, %v; want ErrMissing", k, err)
	}
}

// TestLoadUnreadable: a file that cannot be read is ErrUnreadable, not
// ErrMissing: a directory in its place, a read refused by the
// protected-file rule, and a file over the read's bound.
func TestLoadUnreadable(t *testing.T) {
	f := newFixture(t)
	refused := func(string, int64) ([]byte, error) { return nil, readErr("has mode 0644") }
	big := f.write(t, append(encode(t, f.file), bytes.Repeat([]byte(" "), MaxFileBytes)...))
	for name, c := range map[string]struct {
		read func(string, int64) ([]byte, error)
		path string
	}{
		"a directory":    {readFile, f.dir},
		"refused":        {refused, filepath.Join(f.dir, "linkkey.json")},
		"over the bound": {readFile, big},
	} {
		k, err := Load(c.read, c.path, testNode, labOnly(f.keys.Dir), NoRegister())
		if k != nil || !errors.Is(err, ErrUnreadable) || errors.Is(err, ErrMissing) {
			t.Errorf("%s: %v, %v; want ErrUnreadable", name, k, err)
		}
	}
}

type readErr string

func (e readErr) Error() string { return "linkkey.json " + string(e) }

// TestLoadMalformed: a file that does not decode strictly, or is not this
// node's, is ErrMalformed, and nothing in it is used.
func TestLoadMalformed(t *testing.T) {
	f := newFixture(t)
	good := encode(t, f.file)
	edit := func(g func(*File)) []byte {
		var c File
		if err := json.Unmarshal(good, &c); err != nil {
			t.Fatal(err)
		}
		g(&c)
		return encode(t, &c)
	}
	many := func(c *File) {
		for len(c.Entries) <= MaxEntries {
			e := c.Entries[0]
			e.Version, e.State = uint32(len(c.Entries)+1), nodekey.StateRetired
			c.Entries = append(c.Entries, e)
		}
	}
	field := func(add string) []byte {
		return []byte(strings.Replace(string(good), `"format"`, add+`,"format"`, 1))
	}
	for name, b := range map[string][]byte{
		"not JSON":         []byte("link key"),
		"not UTF-8":        append([]byte{0xff}, good...),
		"trailing data":    append(append([]byte{}, good...), []byte(" {}")...),
		"a private key":    field(`"private_key":"x"`),
		"a certificate":    []byte(strings.Replace(string(good), `"fingerprint"`, `"certificates":["eA=="],"fingerprint"`, 1)),
		"duplicate field":  field(`"node_id":"site-a-node1"`),
		"format":           edit(func(c *File) { c.Format = "otsec.linkkey/0.2" }),
		"register format":  edit(func(c *File) { c.Format = nodekey.RegisterFormat }),
		"other node":       edit(func(c *File) { c.NodeID = "site-a-node2" }),
		"no entries":       edit(func(c *File) { c.Entries = nil }),
		"too many entries": edit(many),
		"oversize":         append(append([]byte{}, good...), bytes.Repeat([]byte(" "), MaxFileBytes)...),
	} {
		// A read that ignores the bound, so the reader's own checks are
		// what refuse.
		read := func(string, int64) ([]byte, error) { return b, nil }
		k, err := Load(read, "linkkey.json", testNode, labOnly(f.keys.Dir), NoRegister())
		if k != nil || !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, %v; want ErrMalformed", name, k, err)
		}
	}
	if _, err := f.load(t, good, NoRegister()); err != nil {
		t.Fatalf("the unedited file: %v", err)
	}
}

// TestBounds: each bound is accepted at its value and refused one past it.
func TestBounds(t *testing.T) {
	f := newFixture(t)
	at := func(n int) *File {
		c := *f.file
		c.Entries = nil
		for v := 1; v <= n; v++ {
			e := entryFor(t, linkRef, uint32(v), f.signer.Public())
			if v > 1 {
				e.State = nodekey.StateRetired
			}
			c.Entries = append(c.Entries, e)
		}
		return &c
	}
	if _, err := parse(encode(t, at(MaxEntries)), testNode); err != nil {
		t.Errorf("%d entries: %v", MaxEntries, err)
	}
	if _, err := parse(encode(t, at(MaxEntries+1)), testNode); !errors.Is(err, ErrMalformed) {
		t.Errorf("%d entries: %v, want ErrMalformed", MaxEntries+1, err)
	}
	version := func(v uint32) []byte {
		c := *f.file
		c.Entries = []Entry{entryFor(t, linkRef, v, f.signer.Public())}
		return encode(t, &c)
	}
	if _, err := parse(version(MaxVersion), testNode); err != nil {
		t.Errorf("version %d: %v", MaxVersion, err)
	}
	if _, err := parse(version(MaxVersion+1), testNode); !errors.Is(err, ErrEntry) {
		t.Errorf("version %d: %v, want ErrEntry", MaxVersion+1, err)
	}
	good := encode(t, f.file)
	pad := func(n int) []byte {
		return append(append([]byte{}, good...), bytes.Repeat([]byte(" "), n-len(good))...)
	}
	if _, err := parse(pad(MaxFileBytes), testNode); err != nil {
		t.Errorf("%d bytes: %v", MaxFileBytes, err)
	}
	if _, err := parse(pad(MaxFileBytes+1), testNode); !errors.Is(err, ErrMalformed) {
		t.Errorf("%d bytes: %v, want ErrMalformed", MaxFileBytes+1, err)
	}
}

// TestLoadEntryRefusals: an entry that fails its checks is ErrEntry, and
// no key is opened. Marshal refuses the same file.
func TestLoadEntryRefusals(t *testing.T) {
	f := newFixture(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	e := func(g func(*Entry)) *File {
		c := *f.file
		c.Entries = []Entry{f.file.Entries[0]}
		g(&c.Entries[0])
		return &c
	}
	second := func(g func(*Entry)) *File {
		c := *f.file
		x := f.file.Entries[0]
		g(&x)
		c.Entries = []Entry{f.file.Entries[0], x}
		return &c
	}
	retired := func(x *Entry) { x.Version, x.State = 2, nodekey.StateRetired }
	for name, c := range map[string]*File{
		"kind tls-key":        e(func(x *Entry) { x.Kind = nodekey.KindTLSKey }),
		"kind trust-anchors":  e(func(x *Entry) { x.Kind = nodekey.KindTrustAnchors }),
		"no kind":             e(func(x *Entry) { x.Kind = "" }),
		"bad ref":             e(func(x *Entry) { x.Ref = "linkkey_sensorlink1" }),
		"version 0":           e(func(x *Entry) { x.Version = 0 }),
		"pending":             e(func(x *Entry) { x.State = nodekey.StatePending }),
		"unknown state":       e(func(x *Entry) { x.State = "maybe" }),
		"unknown provider":    e(func(x *Entry) { x.Provider = "hsm" }),
		"no provider":         e(func(x *Entry) { x.Provider = "" }),
		"no public key":       e(func(x *Entry) { x.PublicKey = nil; x.Fingerprint = fingerprint(nil) }),
		"garbage public key":  e(func(x *Entry) { x.PublicKey = []byte("x"); x.Fingerprint = fingerprint(x.PublicKey) }),
		"P-384 public key":    e(func(x *Entry) { x.PublicKey = spkiOf(t, p384.Public()); x.Fingerprint = fingerprint(x.PublicKey) }),
		"fingerprint":         e(func(x *Entry) { x.Fingerprint = strings.Repeat("0", 64) }),
		"fingerprint case":    e(func(x *Entry) { x.Fingerprint = strings.ToUpper(x.Fingerprint) }),
		"installed_by":        e(func(x *Entry) { x.InstalledBy = "admin site a" }),
		"installed_at":        e(func(x *Entry) { x.InstalledAt = "2026-11-13T12:00:00+03:00" }),
		"no installed_at":     e(func(x *Entry) { x.InstalledAt = "" }),
		"two active":          second(func(x *Entry) { x.Version = 2 }),
		"version twice":       second(func(x *Entry) { x.State = nodekey.StateRetired }),
		"two references":      second(func(x *Entry) { retired(x); x.Ref = "nodekey_sensorlink2" }),
		"no active":           e(func(x *Entry) { x.State = nodekey.StateRetired }),
		"retired then broken": second(func(x *Entry) { retired(x); x.Fingerprint = "" }),
	} {
		k, err := f.load(t, encode(t, c), NoRegister())
		if k != nil || !errors.Is(err, ErrEntry) {
			t.Errorf("%s: %v, %v; want ErrEntry", name, k, err)
		}
		if name == "no active" {
			continue // a file with the key withdrawn is one an administrator may write
		}
		if _, err := c.Marshal(); !errors.Is(err, ErrEntry) {
			t.Errorf("%s: Marshal: %v, want ErrEntry", name, err)
		}
	}
}

// failKeys fails the test if a key is opened.
type failKeys struct{ t testing.TB }

func (failKeys) Provider() nodekey.Provider { return nodekey.ProviderLabFiles }
func (k failKeys) Create(string) (crypto.Signer, error) {
	k.t.Error("a key was created")
	return nil, errors.New("no")
}
func (k failKeys) Open(name string) (crypto.Signer, error) {
	k.t.Errorf("%s was opened", name)
	return nil, errors.New("no")
}
func (k failKeys) Delete(string) error {
	k.t.Error("a key was deleted")
	return errors.New("no")
}

// claims is a lab store that holds the key and names another provider.
type claims struct {
	nodekey.LabFiles
	p nodekey.Provider
}

func (c claims) Provider() nodekey.Provider { return c.p }

// TestLoadNoKey: a provider that does not have the key, or holds another
// key under its name, or is not available, is ErrNoKey.
func TestLoadNoKey(t *testing.T) {
	f := newFixture(t)
	good := encode(t, f.file)
	path := f.write(t, good)
	other := nodekey.LabFiles{Dir: t.TempDir()}
	if _, err := other.Create(nodekey.KeyName(linkRef, 1)); err != nil {
		t.Fatal(err)
	}
	cngFile := *f.file
	cngFile.Entries = []Entry{f.file.Entries[0]}
	cngFile.Entries[0].Provider = nodekey.ProviderCNGSoftware
	for name, c := range map[string]struct {
		keys func(nodekey.Provider) (nodekey.Keys, error)
		file []byte
	}{
		"empty store":      {labOnly(t.TempDir()), good},
		"another key":      {labOnly(other.Dir), good},
		"no provider":      {nil, good},
		"provider refused": {labOnly(f.keys.Dir), encode(t, &cngFile)},
		"provider nil":     {func(nodekey.Provider) (nodekey.Keys, error) { return nil, nil }, good},
		"another provider": {func(nodekey.Provider) (nodekey.Keys, error) { return claims{f.keys, nodekey.ProviderCNGSoftware}, nil }, good},
	} {
		if err := os.WriteFile(path, c.file, 0o600); err != nil {
			t.Fatal(err)
		}
		k, err := Load(readFile, path, testNode, c.keys, NoRegister())
		if k != nil || !errors.Is(err, ErrNoKey) {
			t.Errorf("%s: %v, %v; want ErrNoKey", name, k, err)
		}
	}
}

// testCA issues the register's certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t testing.TB) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &testCA{cert: selfSigned(t, k), key: k}
}

func selfSigned(t testing.TB, k crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "otsec test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func (ca *testCA) issue(t testing.TB, csrDER []byte) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// installed is a register with an active tls-key from ca and ca as trust
// anchors, its keys in keys.
func installed(t testing.TB, ca *testCA, keys nodekey.LabFiles) *nodekey.Register {
	t.Helper()
	r := nodekey.NewRegister(testNode)
	csr, err := r.Request(keys, clientRef, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(clientRef, [][]byte{ca.issue(t, csr)}, admin, now); err != nil {
		t.Fatal(err)
	}
	if err := r.SetAnchors(anchorRef, [][]byte{ca.cert.Raw}, admin, now); err != nil {
		t.Fatal(err)
	}
	return r
}

// copyKey puts the provider's key from one name under another, so that a
// reader with no clash check would open the shared key.
func copyKey(t testing.TB, keys nodekey.LabFiles, from, to string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(keys.Dir, from+".p8"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys.Dir, to+".p8"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLoadClash (NK-2): a link key that is also a key of the register is
// refused, and the register is untouched and still serves its tls-key: the
// public key of a tls-key entry, of a retired one, or of a trust anchor's
// certificate, and a reference of the register. With the register set and
// not loaded, the key is refused without being opened. Control: a reader
// with no clash check, which returns the register's key as the link key.
func TestLoadClash(t *testing.T) {
	ca := newCA(t)
	f := newFixture(t)
	reg := installed(t, ca, f.keys)
	before, err := reg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cert, regEntry, err := reg.LoadCertificate(clientRef, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	shared := func() *File {
		// The link key's name holds the tls-key's own key.
		copyKey(t, f.keys, nodekey.KeyName(clientRef, regEntry.Version), nodekey.KeyName(linkRef, 2))
		c := *f.file
		c.Entries = []Entry{entryFor(t, linkRef, 2, cert.PrivateKey.(crypto.Signer).Public())}
		return &c
	}()
	sameRef := func() *File {
		s, err := f.keys.Create(nodekey.KeyName(clientRef, 9))
		if err != nil {
			t.Fatal(err)
		}
		c := *f.file
		c.Entries = []Entry{entryFor(t, clientRef, 9, s.Public())}
		return &c
	}()
	// The link key's own certificate set as a register trust anchor.
	anchored := nodekey.NewRegister(testNode)
	if err := anchored.SetAnchors(anchorRef, [][]byte{selfSigned(t, f.signer).Raw}, admin, now); err != nil {
		t.Fatal(err)
	}
	// The tls-key replaced: its first version is retired, and its key is
	// the link key.
	rotated := installed(t, ca, nodekey.LabFiles{Dir: t.TempDir()})
	retiredKey := func() *File {
		csr, err := rotated.Request(nodekey.LabFiles{Dir: t.TempDir()}, clientRef, pkix.Name{CommonName: testNode}, admin, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := rotated.Install(clientRef, [][]byte{ca.issue(t, csr)}, admin, now); err != nil {
			t.Fatal(err)
		}
		for _, e := range rotated.Entries {
			if e.Ref == clientRef && e.State == nodekey.StateRetired {
				pub, err := x509.ParsePKIXPublicKey(e.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				c := *f.file
				c.Entries = []Entry{entryFor(t, linkRef, 3, pub)}
				return &c
			}
		}
		t.Fatal("no retired version")
		return nil
	}()
	for name, c := range map[string]struct {
		file *File
		reg  *nodekey.Register
	}{
		"a tls-key's key":         {shared, reg},
		"a register reference":    {sameRef, reg},
		"a trust anchor's key":    {f.file, anchored},
		"a retired tls-key's key": {retiredKey, rotated},
	} {
		k, err := f.load(t, encode(t, c.file), FromRegister(c.reg))
		if k != nil || !errors.Is(err, ErrClash) {
			t.Errorf("%s: %v, %v; want ErrClash", name, k, err)
		}
	}
	after, err := reg.Marshal()
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("the register changed: %v", err)
	}
	if _, _, err := reg.LoadCertificate(clientRef, f.keys); err != nil {
		t.Errorf("the tls-key no longer resolves: %v", err)
	}
	for name, rk := range map[string]RegisterKeys{"zero": {}, "nil register": FromRegister(nil)} {
		k, err := Load(readFile, f.write(t, encode(t, f.file)), testNode,
			func(nodekey.Provider) (nodekey.Keys, error) { return failKeys{t}, nil }, rk)
		if k != nil || !errors.Is(err, ErrRegisterNotLoaded) {
			t.Errorf("%s: %v, %v; want ErrRegisterNotLoaded", name, k, err)
		}
	}
	// No clash: the link key loads beside the register.
	if _, err := f.load(t, encode(t, f.file), FromRegister(reg)); err != nil {
		t.Errorf("a link key apart from the register: %v", err)
	}
}

// TestFromRegisterUnparsed: a register key that does not parse makes the
// register one not loaded, never a register with nothing to clash with.
func TestFromRegisterUnparsed(t *testing.T) {
	for name, e := range map[string]nodekey.Entry{
		"public key":  {Ref: clientRef, PublicKey: []byte("x")},
		"certificate": {Ref: anchorRef, Certificates: [][]byte{[]byte("x")}},
	} {
		if k := FromRegister(&nodekey.Register{Entries: []nodekey.Entry{e}}); k.loaded {
			t.Errorf("%s: a register with a key that does not parse is taken as loaded", name)
		}
	}
}
