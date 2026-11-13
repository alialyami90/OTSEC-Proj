// Package linkkey reads the node's link key: the key the node offers in
// the mutual TLS handshake of its link to a passive network sensor
// (docs/phase4/D3-sensor-link.md section 11.4, NK-1 to NK-6). The key is
// kept in a file of its own beside the node key register, never in it, so
// that a fault in it holds back the sensor links only and never the
// register, whose all-or-nothing rule the node's start depends on (F11).
//
// # The file
//
// The file holds entries of one kind, link-key, in the register's entry
// form: a nodekey_ reference to a key held by one of the register's
// providers, its public key, its version and state, and who installed it
// and when. It holds no private key, no certificate and no pending state:
// the link has no CA (SL-2), and the handshake's self-signed certificate is
// made in memory at each start (NK-3). All its entries are versions of one
// reference, and at most one is active. An administrator's tool writes it
// (Marshal); the node only reads it.
//
// # The reader
//
// Load is the one reader. It returns the active entry's signer and pin.
// Its one other input is what the node already loaded of the node key
// register (RegisterKeys): a link key whose public key is any key of the
// register, or whose reference is any reference of the register, is
// refused, and with a register that is set and not loaded the clash cannot
// be checked, so the key is refused too (NK-2). Load never changes the
// register and opens no register key. Every fault wraps one of the Err
// values, which name the cause of the node's alarm, and none falls back.
//
// The caller passes the file read (protect.ReadFile, the protected-file
// rule) and the providers the node may open (the lab-files provider only
// behind lab_tls_files), as it does for the register. No package other
// than platform/sensorlink imports this one (TestOnlySensorlinkImports).
//
// # Limit
//
// A local administrator can use the key (D3-7), and whoever can write the
// file can point the node at another key of a provider. The sensor's end
// pins the node's key, so it then refuses the node, which fails closed.
package linkkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/nodekey"
)

// Format identifies the link key file. Any other value is refused.
const Format = "otsec.linkkey/0.1"

// Bounds on the file, checked before anything is used.
const (
	MaxFileBytes = 64 << 10
	MaxEntries   = 16
	// MaxVersion is the highest version nodekey.KeyName names.
	MaxVersion = 999999999
)

// KindLinkKey is the one kind of entry the file holds. The node key
// register refuses it, as it refuses any kind it does not know (NK-1).
const KindLinkKey nodekey.Kind = "link-key"

// Each fault of Load wraps one of these. A caller tells them apart with
// errors.Is, for the cause its alarm names.
var (
	ErrMissing           = errors.New("linkkey: the link key file is missing")
	ErrUnreadable        = errors.New("linkkey: the link key file cannot be read")
	ErrMalformed         = errors.New("linkkey: the link key file is malformed")
	ErrEntry             = errors.New("linkkey: the link key entry fails its checks")
	ErrNoKey             = errors.New("linkkey: the provider does not have the link key")
	ErrClash             = errors.New("linkkey: the link key is also a key of the node key register")
	ErrRegisterNotLoaded = errors.New("linkkey: the node key register is set and not loaded, so a clash cannot be checked")
)

var providers = []nodekey.Provider{nodekey.ProviderCNGSoftware, nodekey.ProviderCNGPlatform, nodekey.ProviderLabFiles}

// File is the link key file.
type File struct {
	Format  string  `json:"format"`
	NodeID  string  `json:"node_id"`
	Entries []Entry `json:"entries"`
}

// Entry is one version of the link key.
type Entry struct {
	Ref     string        `json:"ref"`
	Kind    nodekey.Kind  `json:"kind"`
	Version uint32        `json:"version"`
	State   nodekey.State `json:"state"`
	// Provider is where the key is, and PublicKey its public half (PKIX
	// DER). The provider's name for the key is nodekey.KeyName(Ref,
	// Version).
	Provider  nodekey.Provider `json:"provider"`
	PublicKey []byte           `json:"public_key"`
	// Fingerprint is the lowercase hex SHA-256 of PublicKey, recomputed on
	// read. The pin is "sha256:" and the fingerprint.
	Fingerprint string `json:"fingerprint"`
	// InstalledBy is the administrator who made the last change to the
	// entry, a C7 human principal ID; InstalledAt is when, RFC 3339 UTC.
	InstalledBy string `json:"installed_by"`
	InstalledAt string `json:"installed_at"`
}

// Key is the loaded link key.
type Key struct {
	// Signer is the active key, used where it lives.
	Signer crypto.Signer
	// Pin is "sha256:" and the hex SHA-256 of the key's DER
	// SubjectPublicKeyInfo: the pin the handshake offers (NK-4).
	Pin string
	// Entry is the active entry, and Entries every entry of the file, for
	// the node's policy.apply records (NK-3).
	Entry   Entry
	Entries []Entry
}

// RegisterKeys is what Load is told of the node key register: its
// references and its public keys, those of its tls-key entries and of
// every certificate it holds, in every state. The zero value is a register
// that is set and not loaded, which Load refuses.
type RegisterKeys struct {
	loaded bool
	refs   map[string]bool
	keys   []crypto.PublicKey
}

// NoRegister is a node with no key register configured: no key can clash.
func NoRegister() RegisterKeys { return RegisterKeys{loaded: true} }

// FromRegister is the register the node loaded. A nil register, or one
// with a key that does not parse, is a register not loaded.
func FromRegister(r *nodekey.Register) RegisterKeys {
	if r == nil {
		return RegisterKeys{}
	}
	k := RegisterKeys{loaded: true, refs: map[string]bool{}}
	for _, e := range r.Entries {
		k.refs[e.Ref] = true
		if e.PublicKey != nil {
			pub, err := x509.ParsePKIXPublicKey(e.PublicKey)
			if err != nil {
				return RegisterKeys{}
			}
			k.keys = append(k.keys, pub)
		}
		for _, der := range e.Certificates {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return RegisterKeys{}
			}
			k.keys = append(k.keys, c.PublicKey)
		}
	}
	return k
}

// clash refuses a link key entry that names a register reference or a
// register key.
func (k RegisterKeys) clash(e *Entry) error {
	if !k.loaded {
		return ErrRegisterNotLoaded
	}
	if k.refs[e.Ref] {
		return fmt.Errorf("%w: %s is a reference of the register", ErrClash, e.Ref)
	}
	pub, _ := x509.ParsePKIXPublicKey(e.PublicKey) // parse checked it
	for _, rk := range k.keys {
		if eq, ok := rk.(interface{ Equal(crypto.PublicKey) bool }); ok && eq.Equal(pub) {
			return fmt.Errorf("%w: %s's public key is a register key", ErrClash, e.Ref)
		}
	}
	return nil
}

// Load reads the link key file at path for nodeID and opens its active
// key. read reads the file under the protected-file rule, with at most its
// max bytes; keys returns the provider the node may open a key in. Load
// refuses a key that clashes with reg (NK-2) before it opens the key.
func Load(read func(path string, max int64) ([]byte, error), path, nodeID string,
	keys func(nodekey.Provider) (nodekey.Keys, error), reg RegisterKeys) (*Key, error) {
	b, err := read(path, MaxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %v", ErrMissing, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	f, err := parse(b, nodeID)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(f.Entries, func(e Entry) bool { return e.State == nodekey.StateActive })
	if i < 0 {
		return nil, fmt.Errorf("%w: no active version", ErrEntry)
	}
	e := f.Entries[i]
	if err := reg.clash(&e); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, fmt.Errorf("%w: no provider", ErrNoKey)
	}
	p, err := keys(e.Provider)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoKey, e.Provider, err)
	}
	if p == nil || p.Provider() != e.Provider {
		return nil, fmt.Errorf("%w: %s is a %s key and that provider is not available", ErrNoKey, e.Ref, e.Provider)
	}
	name := nodekey.KeyName(e.Ref, e.Version)
	signer, err := p.Open(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoKey, err)
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(spki, e.PublicKey) {
		return nil, fmt.Errorf("%w: the %s key %s is not the key the file names", ErrNoKey, e.Provider, name)
	}
	return &Key{Signer: signer, Pin: "sha256:" + e.Fingerprint, Entry: e, Entries: f.Entries}, nil
}

// parse decodes the file strictly and checks it is nodeID's.
func parse(b []byte, nodeID string) (*File, error) {
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%w: %d bytes, over %d", ErrMalformed, len(b), MaxFileBytes)
	}
	var f File
	if err := collectorwire.DecodeStrict(b, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if f.NodeID != nodeID {
		return nil, fmt.Errorf("%w: the file is for node %q, not %q", ErrMalformed, f.NodeID, nodeID)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Marshal checks the file and encodes it, for an administrator's tool to
// write.
func (f *File) Marshal() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// validate checks the file on its own: its form, every entry, and the
// rules across entries (one reference, a version once, at most one active).
func (f *File) validate() error {
	if f.Format != Format {
		return fmt.Errorf("%w: format %q, want %q", ErrMalformed, f.Format, Format)
	}
	if !node.ID(f.NodeID).Valid() {
		return fmt.Errorf("%w: node_id %q", ErrMalformed, f.NodeID)
	}
	if len(f.Entries) == 0 || len(f.Entries) > MaxEntries {
		return fmt.Errorf("%w: %d entries, want 1 to %d", ErrMalformed, len(f.Entries), MaxEntries)
	}
	versions := map[uint32]bool{}
	active := false
	for i := range f.Entries {
		e := &f.Entries[i]
		if err := e.validate(); err != nil {
			return fmt.Errorf("%w: entries[%d]: %v", ErrEntry, i, err)
		}
		switch {
		case e.Ref != f.Entries[0].Ref:
			return fmt.Errorf("%w: entries[%d]: %s and %s; the file holds one reference", ErrEntry, i, e.Ref, f.Entries[0].Ref)
		case versions[e.Version]:
			return fmt.Errorf("%w: entries[%d]: version %d appears twice", ErrEntry, i, e.Version)
		case e.State == nodekey.StateActive && active:
			return fmt.Errorf("%w: entries[%d]: two active versions", ErrEntry, i)
		}
		versions[e.Version] = true
		active = active || e.State == nodekey.StateActive
	}
	return nil
}

func (e *Entry) validate() error {
	if e.Kind != KindLinkKey {
		return fmt.Errorf("kind %q, want %s", e.Kind, KindLinkKey)
	}
	if !nodekey.RefPattern.MatchString(e.Ref) {
		return fmt.Errorf("ref %q", e.Ref)
	}
	if e.Version == 0 || e.Version > MaxVersion {
		return fmt.Errorf("%s: version %d", e.Ref, e.Version)
	}
	if e.State != nodekey.StateActive && e.State != nodekey.StateRetired {
		return fmt.Errorf("%s: state %q; a link key is active or retired", e.Ref, e.State)
	}
	if !slices.Contains(providers, e.Provider) {
		return fmt.Errorf("%s: provider %q", e.Ref, e.Provider)
	}
	pub, err := x509.ParsePKIXPublicKey(e.PublicKey)
	if ec, ok := pub.(*ecdsa.PublicKey); err != nil || !ok || ec.Curve != elliptic.P256() {
		return fmt.Errorf("%s: public_key is not an ECDSA P-256 key", e.Ref)
	}
	if want := fingerprint(e.PublicKey); e.Fingerprint != want {
		return fmt.Errorf("%s: fingerprint %q is not the recomputed %s", e.Ref, e.Fingerprint, want)
	}
	if err := (authz.Principal{Type: authz.PrincipalHuman, ID: e.InstalledBy}).Validate(); err != nil {
		return fmt.Errorf("%s: installed_by: %v", e.Ref, err)
	}
	if t, err := time.Parse(time.RFC3339, e.InstalledAt); err != nil || t.Location() != time.UTC {
		return fmt.Errorf("%s: installed_at %q is not RFC 3339 UTC", e.Ref, e.InstalledAt)
	}
	return nil
}

func fingerprint(spki []byte) string {
	h := sha256.Sum256(spki)
	return hex.EncodeToString(h[:])
}
