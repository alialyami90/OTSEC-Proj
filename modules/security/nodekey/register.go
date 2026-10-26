package nodekey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/modules/security/collectorwire"
)

// RegisterFormat identifies register.json. Any other value is refused.
const RegisterFormat = "otsec.nodekey-register/0.1"

// Bounds on the register, checked before anything is used.
const (
	MaxRegisterBytes = 1 << 20
	MaxEntries       = 64
	MaxCertificates  = 16
)

// RefPattern is a node key reference: "nodekey_" and 8 to 40 lowercase
// letters or digits (credential design section 9).
var RefPattern = regexp.MustCompile(`^nodekey_[a-z0-9]{8,40}$`)

// Kind is what an entry holds.
type Kind string

const (
	// KindTLSKey is a key the node signs with and, once installed, its
	// certificate chain: a forwarding target's client_credential_ref, or a
	// Syslog listener's certificate. The consumer checks the certificate's
	// use (forward.ClientTLS, receive.ServerTLS).
	KindTLSKey Kind = "tls-key"
	// KindTrustAnchors is a CA set, or one peer certificate, that verifies
	// a peer: a target's trust_anchor_ref, or a listener's sender CAs.
	KindTrustAnchors Kind = "trust-anchors"
)

// State is an entry's place in its reference's life.
type State string

const (
	// StatePending: a tls-key whose key exists and whose certificate is
	// not installed yet. It is never resolved.
	StatePending State = "pending"
	// StateActive: the version a reference resolves to. A reference has at
	// most one.
	StateActive State = "active"
	// StateRetired: replaced or withdrawn. Kept so the fingerprint a C8
	// record names can still be looked up; never resolved.
	StateRetired State = "retired"
)

// Register is register.json: the node's key register.
type Register struct {
	Format  string  `json:"format"`
	NodeID  string  `json:"node_id"`
	Entries []Entry `json:"entries"`
}

// Entry is one version of one reference.
type Entry struct {
	Ref     string `json:"ref"`
	Kind    Kind   `json:"kind"`
	Version uint32 `json:"version"`
	State   State  `json:"state"`
	// Provider and PublicKey are on tls-key only: where its key is, and
	// the key's public half (PKIX DER).
	Provider  Provider `json:"provider,omitempty"`
	PublicKey []byte   `json:"public_key,omitempty"`
	// Certificates are DER. For a tls-key, the chain, leaf first, absent
	// while pending. For trust-anchors, the set.
	Certificates [][]byte `json:"certificates,omitempty"`
	// Fingerprint is lowercase hex SHA-256: of PublicKey for a tls-key (it
	// names the key from its request on), of the certificates' DER
	// concatenated in order for trust-anchors. It is recomputed on read.
	Fingerprint string `json:"fingerprint"`
	// InstalledBy is the administrator who made the last change to the
	// entry, a C7 human principal ID; InstalledAt is when, RFC 3339 UTC.
	InstalledBy string `json:"installed_by"`
	InstalledAt string `json:"installed_at"`
}

// NewRegister is an empty register for nodeID.
func NewRegister(nodeID string) *Register {
	return &Register{Format: RegisterFormat, NodeID: nodeID, Entries: []Entry{}}
}

// Parse decodes register.json strictly and checks it is the register of
// nodeID. Any error refuses the whole register: no entry of a register
// with a bad one is used.
func Parse(b []byte, nodeID string) (*Register, error) {
	if len(b) > MaxRegisterBytes {
		return nil, fmt.Errorf("nodekey: register is %d bytes, over %d", len(b), MaxRegisterBytes)
	}
	var r Register
	if err := collectorwire.DecodeStrict(b, &r); err != nil {
		return nil, fmt.Errorf("nodekey: register: %w", err)
	}
	if r.NodeID != nodeID {
		return nil, fmt.Errorf("nodekey: register is for node %q, not %q", r.NodeID, nodeID)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Marshal checks the register and encodes it for an administrator's tool
// to write.
func (r *Register) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Validate checks the register on its own: every entry, and the rules
// across entries (a version once per reference, at most one active and one
// pending version per reference, one kind per reference).
func (r *Register) Validate() error {
	if r.Format != RegisterFormat {
		return fmt.Errorf("nodekey: register format %q, want %q", r.Format, RegisterFormat)
	}
	if !node.ID(r.NodeID).Valid() {
		return fmt.Errorf("nodekey: register node_id %q", r.NodeID)
	}
	if r.Entries == nil || len(r.Entries) > MaxEntries {
		return fmt.Errorf("nodekey: register needs entries, at most %d", MaxEntries)
	}
	type refState struct {
		kind            Kind
		active, pending bool
		versions        map[uint32]bool
	}
	refs := map[string]*refState{}
	for i := range r.Entries {
		e := &r.Entries[i]
		if err := e.validate(); err != nil {
			return fmt.Errorf("nodekey: entries[%d]: %w", i, err)
		}
		s := refs[e.Ref]
		if s == nil {
			s = &refState{kind: e.Kind, versions: map[uint32]bool{}}
			refs[e.Ref] = s
		}
		switch {
		case s.kind != e.Kind:
			return fmt.Errorf("nodekey: %s is both %s and %s", e.Ref, s.kind, e.Kind)
		case s.versions[e.Version]:
			return fmt.Errorf("nodekey: %s version %d appears twice", e.Ref, e.Version)
		case e.State == StateActive && s.active:
			return fmt.Errorf("nodekey: %s has two active versions", e.Ref)
		case e.State == StatePending && s.pending:
			return fmt.Errorf("nodekey: %s has two pending versions", e.Ref)
		}
		s.versions[e.Version] = true
		s.active = s.active || e.State == StateActive
		s.pending = s.pending || e.State == StatePending
	}
	return nil
}

func (e *Entry) validate() error {
	if !RefPattern.MatchString(e.Ref) {
		return fmt.Errorf("ref %q", e.Ref)
	}
	if e.Version == 0 || e.Version > 999999999 {
		return fmt.Errorf("%s: version %d", e.Ref, e.Version)
	}
	if err := (authz.Principal{Type: authz.PrincipalHuman, ID: e.InstalledBy}).Validate(); err != nil {
		return fmt.Errorf("%s: installed_by: %v", e.Ref, err)
	}
	if t, err := time.Parse(time.RFC3339, e.InstalledAt); err != nil || t.Location() != time.UTC {
		return fmt.Errorf("%s: installed_at %q is not RFC 3339 UTC", e.Ref, e.InstalledAt)
	}
	if len(e.Certificates) > MaxCertificates {
		return fmt.Errorf("%s: %d certificates, at most %d", e.Ref, len(e.Certificates), MaxCertificates)
	}
	certs := make([]*x509.Certificate, len(e.Certificates))
	for i, der := range e.Certificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("%s: certificates[%d] does not parse", e.Ref, i)
		}
		certs[i] = c
	}
	switch e.Kind {
	case KindTLSKey:
		if !slices.Contains(providers, e.Provider) {
			return fmt.Errorf("%s: provider %q", e.Ref, e.Provider)
		}
		pub, err := x509.ParsePKIXPublicKey(e.PublicKey)
		if ec, ok := pub.(*ecdsa.PublicKey); err != nil || !ok || ec.Curve != elliptic.P256() {
			return fmt.Errorf("%s: public_key is not an ECDSA P-256 key", e.Ref)
		}
		switch e.State {
		case StatePending:
			if len(certs) != 0 {
				return fmt.Errorf("%s: a pending key has no certificate", e.Ref)
			}
		case StateActive, StateRetired:
			if len(certs) == 0 {
				return fmt.Errorf("%s: an installed key needs its certificate", e.Ref)
			}
			if !bytes.Equal(certs[0].RawSubjectPublicKeyInfo, e.PublicKey) {
				return fmt.Errorf("%s: the certificate is not for this key", e.Ref)
			}
		default:
			return fmt.Errorf("%s: state %q", e.Ref, e.State)
		}
	case KindTrustAnchors:
		if e.Provider != "" || e.PublicKey != nil {
			return fmt.Errorf("%s: trust-anchors have no provider or public_key", e.Ref)
		}
		if len(certs) == 0 {
			return fmt.Errorf("%s: trust-anchors need a certificate", e.Ref)
		}
		if e.State != StateActive && e.State != StateRetired {
			return fmt.Errorf("%s: trust-anchors are active or retired, not %q", e.Ref, e.State)
		}
	default:
		return fmt.Errorf("%s: kind %q", e.Ref, e.Kind)
	}
	if want := e.fingerprint(); e.Fingerprint != want {
		return fmt.Errorf("%s: fingerprint %q is not the recomputed %s", e.Ref, e.Fingerprint, want)
	}
	return nil
}

func (e *Entry) fingerprint() string {
	h := sha256.New()
	if e.Kind == KindTLSKey {
		h.Write(e.PublicKey)
	} else {
		for _, c := range e.Certificates {
			h.Write(c)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// active returns ref's active entry of kind.
func (r *Register) active(ref string, kind Kind) (*Entry, error) {
	for i := range r.Entries {
		e := &r.Entries[i]
		if e.Ref != ref || e.State != StateActive {
			continue
		}
		if e.Kind != kind {
			return nil, fmt.Errorf("nodekey: %s is %s, not %s", ref, e.Kind, kind)
		}
		return e, nil
	}
	return nil, fmt.Errorf("nodekey: %s has no active version", ref)
}

// TrustAnchors resolves a trust-anchors reference: its certificates as a
// pool, and the entry, whose version and fingerprint the node's C8 record
// names. Every certificate must be valid at now: one expired certificate
// refuses the whole set, so the set of trusted peers never shrinks or
// changes silently, and Expiring reports it 30 days ahead.
func (r *Register) TrustAnchors(ref string, now time.Time) (*x509.CertPool, *Entry, error) {
	e, err := r.active(ref, KindTrustAnchors)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	for i, der := range e.Certificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("nodekey: %s certificates[%d] does not parse", ref, i)
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, nil, fmt.Errorf("nodekey: %s certificates[%d] is valid from %s to %s", ref, i, utc(c.NotBefore), utc(c.NotAfter))
		}
		pool.AddCert(c)
	}
	return pool, e, nil
}

// Certificate resolves a tls-key reference to a certificate whose private
// key is the provider's crypto.Signer: the key is used where it lives and
// never read out. keys must be the entry's provider, the key must be the
// one the register and the certificate name, and the leaf must be valid
// at now.
func (r *Register) Certificate(ref string, keys Keys, now time.Time) (*tls.Certificate, *Entry, error) {
	e, err := r.active(ref, KindTLSKey)
	if err != nil {
		return nil, nil, err
	}
	if keys == nil || keys.Provider() != e.Provider {
		return nil, nil, fmt.Errorf("nodekey: %s is a %s key and that provider is not available", ref, e.Provider)
	}
	leaf, err := x509.ParseCertificate(e.Certificates[0])
	if err != nil {
		return nil, nil, fmt.Errorf("nodekey: %s certificate does not parse", ref)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("nodekey: %s certificate is valid from %s to %s", ref, utc(leaf.NotBefore), utc(leaf.NotAfter))
	}
	signer, err := keys.Open(KeyName(e.Ref, e.Version))
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(spki, e.PublicKey) {
		return nil, nil, fmt.Errorf("nodekey: the %s key %s is not the key the register names", e.Provider, KeyName(e.Ref, e.Version))
	}
	return &tls.Certificate{Certificate: slices.Clone(e.Certificates), PrivateKey: signer, Leaf: leaf}, e, nil
}

// Expiry is an active reference whose earliest certificate expires soon.
type Expiry struct {
	Ref      string
	Kind     Kind
	NotAfter time.Time // the earliest NotAfter among the entry's certificates
}

// Expiring lists the active references with a certificate that expires
// before now+within, for node health (section 9: 30 days ahead). A
// trust-anchors set is listed when any one of its certificates expires
// soon, because TrustAnchors refuses the whole set once one has expired.
func (r *Register) Expiring(now time.Time, within time.Duration) []Expiry {
	var out []Expiry
	for _, e := range r.Entries {
		if e.State != StateActive {
			continue
		}
		var first time.Time
		for _, der := range e.Certificates {
			if c, err := x509.ParseCertificate(der); err == nil && (first.IsZero() || c.NotAfter.Before(first)) {
				first = c.NotAfter
			}
		}
		if !first.IsZero() && first.Before(now.Add(within)) {
			out = append(out, Expiry{Ref: e.Ref, Kind: e.Kind, NotAfter: first.UTC()})
		}
	}
	return out
}

func (r *Register) nextVersion(ref string) uint32 {
	var v uint32
	for _, e := range r.Entries {
		if e.Ref == ref {
			v = max(v, e.Version)
		}
	}
	return v + 1
}

func (r *Register) find(ref string, state State) int {
	return slices.IndexFunc(r.Entries, func(e Entry) bool { return e.Ref == ref && e.State == state })
}

// Request is an administrator's first step for a tls-key: it creates a new
// key in keys, adds it to the register as pending, and returns a PKCS #10
// certificate request, signed by the key, for a CA to issue a certificate
// from. Only the request leaves the provider. Once the request is signed,
// a CNG key gets its final DACL (CNG.Restrict): SYSTEM, Administrators and
// the node service. On any error the key is deleted and the register is
// unchanged.
func (r *Register) Request(keys Keys, ref string, subject pkix.Name, by string, now time.Time) ([]byte, error) {
	if !RefPattern.MatchString(ref) {
		return nil, fmt.Errorf("nodekey: ref %q", ref)
	}
	if i := r.find(ref, StatePending); i >= 0 {
		return nil, fmt.Errorf("nodekey: %s already has a pending version %d", ref, r.Entries[i].Version)
	}
	if i := slices.IndexFunc(r.Entries, func(e Entry) bool { return e.Ref == ref }); i >= 0 && r.Entries[i].Kind != KindTLSKey {
		return nil, fmt.Errorf("nodekey: %s is %s", ref, r.Entries[i].Kind)
	}
	version := r.nextVersion(ref)
	name := KeyName(ref, version)
	signer, err := keys.Create(name)
	if err != nil {
		return nil, err
	}
	csr, entry, err := pendingEntry(signer, keys.Provider(), ref, version, subject, by, now)
	if rk, ok := keys.(restricter); ok && err == nil {
		// The request is signed: the key gets the DACL it keeps.
		err = rk.Restrict(signer)
	}
	if err == nil {
		next := *r
		next.Entries = append(slices.Clone(r.Entries), entry)
		if err = next.Validate(); err == nil {
			*r = next
			return csr, nil
		}
	}
	keys.Delete(name)
	return nil, err
}

func pendingEntry(signer crypto.Signer, p Provider, ref string, version uint32, subject pkix.Name, by string, now time.Time) ([]byte, Entry, error) {
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, Entry{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, signer)
	if err != nil {
		return nil, Entry{}, fmt.Errorf("nodekey: certificate request for %s: %w", ref, err)
	}
	e := Entry{Ref: ref, Kind: KindTLSKey, Version: version, State: StatePending, Provider: p, PublicKey: spki,
		InstalledBy: by, InstalledAt: utc(now)}
	e.Fingerprint = e.fingerprint()
	return csr, e, nil
}

// Install puts the certificate chain a CA issued for ref's pending key in
// the register (leaf first): the pending version becomes active and the
// version it replaces is retired. The leaf must be for the pending key and
// valid at now.
func (r *Register) Install(ref string, chain [][]byte, by string, now time.Time) error {
	i := r.find(ref, StatePending)
	if i < 0 {
		return fmt.Errorf("nodekey: %s has no pending key", ref)
	}
	if len(chain) == 0 {
		return errors.New("nodekey: no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return errors.New("nodekey: the leaf certificate does not parse")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("nodekey: the certificate is valid from %s to %s", utc(leaf.NotBefore), utc(leaf.NotAfter))
	}
	next := *r
	next.Entries = slices.Clone(r.Entries)
	if j := next.find(ref, StateActive); j >= 0 {
		next.Entries[j].State = StateRetired
	}
	e := &next.Entries[i]
	e.State, e.Certificates, e.InstalledBy, e.InstalledAt = StateActive, cloneAll(chain), by, utc(now)
	if err := next.Validate(); err != nil {
		return err
	}
	*r = next
	return nil
}

// SetAnchors installs a new version of a trust-anchors reference and
// retires the one it replaces.
func (r *Register) SetAnchors(ref string, certs [][]byte, by string, now time.Time) error {
	if i := slices.IndexFunc(r.Entries, func(e Entry) bool { return e.Ref == ref }); i >= 0 && r.Entries[i].Kind != KindTrustAnchors {
		return fmt.Errorf("nodekey: %s is %s", ref, r.Entries[i].Kind)
	}
	next := *r
	next.Entries = slices.Clone(r.Entries)
	if j := next.find(ref, StateActive); j >= 0 {
		next.Entries[j].State = StateRetired
	}
	e := Entry{Ref: ref, Kind: KindTrustAnchors, Version: r.nextVersion(ref), State: StateActive,
		Certificates: cloneAll(certs), InstalledBy: by, InstalledAt: utc(now)}
	e.Fingerprint = e.fingerprint()
	next.Entries = append(next.Entries, e)
	if err := next.Validate(); err != nil {
		return err
	}
	*r = next
	return nil
}

// Retire withdraws ref's active version. A target or listener that names
// it is then invalid at load, which the node raises as an alarm; nothing
// falls back.
func (r *Register) Retire(ref string, by string, now time.Time) error {
	i := r.find(ref, StateActive)
	if i < 0 {
		return fmt.Errorf("nodekey: %s has no active version", ref)
	}
	next := *r
	next.Entries = slices.Clone(r.Entries)
	e := &next.Entries[i]
	e.State, e.InstalledBy, e.InstalledAt = StateRetired, by, utc(now)
	if err := next.Validate(); err != nil {
		return err
	}
	*r = next
	return nil
}

func cloneAll(bs [][]byte) [][]byte {
	out := make([][]byte, len(bs))
	for i, b := range bs {
		out[i] = slices.Clone(b)
	}
	return out
}

func utc(t time.Time) string { return t.UTC().Format(time.RFC3339) }
