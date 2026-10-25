package collector

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/seal"
)

// CredStoreFormat identifies the credential store file. A file with another
// value is refused.
const CredStoreFormat = "otsec.collector-credentials/0.1"

// MaxCredStoreBytes bounds the credential store file. One entry is under
// 1 KiB, so this holds thousands of credentials, far beyond one node.
const MaxCredStoreBytes = 4 << 20

const storeKeyLen = 32

var errStoreKeyLength = errors.New("store key has the wrong length")

// CredStore is the collector's credential store (A3 credential design,
// sections 3 to 7). It is one file, which holds:
//
//   - the store key, protected for the collector's account only (DPAPI user
//     scope on Windows; see keyProtection);
//   - the collector's X25519 install key, its private half encrypted under
//     the store key;
//   - one entry per credential version: the C7 CredentialRef, its
//     CredentialStatus, the secret encrypted with AES-256-GCM under the
//     store key with authz.SealAAD(ref) as additional data, and the reuse
//     tag (section 6).
//
// Three keys are derived from the store key with HKDF-SHA256, one each for
// the records, the install key and the reuse tags, so no key serves two
// purposes.
//
// Every change is written, flushed and renamed into place before the method
// returns, as for State. A failed write breaks the store: every later call
// fails with ErrStateUnavailable until the collector restarts. Refusals are
// *authz.Refusal values with C7 codes; a store failure wraps
// ErrStateUnavailable. No error, status or result carries a secret or a
// value derived from one.
type CredStore struct {
	path   string
	nodeID string
	now    func() time.Time
	rnd    io.Reader

	mu     sync.Mutex
	doc    credDoc
	broken error

	install  *ecdh.PrivateKey
	records  cipher.AEAD
	reuseKey []byte
}

type credDoc struct {
	Format        string        `json:"format"`
	NodeID        string        `json:"node_id"`
	KeyProtection string        `json:"key_protection"`
	StoreKey      string        `json:"store_key"` // base64 of the protected store key
	InstallKey    installKeyDoc `json:"install_key"`
	Entries       []credEntry   `json:"entries"`
}

type installKeyDoc struct {
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	Nonce      string `json:"nonce"`
	PrivateKey string `json:"private_key"` // AES-256-GCM under the install-key subkey
	CreatedAt  string `json:"created_at"`
}

type credEntry struct {
	Ref    authz.CredentialRef    `json:"ref"`
	Status authz.CredentialStatus `json:"status"`
	// Nonce, Ciphertext and ReuseTag are removed when the version is
	// revoked: that is the destruction of the secret (section 7).
	Nonce      string `json:"nonce,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	ReuseTag   string `json:"reuse_tag,omitempty"`
}

// CredStoreConfig configures OpenCredStore.
type CredStoreConfig struct {
	// NodeID is this node. The store refuses to open for another node, and
	// every credential must name it.
	NodeID string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Rand is the randomness source; nil means crypto/rand. Tests only.
	Rand io.Reader
}

// InitCredStore creates the credential store at path for nodeID: a new
// store key and a new install key. It refuses to overwrite an existing file.
// The installer calls it once, in the directory with the collector's
// protected DACL (W-4); on Windows it must run as the collector's account,
// since DPAPI protects the store key for the calling account.
func InitCredStore(path, nodeID string, now func() time.Time) error {
	if !node.ID(nodeID).Valid() {
		return fmt.Errorf("collector: node id %q is not valid", nodeID)
	}
	if now == nil {
		now = time.Now
	}
	storeKey := make([]byte, storeKeyLen)
	defer clear(storeKey)
	if _, err := io.ReadFull(rand.Reader, storeKey); err != nil {
		return err
	}
	protected, err := protectKey(storeKey)
	if err != nil {
		return fmt.Errorf("collector: protect store key: %w", err)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	wrap, err := subkeyAEAD(storeKey, "install-key")
	if err != nil {
		return err
	}
	pub := priv.PublicKey().Bytes()
	keyID := seal.KeyID(pub)
	nonce := make([]byte, wrap.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	privBytes := priv.Bytes()
	defer clear(privBytes)
	doc := credDoc{
		Format:        CredStoreFormat,
		NodeID:        nodeID,
		KeyProtection: keyProtection,
		StoreKey:      b64(protected),
		InstallKey: installKeyDoc{
			KeyID:      keyID,
			PublicKey:  b64(pub),
			Nonce:      b64(nonce),
			PrivateKey: b64(wrap.Seal(nil, nonce, privBytes, installKeyAAD(keyID))),
			CreatedAt:  now().UTC().Format(time.RFC3339Nano),
		},
		Entries: []credEntry{},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if err := createExclusive(path, b); err != nil {
		return fmt.Errorf("collector: create credential store: %w", err)
	}
	return nil
}

// OpenCredStore reads the credential store. Any failure, including a
// missing file, is ErrStateUnavailable: a missing store at run time is lost
// state, never a first start, because a fresh one would have a new install
// key that no admin has pinned.
func OpenCredStore(path string, cfg CredStoreConfig) (*CredStore, error) {
	fail := func(format string, a ...any) (*CredStore, error) {
		return nil, fmt.Errorf("%w: %s: %s", ErrStateUnavailable, path, fmt.Sprintf(format, a...))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	b, err := readBounded(path, MaxCredStoreBytes)
	if err != nil {
		return fail("%v", err)
	}
	var doc credDoc
	if err := collectorwire.DecodeStrict(b, &doc); err != nil {
		return fail("%v", err)
	}
	switch {
	case doc.Format != CredStoreFormat:
		return fail("format %q", doc.Format)
	case doc.NodeID != cfg.NodeID:
		return fail("store is for node %q, this is %q", doc.NodeID, cfg.NodeID)
	case doc.KeyProtection != keyProtection:
		return fail("store key protection %q; this platform uses %q", doc.KeyProtection, keyProtection)
	case doc.Entries == nil:
		return fail("no entries list")
	}
	protected, err := unb64(doc.StoreKey, 1, 1<<12)
	if err != nil {
		return fail("store key: %v", err)
	}
	storeKey, err := unprotectKey(protected)
	if err != nil {
		return fail("store key: %v", err)
	}
	defer clear(storeKey)
	s := &CredStore{path: path, nodeID: cfg.NodeID, now: cfg.Now, rnd: cfg.Rand, doc: doc}
	if s.install, err = openInstallKey(storeKey, doc.InstallKey); err != nil {
		return fail("install key: %v", err)
	}
	if s.records, err = subkeyAEAD(storeKey, "record"); err != nil {
		return fail("%v", err)
	}
	if s.reuseKey, err = hkdf.Key(sha256.New, storeKey, nil, subkeyInfo("reuse"), 32); err != nil {
		return fail("%v", err)
	}
	if err := checkEntries(doc.Entries, cfg.NodeID); err != nil {
		return fail("%v", err)
	}
	return s, nil
}

func openInstallKey(storeKey []byte, k installKeyDoc) (*ecdh.PrivateKey, error) {
	wrap, err := subkeyAEAD(storeKey, "install-key")
	if err != nil {
		return nil, err
	}
	nonce, err := unb64(k.Nonce, wrap.NonceSize(), wrap.NonceSize())
	if err != nil {
		return nil, err
	}
	ct, err := unb64(k.PrivateKey, 32+16, 32+16)
	if err != nil {
		return nil, err
	}
	pt, err := wrap.Open(nil, nonce, ct, installKeyAAD(k.KeyID))
	if err != nil {
		return nil, errors.New("does not decrypt")
	}
	defer clear(pt)
	priv, err := ecdh.X25519().NewPrivateKey(pt)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	if k.PublicKey != b64(pub) || k.KeyID != seal.KeyID(pub) {
		return nil, errors.New("public key or key id does not match the private key")
	}
	return priv, nil
}

// checkEntries checks the entries on their own: valid references for this
// node, statuses that match them, no version twice, at most one version of
// a reference not revoked, and secret material present exactly when the
// version is not revoked.
func checkEntries(es []credEntry, nodeID string) error {
	type key struct {
		id string
		v  uint32
	}
	seen := map[key]bool{}
	live := map[string]bool{}
	for i, e := range es {
		if err := e.Ref.Validate(); err != nil {
			return fmt.Errorf("entry %d: %v", i, err)
		}
		if e.Ref.NodeID != nodeID {
			return fmt.Errorf("entry %d is for node %q", i, e.Ref.NodeID)
		}
		if err := e.Status.Validate(); err != nil {
			return fmt.Errorf("entry %d: %v", i, err)
		}
		if e.Status.RefID != e.Ref.ID || e.Status.Version != e.Ref.Version {
			return fmt.Errorf("entry %d: status names another credential", i)
		}
		k := key{e.Ref.ID, e.Ref.Version}
		if seen[k] {
			return fmt.Errorf("entry %d: %s version %d appears twice", i, e.Ref.ID, e.Ref.Version)
		}
		seen[k] = true
		if e.Status.State == authz.CredentialRevoked {
			if e.Nonce != "" || e.Ciphertext != "" || e.ReuseTag != "" {
				return fmt.Errorf("entry %d is revoked but still holds its secret", i)
			}
			continue
		}
		if live[e.Ref.ID] {
			return fmt.Errorf("entry %d: %s has two versions that are not revoked", i, e.Ref.ID)
		}
		live[e.Ref.ID] = true
		if _, err := unb64(e.Nonce, 12, 12); err != nil {
			return fmt.Errorf("entry %d nonce: %v", i, err)
		}
		if _, err := unb64(e.Ciphertext, 1+16, authz.MaxSecretLen+16); err != nil {
			return fmt.Errorf("entry %d ciphertext: %v", i, err)
		}
		if _, err := unb64(e.ReuseTag, 32, 32); err != nil {
			return fmt.Errorf("entry %d reuse tag: %v", i, err)
		}
	}
	return nil
}

// InstallKey returns the public install key the node publishes.
func (s *CredStore) InstallKey() seal.InstallKey {
	return seal.InstallKey{KeyID: s.doc.InstallKey.KeyID, PublicKey: s.doc.InstallKey.PublicKey}
}

// Fingerprint returns the install key's fingerprint, for the Event Log and
// the install tool's console.
func (s *CredStore) Fingerprint() string {
	return seal.Fingerprint(s.install.PublicKey().Bytes())
}

// InstallTarget is what the collector knows, from its own configuration and
// never from the request, about the asset a credential is installed for.
type InstallTarget struct {
	// Asset is the asset as enrolled on this node; nil when it is not.
	Asset *asset.Asset
	// Register is the active, verified register package for the asset's
	// family; nil when there is none.
	Register *register.Package
}

// InstallResult is what an accepted install changed, for the audit records.
type InstallResult struct {
	Status authz.CredentialStatus
	// Replaced is the previous version, now revoked with reason rotated and
	// its secret destroyed; nil for a first version.
	Replaced *authz.CredentialStatus
	// SharedWith is the number of other assets whose stored credential holds
	// the same secret, all with the same plaintext scope (section 6).
	SharedWith int
}

// Install checks and stores one credential version (section 4). The checks
// run in this order, and any failure refuses the install and keeps nothing:
//
//  1. the reference is consistent (CredentialRef.Validate);
//  2. it is for this node, and its asset is enrolled here;
//  3. a verified register package is active for the asset's family, and the
//     access level is one it reaches (CheckAccessLevel). This comes after
//     enrollment, not before as in the design note, because the package is
//     chosen by the asset's family;
//  4. the named C1 endpoint belongs to the asset and has the reference's
//     transport, downstream security label and acknowledgement scope;
//  5. the version follows the stored one, and a new version keeps the
//     reference's node, asset, endpoint, transport and access level;
//  6. the secret is sealed to this collector's install key and opens;
//  7. the secret passes ValidateSecret with the family's policy and the
//     register package (so "SER C", "ACC" and anything starting with a
//     command mnemonic are refused);
//  8. the reuse rule (section 6).
//
// A new version revokes the previous one with reason rotated and destroys
// its secret in the same write.
func (s *CredStore) Install(body authz.CredentialInstallBody, t InstallTarget) (InstallResult, error) {
	ref := body.Ref
	if err := ref.Validate(); err != nil {
		return InstallResult{}, refusal(authz.RefuseInvalid, "%v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return InstallResult{}, s.broken
	}

	// 2. Node and enrollment.
	if ref.NodeID != s.nodeID {
		return InstallResult{}, refusal(authz.RefuseCredentialMismatch, "credential is for node %s, this is %s", ref.NodeID, s.nodeID)
	}
	a := t.Asset
	if a == nil || a.AssetID != ref.AssetID || string(a.NodeID) != s.nodeID {
		return InstallResult{}, refusal(authz.RefuseAssetNotEnrolled, "asset %s is not enrolled on this node", ref.AssetID)
	}
	// 3. Register and access level.
	pkg := t.Register
	if pkg == nil {
		return InstallResult{}, refusal(authz.RefuseRegisterUnverified, "no verified register package for the asset")
	}
	if err := authz.CheckAccessLevel(pkg, ref.AccessLevel); err != nil {
		return InstallResult{}, err
	}
	// 4. Endpoint.
	if err := endpointMatches(a, ref); err != nil {
		return InstallResult{}, err
	}
	// 5. Version.
	cur := s.latest(ref.ID)
	if cur < 0 {
		if ref.Version != 1 {
			return InstallResult{}, refusal(authz.RefuseInvalid, "first version of %s must be 1, got %d", ref.ID, ref.Version)
		}
	} else {
		old := s.doc.Entries[cur]
		switch {
		case old.Status.State == authz.CredentialRevoked:
			return InstallResult{}, refusal(authz.RefuseCredentialUnusable, "%s is revoked; install a new reference", ref.ID)
		case ref.Version != old.Ref.Version+1:
			return InstallResult{}, refusal(authz.RefuseInvalid, "next version of %s is %d, got %d", ref.ID, old.Ref.Version+1, ref.Version)
		case ref.NodeID != old.Ref.NodeID || ref.AssetID != old.Ref.AssetID || ref.EndpointID != old.Ref.EndpointID ||
			ref.Transport != old.Ref.Transport || ref.AccessLevel != old.Ref.AccessLevel:
			return InstallResult{}, refusal(authz.RefuseCredentialMismatch, "a new version keeps the reference's asset, endpoint, transport and access level; install a new reference instead")
		}
	}
	// 6. Open the sealed secret.
	if body.Sealed.RecipientKeyID != s.doc.InstallKey.KeyID {
		return InstallResult{}, refusal(authz.RefuseCredentialMismatch, "secret is sealed to install key %q, this collector's is %q", body.Sealed.RecipientKeyID, s.doc.InstallKey.KeyID)
	}
	secret, err := seal.Open(s.install, ref, body.Sealed)
	if err != nil {
		return InstallResult{}, refusal(authz.RefuseSecretRejected, "sealed secret does not open for this reference")
	}
	defer clear(secret)
	// 7. Write-time rules.
	policy, ok := authz.SecretPolicies[pkg.Family]
	if !ok {
		return InstallResult{}, refusal(authz.RefuseSecretRejected, "no secret policy for family %q", pkg.Family)
	}
	if err := authz.ValidateSecret(secret, policy, pkg); err != nil {
		detail := err.Error()
		if bytes.Contains([]byte(detail), secret) {
			detail = authz.ErrSecretRejected.Error() // defence in depth: C7 already keeps the secret out
		}
		return InstallResult{}, refusal(authz.RefuseSecretRejected, "%s", detail)
	}
	// 8. Reuse.
	tag := s.reuseTag(secret)
	sharedAssets := map[string]bool{}
	for _, e := range s.doc.Entries {
		if e.ReuseTag == "" || e.Ref.ID == ref.ID {
			continue
		}
		other, _ := unb64(e.ReuseTag, 32, 32) // checked on open and on write
		if !hmac.Equal(tag, other) {
			continue
		}
		if e.Ref.PlaintextScope != ref.PlaintextScope {
			return InstallResult{}, refusal(authz.RefuseSecretRejected, "this secret is installed under another plaintext scope; a lab-only secret and a non-lab secret are never the same")
		}
		if e.Ref.AssetID != ref.AssetID {
			sharedAssets[e.Ref.AssetID] = true
		}
	}

	nonce := make([]byte, s.records.NonceSize())
	if _, err := io.ReadFull(s.rnd, nonce); err != nil {
		return InstallResult{}, refusal(authz.RefuseStateUnavailable, "no randomness: %v", err)
	}
	now := s.stamp()
	entry := credEntry{
		Ref:        ref,
		Status:     authz.CredentialStatus{RefID: ref.ID, Version: ref.Version, State: authz.CredentialActive, Since: now},
		Nonce:      b64(nonce),
		Ciphertext: b64(s.records.Seal(nil, nonce, secret, authz.SealAAD(ref))),
		ReuseTag:   b64(tag),
	}
	next := s.copyDoc()
	res := InstallResult{Status: entry.Status, SharedWith: len(sharedAssets)}
	if cur >= 0 {
		old := &next.Entries[cur]
		revoke(old, authz.RevokeRotated, now)
		st := old.Status
		res.Replaced = &st
	}
	next.Entries = append(next.Entries, entry)
	if err := s.write(next); err != nil {
		return InstallResult{}, err
	}
	return res, nil
}

// endpointMatches is check 4 of Install.
func endpointMatches(a *asset.Asset, ref authz.CredentialRef) error {
	var ep *asset.Endpoint
	for i := range a.Endpoints {
		if a.Endpoints[i].ID == ref.EndpointID {
			ep = &a.Endpoints[i]
			break
		}
	}
	if ep == nil {
		return refusal(authz.RefuseCredentialMismatch, "asset has no endpoint %q", ref.EndpointID)
	}
	if string(ep.Transport) != string(ref.Transport) {
		return refusal(authz.RefuseCredentialMismatch, "endpoint %s uses %s, credential is for %s", ep.ID, ep.Transport, ref.Transport)
	}
	if string(ep.DownstreamSecurity.Level) != string(ref.DownstreamSecurity) {
		return refusal(authz.RefuseCredentialMismatch, "endpoint %s is labelled %s, credential %s", ep.ID, ep.DownstreamSecurity.Level, ref.DownstreamSecurity)
	}
	if got := ackScope(ep); got != ref.PlaintextScope {
		return refusal(authz.RefuseCredentialMismatch, "endpoint %s acknowledgement scope %q differs from the credential's %q", ep.ID, got, ref.PlaintextScope)
	}
	return nil
}

// ackScope is the endpoint acknowledgement's scope, as C7 names it; empty
// when the endpoint has none.
func ackScope(ep *asset.Endpoint) authz.PlaintextScope {
	if ep.DownstreamSecurity.Acknowledgement == nil {
		return ""
	}
	return authz.PlaintextScope(ep.DownstreamSecurity.Acknowledgement.Scope)
}

// Revoke revokes every version of one reference and destroys their secrets
// (section 7). Revocation is terminal. It returns the statuses it changed.
func (s *CredStore) Revoke(body authz.CredentialRevokeBody) ([]authz.CredentialStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return nil, s.broken
	}
	cur := s.latest(body.RefID)
	if cur < 0 {
		return nil, refusal(authz.RefuseCredentialUnusable, "no credential %s", body.RefID)
	}
	if s.doc.Entries[cur].Status.State == authz.CredentialRevoked {
		return nil, refusal(authz.RefuseCredentialUnusable, "%s is already revoked", body.RefID)
	}
	next := s.copyDoc()
	now := s.stamp()
	var changed []authz.CredentialStatus
	for i := range next.Entries {
		e := &next.Entries[i]
		if e.Ref.ID == body.RefID && e.Status.State != authz.CredentialRevoked {
			revoke(e, body.Reason, now)
			changed = append(changed, e.Status)
		}
	}
	if err := s.write(next); err != nil {
		return nil, err
	}
	return changed, nil
}

// ClearSuspension makes the exact version the admin reviewed usable again
// (section 7). It refuses a version that is not the current one, one that is
// not suspended, and an identity-mismatch suspension, which only a new
// version clears.
func (s *CredStore) ClearSuspension(body authz.CredentialClearSuspBody) (authz.CredentialStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return authz.CredentialStatus{}, s.broken
	}
	cur := s.latest(body.RefID)
	if cur < 0 || s.doc.Entries[cur].Status.State == authz.CredentialRevoked {
		return authz.CredentialStatus{}, refusal(authz.RefuseCredentialUnusable, "no usable credential %s", body.RefID)
	}
	e := s.doc.Entries[cur]
	switch {
	case e.Ref.Version != body.Version:
		return authz.CredentialStatus{}, refusal(authz.RefuseInvalid, "version %d is not the current version %d", body.Version, e.Ref.Version)
	case e.Status.State != authz.CredentialSuspended:
		return authz.CredentialStatus{}, refusal(authz.RefuseInvalid, "%s version %d is not suspended", body.RefID, body.Version)
	case !authz.SuspendReason(e.Status.Reason).ClearableInPlace():
		return authz.CredentialStatus{}, refusal(authz.RefuseCredentialUnusable, "a %s suspension is cleared only by a new version", e.Status.Reason)
	}
	next := s.copyDoc()
	next.Entries[cur].Status = authz.CredentialStatus{RefID: e.Ref.ID, Version: e.Ref.Version, State: authz.CredentialActive, Since: s.stamp()}
	if err := s.write(next); err != nil {
		return authz.CredentialStatus{}, err
	}
	return next.Entries[cur].Status, nil
}

// Suspend suspends one version after a session found a credential fault
// (section 5). Only the current version changes. A suspension already in
// place keeps its reason, except that identity-mismatch replaces any other,
// because it is the one an admin cannot clear in place. changed reports
// whether the status changed and so needs an audit record.
func (s *CredStore) Suspend(refID string, version uint32, reason authz.SuspendReason) (st authz.CredentialStatus, changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return authz.CredentialStatus{}, false, s.broken
	}
	cur := s.latest(refID)
	if cur < 0 || s.doc.Entries[cur].Ref.Version != version {
		return authz.CredentialStatus{}, false, fmt.Errorf("collector: %s version %d is not the current version", refID, version)
	}
	e := s.doc.Entries[cur]
	switch {
	case e.Status.State == authz.CredentialRevoked:
		return e.Status, false, nil
	case e.Status.State == authz.CredentialSuspended &&
		(reason != authz.SuspendIdentityMismatch || e.Status.Reason == string(authz.SuspendIdentityMismatch)):
		return e.Status, false, nil
	}
	next := s.copyDoc()
	next.Entries[cur].Status = authz.CredentialStatus{RefID: refID, Version: version, State: authz.CredentialSuspended, Reason: string(reason), Since: s.stamp()}
	if err := next.Entries[cur].Status.Validate(); err != nil {
		return authz.CredentialStatus{}, false, err
	}
	if err := s.write(next); err != nil {
		return authz.CredentialStatus{}, false, err
	}
	return next.Entries[cur].Status, true, nil
}

// Acquire resolves the current version of a credential for one accepted run
// (section 5). It refuses with credential_unusable a credential that is
// missing, suspended or revoked, or whose stored secret does not decrypt for
// its reference (T-4); with credential_mismatch one whose binding differs
// from use (CredentialRef.Binds); and it applies CheckAccessLevel again at
// every run. The caller closes the handle when the run is over.
func (s *CredStore) Acquire(refID string, use authz.Use, pkg *register.Package) (*SecretHandle, authz.CredentialRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return nil, authz.CredentialRef{}, s.broken
	}
	cur := s.latest(refID)
	if cur < 0 {
		return nil, authz.CredentialRef{}, refusal(authz.RefuseCredentialUnusable, "no credential %s", refID)
	}
	e := s.doc.Entries[cur]
	if e.Status.State != authz.CredentialActive {
		return nil, authz.CredentialRef{}, refusal(authz.RefuseCredentialUnusable, "%s version %d is %s (%s)", refID, e.Ref.Version, e.Status.State, e.Status.Reason)
	}
	if err := e.Ref.Binds(use); err != nil {
		return nil, authz.CredentialRef{}, err
	}
	if err := authz.CheckAccessLevel(pkg, e.Ref.AccessLevel); err != nil {
		return nil, authz.CredentialRef{}, err
	}
	nonce, _ := unb64(e.Nonce, 12, 12) // checked on open and on write
	ct, _ := unb64(e.Ciphertext, 1+16, authz.MaxSecretLen+16)
	pt, err := s.records.Open(nil, nonce, ct, authz.SealAAD(e.Ref))
	if err != nil {
		return nil, authz.CredentialRef{}, refusal(authz.RefuseCredentialUnusable, "stored secret of %s does not decrypt for its reference", refID)
	}
	return &SecretHandle{b: pt}, e.Ref, nil
}

// Status returns the status of every version of one reference, oldest
// first; nil when there is none.
func (s *CredStore) Status(refID string) []authz.CredentialStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []authz.CredentialStatus
	for _, e := range s.doc.Entries {
		if e.Ref.ID == refID {
			out = append(out, e.Status)
		}
	}
	return out
}

// latest returns the index of the highest version of refID, or -1.
func (s *CredStore) latest(refID string) int {
	idx := -1
	for i, e := range s.doc.Entries {
		if e.Ref.ID == refID && (idx < 0 || e.Ref.Version > s.doc.Entries[idx].Ref.Version) {
			idx = i
		}
	}
	return idx
}

func (s *CredStore) reuseTag(secret []byte) []byte {
	m := hmac.New(sha256.New, s.reuseKey)
	m.Write(secret)
	return m.Sum(nil)
}

func (s *CredStore) stamp() string { return s.now().UTC().Format(time.RFC3339Nano) }

func (s *CredStore) copyDoc() credDoc {
	next := s.doc
	next.Entries = append([]credEntry(nil), s.doc.Entries...)
	return next
}

// write replaces the file with next and, only on success, adopts it. Any
// failure breaks the store.
func (s *CredStore) write(next credDoc) error {
	err := checkEntries(next.Entries, s.nodeID)
	var b []byte
	if err == nil {
		b, err = json.Marshal(next)
	}
	if err == nil && len(b) > MaxCredStoreBytes {
		err = fmt.Errorf("store would be %d bytes, limit %d", len(b), MaxCredStoreBytes)
	}
	if err == nil {
		err = replaceFile(s.path, b)
	}
	if err != nil {
		s.broken = fmt.Errorf("%w: write %s: %v", ErrStateUnavailable, s.path, err)
		return s.broken
	}
	s.doc = next
	return nil
}

// revoke marks e revoked and removes its secret material.
func revoke(e *credEntry, reason authz.RevokeReason, now string) {
	e.Status = authz.CredentialStatus{RefID: e.Ref.ID, Version: e.Ref.Version, State: authz.CredentialRevoked, Reason: string(reason), Since: now}
	e.Nonce, e.Ciphertext, e.ReuseTag = "", "", ""
}

func refusal(code authz.RefusalCode, format string, a ...any) *authz.Refusal {
	return &authz.Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

func subkeyInfo(purpose string) string { return "otsec.collector/0.1 store " + purpose }

func subkeyAEAD(storeKey []byte, purpose string) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, storeKey, nil, subkeyInfo(purpose), 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func installKeyAAD(keyID string) []byte {
	return []byte("otsec.collector/0.1 install-key\nkey_id=" + keyID + "\n")
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string, min, max int) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("not strict base64")
	}
	if len(b) < min || len(b) > max {
		return nil, fmt.Errorf("%d bytes, want %d to %d", len(b), min, max)
	}
	return b, nil
}
