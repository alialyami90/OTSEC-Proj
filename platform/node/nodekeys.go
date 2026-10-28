package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/nodekey"
	"otsec.local/otsec/platform/store/protect"
)

// Node keys (credential design section 9, P3-A3). With key_register set,
// every TLS reference of the configuration is a nodekey_ reference and
// resolves from A3's node key register: a target's trust_anchor_ref and
// client_credential_ref, a listener's credential_ref and sender_ca_ref. A
// tls-key's private key stays in its provider. On Windows that is CNG, a
// non-exportable machine key the node service may use (CNG{Users}); the
// lab-files provider, a key in a file, is refused unless lab_tls_files is
// set, as the D2-12 files are.
//
// The node writes a C8 policy.apply record for each register entry it has
// not recorded before: reference, kind, version, state, fingerprint and the
// administrator who installed it. What it has recorded is kept in the store
// directory (NodeKeysFileName). A lost file means the entries are recorded
// again, never that one goes unrecorded.

// ReasonNodeKeyRegister is the reason_code of the policy.apply record of a
// register entry the node loaded.
const ReasonNodeKeyRegister = "node_key_register"

// NodeKeysFileName is the store directory file listing the register
// entries already recorded as policy.apply.
const NodeKeysFileName = "nodekeys.json"

const nodeKeysSchema = "otsec.node-nodekeys/0.1"

// AlarmNodeKeyNotRecorded: a register entry's policy.apply record could
// not be committed. The node tries again at every check until it is.
const AlarmNodeKeyNotRecorded = "node-key-not-recorded"

// AlarmNodeKeyExpiring: an active register entry has a certificate that
// expires within NodeKeyWarning, or has expired. A tls-key or a
// trust-anchors set is refused at resolution once expired, which stops the
// node at its next start.
const AlarmNodeKeyExpiring = "node-key-certificate-expiring"

// NodeKeyWarning is how far ahead a node key's expiry is reported
// (section 9: 30 days).
const NodeKeyWarning = 30 * 24 * time.Hour

// keyStore is the loaded register and the providers its keys may be in.
type keyStore struct {
	reg *nodekey.Register
	// lab is tls_dir when lab_tls_files is set: the lab-files provider's
	// directory. Empty, the provider is refused.
	lab string
}

// nodeKeys loads key_register, once, at the first reference it resolves.
// The node resolves its references from one goroutine at start.
func (c *Config) nodeKeys() (*keyStore, error) {
	if c.keys != nil {
		return c.keys, nil
	}
	if err := protect.CheckDir(filepath.Dir(c.KeyRegister)); err != nil {
		return nil, fmt.Errorf("key_register: %w", err)
	}
	b, err := protect.ReadFile(c.KeyRegister, nodekey.MaxRegisterBytes)
	if err != nil {
		return nil, fmt.Errorf("key_register: %w", err)
	}
	reg, err := nodekey.Parse(b, string(c.NodeID))
	if err != nil {
		return nil, fmt.Errorf("key_register: %w", err)
	}
	ks := &keyStore{reg: reg}
	if c.LabTLSFiles {
		ks.lab = c.TLSDir
	}
	c.keys = ks
	return ks, nil
}

// provider is where an entry's key is to be opened: CNG for the node
// service, or the lab files only behind lab_tls_files.
func (ks *keyStore) provider(p nodekey.Provider) (nodekey.Keys, error) {
	users := []string{collectorwire.ServiceSID(collectorwire.NodeService)}
	switch p {
	case nodekey.ProviderCNGSoftware:
		return nodekey.CNG{Users: users}, nil
	case nodekey.ProviderCNGPlatform:
		return nodekey.CNG{Platform: true, Users: users}, nil
	case nodekey.ProviderLabFiles:
		if ks.lab == "" {
			return nil, errors.New("its key is in a file (lab-files), which needs lab_tls_files and tls_dir")
		}
		return nodekey.LabFiles{Dir: ks.lab}, nil
	}
	return nil, fmt.Errorf("unknown key provider %q", p)
}

// keyCertificate resolves a tls-key reference to a certificate whose key is
// used where it lives. It does not judge the validity period: the TLS
// configuration does, with the clock its stack uses, so an expired or
// not-yet-valid certificate holds back its own link only, as a lab file's
// does (HR-13, D4-11, D4-17). Every other fault, the provider, the key and
// the public key included, is still refused here.
func (c *Config) keyCertificate(ref string) (*tls.Certificate, error) {
	ks, err := c.nodeKeys()
	if err != nil {
		return nil, err
	}
	p, err := ks.providerOf(ref)
	if err != nil {
		return nil, err
	}
	keys, err := ks.provider(p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	cert, _, err := ks.reg.LoadCertificate(ref, keys)
	return cert, err
}

// providerOf is ref's active tls-key provider, as the register names it.
func (ks *keyStore) providerOf(ref string) (nodekey.Provider, error) {
	for _, e := range ks.reg.Entries {
		if e.Ref == ref && e.State == nodekey.StateActive {
			return e.Provider, nil
		}
	}
	return "", fmt.Errorf("nodekey: %s has no active version", ref)
}

// keyAnchors resolves a trust-anchors reference. An expired anchor stays in
// the pool and is never trusted: a verification that chains to it fails on
// the expiry, as for a lab file (D4-11 item 5).
func (c *Config) keyAnchors(ref string) (*x509.CertPool, error) {
	ks, err := c.nodeKeys()
	if err != nil {
		return nil, err
	}
	pool, _, err := ks.reg.LoadTrustAnchors(ref)
	return pool, err
}

// keyLoadTarget is loadTarget from the key register.
func (c *Config) keyLoadTarget(t *syslog.Target) (*targetCreds, error) {
	roots, err := c.keyAnchors(t.TLS.TrustAnchorRef)
	if err != nil {
		return nil, fmt.Errorf("target %s: trust anchors: %w", t.Name, err)
	}
	creds := &targetCreds{roots: roots}
	if ref := t.TLS.ClientCredentialRef; ref != "" {
		if creds.client, err = c.keyCertificate(ref); err != nil {
			return nil, fmt.Errorf("target %s: client credential: %w", t.Name, err)
		}
	}
	return creds, nil
}

// keyLoadListener is loadListener from the key register.
func (c *Config) keyLoadListener(l Listener) (*listenerCreds, error) {
	cert, err := c.keyCertificate(l.TLS.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("listener %s: credential: %w", l.ID, err)
	}
	creds := &listenerCreds{cert: cert}
	if ref := l.TLS.SenderCARef; ref != "" {
		if creds.senders, err = c.keyAnchors(ref); err != nil {
			return nil, fmt.Errorf("listener %s: sender CAs: %w", l.ID, err)
		}
	}
	return creds, nil
}

// nodeKeysFile is NodeKeysFileName: the register entries recorded.
type nodeKeysFile struct {
	Schema   string   `json:"schema"`
	Recorded []string `json:"recorded"`
}

// entryKey names one register entry's state: what a policy.apply record
// is written once for.
func entryKey(e nodekey.Entry) string {
	return fmt.Sprintf("%s %s v%d %s sha256:%s", e.Ref, e.Kind, e.Version, e.State, e.Fingerprint)
}

// RecordNodeKeys writes policy.apply for every register entry the node has
// not recorded, and returns how many are still not recorded. Without
// key_register it does nothing. The register must already be loaded (by
// resolving a reference); one that is not is loaded now.
func (r *Runtime) RecordNodeKeys(ctx context.Context) int {
	if r.cfg.KeyRegister == "" {
		return 0
	}
	ks, err := r.cfg.nodeKeys()
	if err != nil {
		r.opt.Status.Raise("", AlarmNodeKeyNotRecorded, "key register not loaded: "+err.Error())
		return 1
	}
	path := filepath.Join(r.cfg.Store.Dir, NodeKeysFileName)
	done := map[string]bool{}
	f, err := readNodeKeys(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Unreadable: the entries are recorded again, never skipped.
		r.opt.Status.Raise("", AlarmNodeKeyNotRecorded, NodeKeysFileName+" unreadable, every register entry is recorded again: "+err.Error())
	}
	for _, k := range f.Recorded {
		done[k] = true
	}
	left, wrote := 0, false
	for _, e := range ks.reg.Entries {
		k := entryKey(e)
		if done[k] {
			continue
		}
		detail := fmt.Sprintf("nodekey %s installed by %s at %s", k, e.InstalledBy, e.InstalledAt)
		if err := r.commitAudit(ctx, audit.ActionPolicyApply, audit.OutcomeInfo, ReasonNodeKeyRegister, detail); err != nil {
			r.opt.Status.Raise("", AlarmNodeKeyNotRecorded, e.Ref+" version "+fmt.Sprint(e.Version)+" ("+string(e.State)+") not recorded: "+err.Error())
			left++
			continue
		}
		done[k], wrote = true, true
	}
	if wrote {
		if err := writeNodeKeys(path, done); err != nil {
			r.opt.Status.Raise("", AlarmNodeKeyNotRecorded, "the recorded entries are not kept, so they are recorded again at the next start: "+err.Error())
		}
	}
	return left
}

// commitAudit appends one node record and returns its error, where audit
// only alarms.
func (r *Runtime) commitAudit(ctx context.Context, action audit.Action, outcome audit.Outcome, reason, detail string) error {
	_, log, mode := r.view(r.find(AuditDB))
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("audit database %s", r.Mode(AuditDB))
	}
	rec, err := r.AuditRecord(action, outcome, reason, detail)
	if err != nil {
		return err
	}
	_, err = log.Append(ctx, rec)
	return err
}

func readNodeKeys(path string) (nodeKeysFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nodeKeysFile{}, err
	}
	var f nodeKeysFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nodeKeysFile{}, fmt.Errorf("%s: %w", path, err)
	}
	if f.Schema != nodeKeysSchema {
		return nodeKeysFile{}, fmt.Errorf("%s: schema %q", path, f.Schema)
	}
	return f, nil
}

func writeNodeKeys(path string, done map[string]bool) error {
	f := nodeKeysFile{Schema: nodeKeysSchema, Recorded: make([]string, 0, len(done))}
	for k := range done {
		f.Recorded = append(f.Recorded, k)
	}
	sort.Strings(f.Recorded)
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodekeys-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// NodeKeyExpiry is one active register entry with a certificate near or
// past expiry, as node status shows it.
type NodeKeyExpiry struct {
	Ref      string    `json:"ref"`
	Kind     string    `json:"kind"`
	NotAfter time.Time `json:"not_after"`
}

// nodeKeyWatch raises AlarmNodeKeyExpiring once per entry and state
// ("expiring" or "expired") and publishes the expiring entries.
type nodeKeyWatch struct {
	raised map[string]string
}

// CheckNodeKeys reports the register's entries that expire within
// NodeKeyWarning. It is called from one goroutine at a time.
func (r *Runtime) CheckNodeKeys() {
	if r.cfg.KeyRegister == "" || r.cfg.keys == nil {
		return
	}
	now := r.opt.Now()
	if r.keyWatch.raised == nil {
		r.keyWatch.raised = map[string]string{}
	}
	var out []NodeKeyExpiry
	for _, x := range r.cfg.keys.reg.Expiring(now, NodeKeyWarning) {
		out = append(out, NodeKeyExpiry{Ref: x.Ref, Kind: string(x.Kind), NotAfter: x.NotAfter})
		state, detail := "expiring", fmt.Sprintf("%s (%s) has a certificate that expires at %s; install a new version before then", x.Ref, x.Kind, x.NotAfter.Format(time.RFC3339))
		if !now.Before(x.NotAfter) {
			state, detail = "expired", fmt.Sprintf("%s (%s) has a certificate that expired at %s; the node refuses it at its next start", x.Ref, x.Kind, x.NotAfter.Format(time.RFC3339))
		}
		if r.keyWatch.raised[x.Ref] != state {
			r.keyWatch.raised[x.Ref] = state
			r.opt.Status.RaiseTarget("nodekey "+x.Ref, AlarmNodeKeyExpiring, detail)
		}
	}
	r.opt.Status.SetNodeKeys(out)
}

// ReasonLabTLSFiles is the reason_code of the node.posture_change record
// a node with lab_tls_files gets at every start (B3 on #176): its TLS
// private keys may be read from files, which is lab only (D2-12), and is
// as visible as a plaintext listener (D3-5).
const ReasonLabTLSFiles = "lab_tls_files"

// labKeyRefs is the TLS references whose private key this configuration
// reads from a file: every one when there is no key_register, otherwise
// those whose active register entry is in the lab-files provider. It is
// called after the references have resolved at start.
func (c *Config) labKeyRefs() []string {
	var refs []string
	for _, t := range c.targets {
		if t.TLS != nil && t.TLS.ClientCredentialRef != "" {
			refs = append(refs, t.TLS.ClientCredentialRef)
		}
	}
	for _, l := range c.Listeners {
		if l.TLS != nil && l.TLS.CredentialRef != "" {
			refs = append(refs, l.TLS.CredentialRef)
		}
	}
	if c.KeyRegister != "" {
		refs = slices.DeleteFunc(refs, func(ref string) bool {
			if c.keys == nil {
				return true
			}
			p, err := c.keys.providerOf(ref)
			return err != nil || p != nodekey.ProviderLabFiles
		})
	}
	slices.Sort(refs)
	return slices.Compact(refs)
}

// RecordLabTLSFiles writes the lab_tls_files posture record and marks
// status, at every start with the flag set, once every reference has
// resolved.
func (r *Runtime) RecordLabTLSFiles(ctx context.Context) {
	if !r.cfg.LabTLSFiles {
		return
	}
	refs := r.cfg.labKeyRefs()
	r.opt.Status.SetLabTLSFiles(refs)
	from := "no reference of this configuration uses one yet"
	if len(refs) > 0 {
		from = "from files: " + strings.Join(refs, ", ")
		if len(from) > 300 {
			// C8 detail is at most 512 bytes; status lists them all.
			from = from[:300] + fmt.Sprintf("... (%d references; see node status)", len(refs))
		}
	}
	r.audit(ctx, audit.ActionNodePostureChange, audit.OutcomeInfo, ReasonLabTLSFiles,
		"lab_tls_files is set: TLS private keys may be read from files in tls_dir, not a key store (lab only, D2-12); "+from)
}
