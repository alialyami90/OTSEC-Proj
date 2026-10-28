// Package node is the site node's runtime: its configuration, the store
// layout derived from it, startup recovery, alarms and health. It is owned
// by A5 (A1 D2-1). The configuration format is documented in README.md.
package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"otsec.local/otsec/contracts/asset"
	cnode "otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/security/nodekey"
)

// ConfigSchema identifies the node configuration format. It is A5's file
// format, not a shared contract (D2-6): a loader accepts exactly this
// value.
const ConfigSchema = "otsec.nodeconfig/0.1"

// MaxConfigBytes bounds the file the loader reads.
const MaxConfigBytes = 4 << 20

// MinIntervalSeconds is the shortest collection interval. A relay's
// session limits are small (C1 SessionLimits), and SER does not need
// faster polling for the slice.
const MinIntervalSeconds = 60

// Config is a loaded, checked node configuration.
type Config struct {
	Schema    string      `json:"schema"`
	NodeID    cnode.ID    `json:"node_id"`
	Store     StoreConfig `json:"store"`
	Listeners []Listener  `json:"listeners"`
	// SyslogOutageHours is the upstream outage the syslog classes must
	// ride out with listeners' unknown senders storing all the while
	// (ListenerSizings); 0 means DefaultSyslogOutageHours.
	SyslogOutageHours int               `json:"syslog_outage_hours,omitempty"`
	Assets            []json.RawMessage `json:"assets"`
	Targets           []json.RawMessage `json:"targets"`
	Schedule          []Collection      `json:"schedule"`
	CollectorPipe     string            `json:"collector_pipe"`
	// CollectorPeer is the identity the collector must hold (collectorwire
	// Endpoint.Peer). On Windows it may be empty, which means the
	// otsec-collector service SID; on Linux it is the collector's uid.
	CollectorPeer string `json:"collector_peer,omitempty"`
	// PolicyVersion and RegisterVersion are named in every run request.
	// The collector refuses a request whose versions are not its own
	// (policy_version, register_version), so the node never runs against a
	// register it was not commissioned with.
	PolicyVersion   uint64 `json:"policy_version"`
	RegisterVersion uint64 `json:"register_version"`
	// KeyRegister is the node key register, register.json (nodekey,
	// credential design section 9; see "Node keys" in the README). With it,
	// every TLS reference is a nodekey_ reference resolved from it.
	KeyRegister string `json:"key_register,omitempty"`
	// LabTLSFiles is the lab flag for private keys in files: the D2-12
	// files in tls_dir, or, with key_register, the lab-files provider's
	// keys in tls_dir. Without it tls_dir is refused.
	LabTLSFiles bool `json:"lab_tls_files,omitempty"`
	// TLSDir holds the files the TLS references name when there is no key
	// register (D2-12, lab only; see "TLS references" in the README), or
	// the lab-files provider's keys when there is one. It needs
	// lab_tls_files.
	TLSDir string `json:"tls_dir,omitempty"`
	// AdminDir is where an administrator leaves the Phase 2 interim admin
	// files, such as clear-suspension.json (see "Suspensions" in the
	// README). The node and the collector only read it (AdminReaders).
	// Empty means no such file is read, so a suspension cannot be cleared.
	AdminDir string `json:"admin_dir,omitempty"`
	// CollectorPublicDir is where the collector publishes its
	// install-key.json (A3 #106). The node reads the key before every
	// request to find a reinstall (D2-15). Required when anything is
	// scheduled.
	CollectorPublicDir string `json:"collector_public_dir,omitempty"`

	assets  []asset.Asset
	targets []*syslog.Target
	// keys is the loaded key register (nodeKeys).
	keys *keyStore
}

// StoreConfig is where the store lives and how much each class may use.
type StoreConfig struct {
	Dir string `json:"dir"`
	// Quotas maps each C5 stream class to its bytes. Every class the
	// configuration needs must have one; see Layout.
	Quotas       map[string]int64 `json:"quotas"`
	WarnFraction float64          `json:"warn_fraction"`
}

// Listener is a Syslog listener on the node (P3-A4; see "Syslog
// listeners" in the README).
type Listener struct {
	ID        string          `json:"id"`
	Transport asset.Transport `json:"transport"` // syslog-udp, syslog-tcp or syslog-tls
	Address   string          `json:"address"`   // ip:port the node listens on
	// Target is what is behind the listener: a simulator or a real device
	// network (D1-24 amendment). The loader refuses device-observed (D2-4).
	Target asset.EvidenceClass `json:"target"`
	// Plaintext is the per-listener setting a syslog-tcp or syslog-udp
	// listener must set (owner decision D3-5). Such a listener has no
	// sender authentication or integrity. The loader refuses it on
	// syslog-tls and requires it on the others, so a listener is plaintext
	// only where its own entry says so: no other flag implies it, and an
	// entry without it is TLS. Health shows it, and every start records it
	// as node.posture_change.
	Plaintext bool `json:"plaintext,omitempty"`
	// TLS is a syslog-tls listener's references, required for that
	// transport and refused for the others.
	TLS *ListenerTLS `json:"tls,omitempty"`
	// ReadBuffer is a syslog-udp listener's socket receive buffer in bytes
	// (SO_RCVBUF); 0 keeps the OS default. A datagram that arrives while
	// the buffer is full is lost before the listener reads it and counted
	// by no one but the OS, so a device that sends bursts needs a larger
	// buffer. Health shows what the OS granted. It is refused on a stream
	// listener, which has TCP flow control instead.
	ReadBuffer int `json:"read_buffer_bytes,omitempty"`
}

// The bounds of Listener.ReadBuffer, as receive.Limits.ReadBuffer's.
const (
	MinReadBuffer = 4 << 10
	MaxReadBuffer = 256 << 20
)

// ListenerTLS names a TLS listener's files in tls_dir, as a target's
// references do (D2-12, lab only, until A3's node key store; see "TLS
// references" in the README).
type ListenerTLS struct {
	// CredentialRef names the listener's certificate chain
	// (<ref>.crt) and its key (<ref>.key).
	CredentialRef string `json:"credential_ref"`
	// SenderCARef names the CA set a sender's certificate must chain to
	// (<ref>.pem). Empty: no sender certificate is asked for.
	SenderCARef string `json:"sender_ca_ref,omitempty"`
	// RequireSenderCert refuses a sender that presents no certificate. It
	// needs SenderCARef.
	RequireSenderCert bool `json:"require_sender_cert,omitempty"`
}

// Collection is one scheduled adapter run.
type Collection struct {
	// ID is the schedule principal the runs are made on behalf of (C7
	// PrincipalSchedule). It names the schedule in every audit record.
	ID      string `json:"id"`
	AssetID string `json:"asset_id"`
	// Endpoint is the asset's endpoint ID the collector connects to.
	Endpoint string `json:"endpoint"`
	// Operation is the C3 register operation ID, for example
	// "sel.ser.read_all". The collector checks it against the signed
	// register; the node only names it.
	Operation string `json:"operation"`
	// Params are the operation's parameters; the collector checks them
	// against the register's grammar.
	Params map[string]string `json:"params,omitempty"`
	// CredentialRef is the C7 credential reference for an operation above
	// access level 0, absent for a level 0 operation (C7-A2-5). It is a
	// handle only; no secret is in the configuration.
	CredentialRef string `json:"credential_ref,omitempty"`
	EverySeconds  int    `json:"every_seconds"`
}

var (
	tokenPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	tlsRefPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

// LoadConfig reads and checks the configuration at path.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(f, MaxConfigBytes+1)); err != nil {
		return nil, err
	}
	if buf.Len() > MaxConfigBytes {
		return nil, fmt.Errorf("node config %s is larger than %d bytes", path, MaxConfigBytes)
	}
	return ParseConfig(buf.Bytes())
}

// ParseConfig decodes and checks a configuration. Decoding is strict: an
// unknown field, a duplicate or case-variant key, or data after the object
// is refused. Assets are C1 records (asset.Decode) and targets are C6
// targets (syslog.ParseTarget), each with its own contract's checks.
func ParseConfig(b []byte) (*Config, error) {
	if err := checkKeys(b); err != nil {
		return nil, fmt.Errorf("node config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("node config: %w", err)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("node config: %w", err)
	}
	return &c, nil
}

func (c *Config) check() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Schema != ConfigSchema {
		fail("schema %q, want %q", c.Schema, ConfigSchema)
	}
	if !c.NodeID.Valid() {
		fail("node_id %q is not a lowercase DNS label", c.NodeID)
	}
	if !filepath.IsAbs(c.Store.Dir) {
		fail("store.dir %q is not an absolute path", c.Store.Dir)
	}
	if !(c.Store.WarnFraction > 0 && c.Store.WarnFraction < 1) {
		fail("store.warn_fraction %v not in (0,1)", c.Store.WarnFraction)
	}
	for class, n := range c.Store.Quotas {
		if !knownClass(class) {
			fail("store.quotas: unknown class %q", class)
		} else if n <= 0 {
			fail("store.quotas.%s must be positive", class)
		}
	}
	if c.SyslogOutageHours < 0 || c.SyslogOutageHours > MaxSyslogOutageHours {
		fail("syslog_outage_hours %d not in [0, %d]", c.SyslogOutageHours, MaxSyslogOutageHours)
	} else if len(c.Listeners) > 0 && len(errs) == 0 {
		if _, err := c.ListenerSizings(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := checkPipe(c.CollectorPipe); err != nil {
		errs = append(errs, err)
	}
	if runtime.GOOS != "windows" && c.CollectorPeer == "" {
		fail("collector_peer is required on %s: the collector's uid", runtime.GOOS)
	}
	if c.PolicyVersion == 0 || c.RegisterVersion == 0 {
		fail("policy_version and register_version must be at least 1")
	}

	ids := map[string]bool{}
	for i, l := range c.Listeners {
		p := fmt.Sprintf("listeners[%d]", i)
		if !tokenPattern.MatchString(l.ID) || ids[l.ID] {
			fail("%s.id %q is not a unique token", p, l.ID)
		}
		ids[l.ID] = true
		if !l.Transport.Inbound() {
			fail("%s.transport %q is not a Syslog transport", p, l.Transport)
		}
		if ap, err := netip.ParseAddrPort(l.Address); err != nil {
			fail("%s.address %q is not ip:port", p, l.Address)
		} else if !loopback(ap.Addr().String()) {
			fail("%s.address %q: %w", p, l.Address, ErrNotLoopback)
		}
		if err := checkTarget(p, l.Target); err != nil {
			errs = append(errs, err)
		}
		switch {
		case l.Transport == asset.SyslogTLS && l.Plaintext:
			fail("%s.plaintext is set on a syslog-tls listener", p)
		case l.Transport == asset.SyslogTLS && l.TLS == nil:
			fail("%s: a syslog-tls listener needs a tls section", p)
		case l.Transport != asset.SyslogTLS && l.TLS != nil:
			fail("%s.tls is set on a %s listener", p, l.Transport)
		case l.Transport.Inbound() && l.Transport != asset.SyslogTLS && !l.Plaintext:
			fail("%s: a %s listener has no sender authentication or integrity and needs \"plaintext\": true (D3-5)", p, l.Transport)
		}
		switch {
		case l.ReadBuffer != 0 && l.Transport != asset.SyslogUDP:
			fail("%s.read_buffer_bytes is set on a %s listener; it applies to syslog-udp only", p, l.Transport)
		case l.ReadBuffer != 0 && (l.ReadBuffer < MinReadBuffer || l.ReadBuffer > MaxReadBuffer):
			fail("%s.read_buffer_bytes %d is not 0 or in [%d, %d]", p, l.ReadBuffer, MinReadBuffer, MaxReadBuffer)
		}
		if l.TLS != nil {
			if l.TLS.RequireSenderCert && l.TLS.SenderCARef == "" {
				fail("%s.tls.require_sender_cert needs sender_ca_ref", p)
			}
			for field, ref := range map[string]string{"credential_ref": l.TLS.CredentialRef, "sender_ca_ref": l.TLS.SenderCARef} {
				if ref == "" && field == "sender_ca_ref" {
					continue
				}
				if err := c.checkTLSRef(ref); err != nil {
					fail("%s.tls.%s %v", p, field, err)
				}
			}
		}
	}

	c.assets = c.assets[:0]
	byID := map[string]asset.Asset{}
	for i, raw := range c.Assets {
		a, err := asset.Decode(raw)
		if err != nil {
			fail("assets[%d]: %v", i, err)
			continue
		}
		if _, dup := byID[a.AssetID]; dup {
			fail("assets[%d]: asset %s listed twice", i, a.AssetID)
		}
		for j, ep := range a.Endpoints {
			p := fmt.Sprintf("assets[%d].endpoints[%d]", i, j)
			if err := checkTarget(p, ep.Target); err != nil {
				errs = append(errs, err)
			}
			// An inbound Syslog endpoint names the device as a sender; every
			// other endpoint is one a collector connects to (D2-10).
			if !ep.Transport.Inbound() && !loopback(ep.Host) {
				fail("%s.host %q: %w", p, ep.Host, ErrNotLoopback)
			}
		}
		byID[a.AssetID] = a
		c.assets = append(c.assets, a)
	}
	if err := asset.CheckSenders(c.assets); err != nil {
		errs = append(errs, err)
	}

	c.targets = c.targets[:0]
	names := map[string]bool{}
	for i, raw := range c.Targets {
		t, err := syslog.ParseTarget(raw)
		if err != nil {
			fail("targets[%d]: %v", i, err)
			continue
		}
		if names[t.Name] {
			fail("targets[%d]: name %q used twice", i, t.Name)
		}
		names[t.Name] = true
		c.targets = append(c.targets, t)
		if t.TLS == nil {
			continue
		}
		// A reference names a file in tls_dir, so it may not hold a path.
		for field, ref := range map[string]string{"trust_anchor_ref": t.TLS.TrustAnchorRef, "client_credential_ref": t.TLS.ClientCredentialRef} {
			if ref == "" {
				continue
			}
			if err := c.checkTLSRef(ref); err != nil {
				fail("targets[%d].tls.%s %v", i, field, err)
			}
		}
	}
	if c.TLSDir != "" && !filepath.IsAbs(c.TLSDir) {
		fail("tls_dir %q is not an absolute path", c.TLSDir)
	}
	switch {
	case c.TLSDir != "" && !c.LabTLSFiles:
		fail("tls_dir is set without lab_tls_files: a private key in a file is lab only (D2-12; section 9 keys are in key_register)")
	case c.LabTLSFiles && c.TLSDir == "":
		fail("lab_tls_files is set, so tls_dir is required")
	}
	if c.KeyRegister != "" && !filepath.IsAbs(c.KeyRegister) {
		fail("key_register %q is not an absolute path", c.KeyRegister)
	}
	if c.AdminDir != "" && !filepath.IsAbs(c.AdminDir) {
		fail("admin_dir %q is not an absolute path", c.AdminDir)
	}
	if c.CollectorPublicDir != "" && !filepath.IsAbs(c.CollectorPublicDir) {
		fail("collector_public_dir %q is not an absolute path", c.CollectorPublicDir)
	}
	if len(c.Schedule) > 0 && c.CollectorPublicDir == "" {
		fail("collector_public_dir is required when anything is scheduled: the node reads the collector's install key before every request")
	}

	schedules := map[string]bool{}
	for i, s := range c.Schedule {
		p := fmt.Sprintf("schedule[%d]", i)
		if schedules[s.ID] {
			fail("%s.id %q used twice", p, s.ID)
		}
		schedules[s.ID] = true
		// The request is checked as C7 checks it, so a schedule the
		// collector would refuse for its syntax does not load.
		if err := c.runRequest(i, "req-config-check").Validate(); err != nil {
			fail("%s: %v", p, err)
		}
		a, ok := byID[s.AssetID]
		switch {
		case !ok:
			fail("%s: asset %q is not in assets", p, s.AssetID)
		case a.NodeID != c.NodeID:
			// One collecting node per asset (D1-3).
			fail("%s: asset %s is collected by node %s, not %s", p, s.AssetID, a.NodeID, c.NodeID)
		default:
			ep, ok := endpoint(a, s.Endpoint)
			if !ok {
				fail("%s: asset %s has no endpoint %q", p, s.AssetID, s.Endpoint)
			} else if ep.Transport.Inbound() {
				fail("%s: endpoint %q is inbound Syslog, not a collector endpoint", p, s.Endpoint)
			}
		}
		if !operationPattern.MatchString(s.Operation) {
			fail("%s.operation %q is not a register operation ID", p, s.Operation)
		} else if len(s.Operation) > MaxOperationBytes {
			// It is in every event of a read, so it is part of the bound
			// on the evidence database's commit cap (commitcap.go).
			fail("%s.operation is %d bytes, over %d", p, len(s.Operation), MaxOperationBytes)
		}
		if s.EverySeconds < MinIntervalSeconds {
			fail("%s.every_seconds %d below %d", p, s.EverySeconds, MinIntervalSeconds)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if _, err := c.Layout(); err != nil {
		return err
	}
	return nil
}

// ErrDeviceObserved marks a refusal under D2-4.
var ErrDeviceObserved = errors.New("device-observed endpoints and listeners are refused in Phase 2 (D2-4); lifting this needs the owner's authorization of a named lab device")

// ErrNotLoopback marks a refusal under D2-10.
var ErrNotLoopback = errors.New("collection endpoints and listeners must be loopback IP literals in Phase 2 (D2-10); host names, localhost included, are refused, and lifting this needs the owner's authorization of a named lab device")

// windowsDeviceName reports a name Windows opens as a device whatever its
// extension (con.pem is the console), so a TLS reference may not be one
// (D2-12). The open also checks the handle is a file on disk.
func windowsDeviceName(name string) bool {
	switch name {
	case "con", "prn", "aux", "nul":
		return true
	}
	return len(name) == 4 && (name[:3] == "com" || name[:3] == "lpt") && name[3] >= '0' && name[3] <= '9'
}

// loopback reports whether host is a loopback IP literal: an IPv4 address
// in 127.0.0.0/8 or ::1, with no zone and no IPv4-mapped form. A host name
// is never resolved, so the check does not depend on name resolution.
func loopback(host string) bool {
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return false
	}
	return (a.Is4() && a.IsLoopback()) || a == netip.IPv6Loopback()
}

// checkTarget enforces D2-4: in Phase 2 everything behind an endpoint or a
// listener is a simulator. Any other value is refused too, never defaulted
// (D1-24).
func checkTarget(path string, t asset.EvidenceClass) error {
	switch t {
	case asset.Simulated:
		return nil
	case asset.DeviceObserved:
		return fmt.Errorf("%s.target: %w", path, ErrDeviceObserved)
	}
	return fmt.Errorf("%s.target %q is not %s", path, t, asset.Simulated)
}

func checkPipe(p string) error {
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(p, `\\.\pipe\`) || len(p) == len(`\\.\pipe\`) {
			return fmt.Errorf(`collector_pipe %q is not a local pipe name \\.\pipe\<name>`, p)
		}
		return nil
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("collector_pipe %q is not an absolute socket path", p)
	}
	return nil
}

func endpoint(a asset.Asset, id string) (asset.Endpoint, bool) {
	for _, ep := range a.Endpoints {
		if ep.ID == id {
			return ep, true
		}
	}
	return asset.Endpoint{}, false
}

// AssetRecords returns the decoded C1 assets, as a 0.1 reader reads them.
func (c *Config) AssetRecords() []asset.Asset { return append([]asset.Asset{}, c.assets...) }

// ForwardTargets returns the decoded C6 targets.
func (c *Config) ForwardTargets() []*syslog.Target { return append([]*syslog.Target{}, c.targets...) }

// Asset returns the asset with id.
func (c *Config) Asset(id string) (asset.Asset, bool) {
	for _, a := range c.assets {
		if a.AssetID == id {
			return a, true
		}
	}
	return asset.Asset{}, false
}

// checkTLSRef checks one TLS reference against the resolver the
// configuration names: a nodekey_ reference with key_register, otherwise a
// D2-12 file name in tls_dir. The error reads after the field's name.
func (c *Config) checkTLSRef(ref string) error {
	if c.KeyRegister != "" {
		if !nodekey.RefPattern.MatchString(ref) {
			return fmt.Errorf("%q is not a node key reference (%s); with key_register every TLS reference is one", ref, nodekey.RefPattern)
		}
		return nil
	}
	if !tlsRefPattern.MatchString(ref) || windowsDeviceName(ref) {
		return fmt.Errorf("%q is not a reference (%s, and not a Windows device name such as con)", ref, tlsRefPattern)
	}
	if c.TLSDir == "" {
		return errors.New("is set, so key_register, or tls_dir with lab_tls_files, is required")
	}
	return nil
}
