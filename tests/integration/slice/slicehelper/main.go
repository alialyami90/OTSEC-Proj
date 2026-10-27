// Command slicehelper prepares the end-to-end slice run (A6, P2-A6). The
// pytest suite (test_slice_e2e.py) runs it, then starts the real binaries:
// the recording simulator as the SEL-751, otsec-collector, otsec node and
// A6's RELP receiver as the upstream collector, each its own process
// (D2-3). Every value it writes is a test value (D2-5), and every endpoint
// is a loopback simulator (D2-10).
//
//	slicehelper setup -root DIR -sim-port N -relp-port N [-every S]
//	slicehelper install-credential -root DIR      (secret from OTSEC_SLICE_SECRET)
//
// setup writes the node configuration through A5's nodeconfigtest (D2-6),
// the collector's collector.json with a register signed by a key made
// here, and the collector's two stores created an hour in the past, so
// the fresh-state floor (A3 #106) has elapsed: the run stands for a
// collector commissioned earlier, which is the state a site is in. It
// prints a JSON object with the paths the suite needs.
//
// install-credential is the administrator's step: it reads the
// collector's published install key, seals the secret to it, signs the
// credential.install with the administrator's key (C7 0.4, D2-11) and
// leaves it in admin_dir as an admin-request file, which the running node
// relays to the collector (P3-A5, #181). It then waits for node status to
// show the collector's decision. The secret comes from the environment,
// never argv (V-S11). The administrator's key is a test key setup makes
// for the run and pins in collector.json; its seed stays under the run's
// root, outside the collector's data, as the private key stays with the
// administrator.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/seal"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

const (
	nodeID  = "site-a-node1"
	assetID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	// The SEL-751 doc profile answers ID with Figure 7.38, its FID
	// replaced by -profile-fid, and SER with Figure 10.16, whose header
	// serial is this (A6's transcription, documented-example).
	simFID    = "SEL-751-R501-V0-Z104101-D20260910"
	simSerial = "2007XXXXXXXXXXX"
	anchorRef = "relp-ca"
	clientRef = "node-client"
	// The receiver's durable-acknowledgement check (V-S6) is A6's
	// test_relp_receiver.py; the node may use a required target only with
	// such a check on record.
	durableAckRef = "tests/integration/slice/test_relp_receiver.py"
)

// Layout is what setup prints and install-credential reads back.
type Layout struct {
	Root          string `json:"root"`
	NodeConfig    string `json:"node_config"`
	CollectorData string `json:"collector_data"`
	Socket        string `json:"socket"`
	PublicDir     string `json:"public_dir"`
	AdminDir      string `json:"admin_dir"`
	StoreDir      string `json:"store_dir"`
	ServerCert    string `json:"server_cert"`
	ServerKey     string `json:"server_key"`
	CA            string `json:"ca"`
	NodeID        string `json:"node_id"`
	AssetID       string `json:"asset_id"`
	FID           string `json:"fid"`
	Serial        string `json:"serial"`
	CredentialRef string `json:"credential_ref"`
	// AdminKey is the test administrator's Ed25519 seed, made by setup.
	AdminKey string `json:"admin_key"`
	// Syslog listeners (#154), when -syslog-udp or -syslog-tls is set: the
	// asset sends from SyslogSender; the TLS sender proves SenderCert,
	// issued by CA.
	SyslogSender string `json:"syslog_sender,omitempty"`
	SyslogUDP    string `json:"syslog_udp,omitempty"`
	SyslogTLS    string `json:"syslog_tls,omitempty"`
	SenderCert   string `json:"sender_cert,omitempty"`
	SenderKey    string `json:"sender_key,omitempty"`
}

// leaveAdminFile writes an administrator's file into admin_dir as one
// would on Linux, where the rule is the mode: the directory opened for the
// write and closed again (0550), and the file read-only (0440).
func leaveAdminFile(dir, name string, b []byte) error {
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	err := os.WriteFile(filepath.Join(dir, name), b, 0o440)
	if cerr := os.Chmod(dir, 0o550); err == nil {
		err = cerr
	}
	return err
}

// adminPrincipal is the person the test administrator's key speaks for.
var adminPrincipal = authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: slicehelper setup|install-credential|admin-file ...")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	root := fs.String("root", "", "the run's directory")
	simPort := fs.Int("sim-port", 0, "setup: the simulator's Telnet port on 127.0.0.1")
	relpPort := fs.Int("relp-port", 0, "setup: the RELP receiver's port on 127.0.0.1")
	every := fs.Int("every", 60, "setup: the SER schedule interval, seconds")
	repo := fs.String("repo", ".", "setup: the repository root, for the fixtures")
	quotas := fs.String("quota", "", "setup: store quotas to change, class=bytes[,class=bytes] (V-S9, V-S12)")
	syslogUDP := fs.Int("syslog-udp", 0, "setup: a syslog-udp listener on this port of 127.0.0.1 (plaintext)")
	syslogTLS := fs.Int("syslog-tls", 0, "setup: a syslog-tls listener on this port of 127.0.0.1, sender certificate required")
	kind := fs.String("kind", "install", "admin-file: install or revoke")
	name := fs.String("name", "", "admin-file: the file's name, or the <name> in admin-request-<name>.json")
	expires := fs.Duration("expires", 10*time.Minute, "admin-file: the request's lifetime from now (negative: already expired)")
	tamper := fs.Bool("tamper", false, "admin-file: change one payload byte after signing")
	mode := fs.Uint("mode", 0o440, "admin-file: the file's mode")
	bad := fs.String("bad", "", "admin-file: a claim to malform and sign anyway: nonce (21 characters) or key (the envelope's key ID)")
	version := fs.Uint("version", 1, "admin-file: an install's credential version (2 rotates the first)")
	fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "setup":
		err = setup(*root, *repo, *simPort, *relpPort, *every, *quotas, *syslogUDP, *syslogTLS)
	case "install-credential":
		err = installCredential(*root)
	case "admin-file":
		err = adminFile(*root, *kind, *name, *expires, *tamper, *bad, os.FileMode(*mode), uint32(*version))
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "slicehelper:", err)
		os.Exit(1)
	}
}

func setup(root, repo string, simPort, relpPort, every int, quotas string, syslogUDP, syslogTLS int) error {
	if root == "" || simPort == 0 || relpPort == 0 {
		return errors.New("setup needs -root, -sim-port and -relp-port")
	}
	l := Layout{Root: root, NodeID: nodeID, AssetID: assetID, FID: simFID, Serial: simSerial,
		CredentialRef: nodeconfigtest.TestCredentialRef}
	l.CollectorData = filepath.Join(root, "data")
	coll := filepath.Join(l.CollectorData, "collector")
	l.PublicDir = filepath.Join(coll, "public")
	// The administrators' folder both services read clear-suspension.json
	// from (D2-15, #119): on Linux the rule is the mode, 0550, so the test
	// opens it only to leave a file there, as an administrator would.
	l.AdminDir = filepath.Join(l.CollectorData, "config", "admin")
	runDir := filepath.Join(root, "run")
	l.Socket = filepath.Join(runDir, "collector.sock")
	l.StoreDir = filepath.Join(root, "node", "store")
	for _, d := range []string{filepath.Join(coll, "state"), filepath.Join(coll, "credentials"), l.PublicDir, runDir, filepath.Dir(l.StoreDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(l.AdminDir, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(l.AdminDir, 0o550); err != nil {
		return err
	}
	if err := store.CreateDir(l.StoreDir, ""); err != nil {
		return err
	}

	// The node: one simulated SEL-751 and one required RELP/TLS target.
	nc := nodeconfigtest.New(nodeID, l.StoreDir)
	nc.CollectorPipe = l.Socket
	nc.CollectorPublicDir = l.PublicDir
	nc.AdminDir = l.AdminDir
	for _, q := range strings.Split(quotas, ",") {
		if q == "" {
			continue
		}
		class, n, ok := strings.Cut(q, "=")
		v, err := strconv.ParseInt(n, 10, 64)
		if _, known := nc.Store.Quotas[class]; !ok || !known || err != nil {
			return fmt.Errorf("-quota %q: want class=bytes with a class the node configures", q)
		}
		nc.Store.Quotas[class] = v
	}
	nc.AddSEL751(assetID, "127.0.0.1", simPort, every)
	setSerial(nc.Assets[0], simSerial)
	nc.AddRELPTarget("upstream", "127.0.0.1", relpPort, anchorRef, clientRef, durableAckRef, false)
	pki, err := nc.WritePKI("127.0.0.1", anchorRef, clientRef)
	if err != nil {
		return err
	}
	if err := listeners(nc, pki, &l, syslogUDP, syslogTLS); err != nil {
		return err
	}
	if err := nc.LockTLS(); err != nil {
		return err
	}
	l.NodeConfig = filepath.Join(root, "node", "node.json")
	if err := nc.Write(l.NodeConfig); err != nil {
		return err
	}
	// The receiver's server certificate, from the same test CA.
	l.ServerCert, l.ServerKey, l.CA = filepath.Join(root, "relp-server.crt"), filepath.Join(root, "relp-server.key"), filepath.Join(root, "relp-ca.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(pki.Server.PrivateKey)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(nc.TLSDir, anchorRef+".pem"))
	if err != nil {
		return err
	}
	for path, b := range map[string][]byte{
		l.ServerCert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.Server.Certificate[0]}),
		l.ServerKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		l.CA:         caPEM,
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return err
		}
	}

	// The collector: the same asset record, the C1 profile, and the C3
	// register on main, signed by a release key made for this run.
	profile, err := os.ReadFile(filepath.Join(repo, "cmd", "otsec-collector", "testdata", "profile-sel-751-ascii.json"))
	if err != nil {
		return err
	}
	payload, err := os.ReadFile(filepath.Join(repo, "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	env := register.Envelope{Contract: register.ContractID, Algorithm: "ed25519", KeyID: "a6-slice-release",
		Payload: payload, Signature: ed25519.Sign(priv, authz.RegisterSigningInput(payload))}
	// The administrator's key, made for this run: its seed for
	// install-credential, its public half pinned in collector.json.
	adminPub, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	l.AdminKey = filepath.Join(root, "admin-test-key.seed")
	if err := os.WriteFile(l.AdminKey, []byte(base64.StdEncoding.EncodeToString(adminPriv.Seed())), 0o600); err != nil {
		return err
	}
	cfg := map[string]any{
		"format": "otsec.collector-config/0.1", "node_id": nodeID, "policy_version": nc.PolicyVersion,
		"ipc":           map[string]any{"address": l.Socket, "node_peer": strconv.Itoa(os.Getuid())},
		"assets":        []any{nc.Assets[0]},
		"profiles":      []any{json.RawMessage(profile)},
		"trust_anchors": []any{map[string]any{"key_id": "a6-slice-release", "public_key": base64.StdEncoding.EncodeToString(pub), "status": "active"}},
		"registers":     []any{env},
		"admin_keys": []any{map[string]any{"key_id": authz.AdminKeyID(adminPub),
			"public_key": base64.StdEncoding.EncodeToString(adminPub), "principal": adminPrincipal.ID, "status": "active"}},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(coll, "collector.json"), b, 0o600); err != nil {
		return err
	}
	// Both stores, created an hour ago: no first-start marker is needed,
	// and the fresh-state floor has passed.
	aged := time.Now().Add(-time.Hour)
	if err := collector.InitState(filepath.Join(coll, "state", "state.json"), aged); err != nil {
		return err
	}
	if err := collector.InitCredStore(filepath.Join(coll, "credentials", "credentials.json"), nodeID, func() time.Time { return aged }); err != nil {
		return err
	}

	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "layout.json"), out, 0o600); err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// setSerial replaces the declared serial_number, which AddSEL751 writes as
// its own test value, with the one the simulator's SER header prints.
func setSerial(a map[string]any, serial string) {
	for _, at := range a["attributes"].([]any) {
		m := at.(map[string]any)
		if m["name"] != "serial_number" {
			continue
		}
		m["value"] = serial
		for _, o := range m["observations"].([]any) {
			o.(map[string]any)["value"] = serial
		}
	}
}

// adminContext is what an administrator's client reads before signing:
// the run's layout, the collector's published install key and the test
// administrator's key.
type adminContext struct {
	l   Layout
	key struct {
		KeyID       string `json:"key_id"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	priv ed25519.PrivateKey
}

func loadAdmin(root string) (*adminContext, error) {
	b, err := os.ReadFile(filepath.Join(root, "layout.json"))
	if err != nil {
		return nil, err
	}
	a := &adminContext{}
	if err := json.Unmarshal(b, &a.l); err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(a.l.PublicDir, "install-key.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(kb, &a.key); err != nil {
		return nil, err
	}
	seed, err := os.ReadFile(a.l.AdminKey)
	if err != nil {
		return nil, err
	}
	rawSeed, err := base64.StdEncoding.Strict().DecodeString(string(seed))
	if err != nil || len(rawSeed) != ed25519.SeedSize {
		return nil, errors.New("the admin test key is not a base64 Ed25519 seed")
	}
	a.priv = ed25519.NewKeyFromSeed(rawSeed)
	return a, nil
}

// sign makes a signed request of kind, issued now and expiring after
// expires (negative: already expired), with a fresh nonce. An install
// seals OTSEC_SLICE_SECRET to the install key as the reference's version;
// a revoke names the run's credential reference.
func (a *adminContext) sign(kind authz.RequestKind, expires time.Duration, version uint32) (*authz.AdminSigned, []byte, error) {
	admin := adminPrincipal
	nonce := make([]byte, authz.AdminNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	issued := now
	if expires < 0 {
		issued = now.Add(expires - time.Minute)
	}
	p := authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: kind, Principal: admin,
		AdminKeyID: authz.AdminKeyID(a.priv.Public().(ed25519.PublicKey)), NodeID: a.l.NodeID, InstallKeyID: a.key.KeyID,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), IssuedAt: issued.Format(time.RFC3339),
		ExpiresAt: now.Add(expires).Format(time.RFC3339),
	}
	switch kind {
	case authz.KindCredentialInstall:
		secret := []byte(os.Getenv("OTSEC_SLICE_SECRET"))
		if len(secret) == 0 {
			return nil, nil, errors.New("OTSEC_SLICE_SECRET is not set")
		}
		ref := authz.CredentialRef{
			ID: a.l.CredentialRef, AssetID: a.l.AssetID, NodeID: a.l.NodeID, EndpointID: "port1-telnet",
			Transport: authz.TransportTelnet, Purpose: authz.PurposeCollectReadOnly, AccessLevel: "1",
			DownstreamSecurity: authz.DownstreamPlaintext, PlaintextScope: authz.PlaintextLabOnly,
			Version: version, CreatedBy: admin, CreatedAt: now.Format(time.RFC3339),
		}
		// The fingerprint is pinned from the published file here; in
		// production the administrator compares it with the commissioning
		// record first (T-12).
		sealed, err := seal.Seal(seal.InstallKey{KeyID: a.key.KeyID, PublicKey: a.key.PublicKey}, a.key.Fingerprint, ref, secret, nil)
		if err != nil {
			return nil, nil, err
		}
		p.CredentialInstall = &authz.CredentialInstallBody{Ref: ref, Sealed: sealed}
	case authz.KindCredentialRevoke:
		p.CredentialRevoke = &authz.CredentialRevokeBody{RefID: a.l.CredentialRef, Reason: authz.RevokeRotated}
	default:
		return nil, nil, fmt.Errorf("kind %q: only install and revoke", kind)
	}
	signed, err := authz.SignAdminRequest(a.priv, p)
	return signed, nonce, err
}

func installCredential(root string) error {
	a, err := loadAdmin(root)
	if err != nil {
		return err
	}
	l := a.l
	// Under the 15-minute maximum less the 2-minute skew allowance, so a
	// collector clock a little ahead still accepts it (A1 on #146).
	signed, nonce, err := a.sign(authz.KindCredentialInstall, 10*time.Minute, 1)
	if err != nil {
		return err
	}
	file, err := json.Marshal(map[string]any{"schema": node.AdminRequestFileSchema, "kind": authz.KindCredentialInstall, "signed": signed})
	if err != nil {
		return err
	}
	name := "admin-request-install-" + hex.EncodeToString(nonce) + ".json"
	if err := leaveAdminFile(l.AdminDir, name, file); err != nil {
		return err
	}
	// The node relays it within node.RelayEverySeconds; the collector's
	// decision shows in node status.
	var decided node.AdminRequestStatus
	deadline := time.Now().Add(4 * node.RelayEverySeconds * time.Second)
	for decided.State == "" || decided.State == "waiting" {
		if time.Now().After(deadline) {
			return fmt.Errorf("the node did not relay %s within %s (status: %+v)", name, 4*node.RelayEverySeconds*time.Second, decided)
		}
		time.Sleep(250 * time.Millisecond)
		st, err := node.ReadStatus(filepath.Join(l.StoreDir, node.StatusFileName))
		if err != nil {
			continue // the node has not written status yet
		}
		for _, r := range st.AdminRequests {
			if r.File == name {
				decided = r
			}
		}
	}
	if decided.State != "accepted" {
		return fmt.Errorf("credential.install %s: %s (%s)", name, decided.State, decided.Detail)
	}
	fmt.Println(`{"event":"credential-installed","collector_seq":` + strconv.FormatUint(decided.CollectorSeq, 10) + `}`)
	return nil
}

// adminFile leaves one signed admin-request file in admin_dir and returns
// at once (A6, #189): kind install or revoke, expiring after expires
// (negative: already expired), with one payload byte changed after
// signing when tamper is set, written with mode (0440 is the rule; a
// wider mode is a file the node must not read); an install names
// credential version. It prints the file's name,
// its request ID as the node derives it from the bytes (admin- and 16 hex
// digits of their SHA-256) and the nonce.
func adminFile(root, kind, name string, expires time.Duration, tamper bool, bad string, mode os.FileMode, version uint32) error {
	a, err := loadAdmin(root)
	if err != nil {
		return err
	}
	k := map[string]authz.RequestKind{"install": authz.KindCredentialInstall, "revoke": authz.KindCredentialRevoke}[kind]
	signed, _, err := a.sign(k, expires, version)
	if err != nil {
		return err
	}
	var p struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(signed.Payload, &p); err != nil {
		return err
	}
	switch bad {
	case "":
	case "nonce":
		// One character short, and signed again: a valid signature over a
		// payload whose nonce claim the node must not record.
		short := p.Nonce[:len(p.Nonce)-1]
		signed.Payload = []byte(strings.Replace(string(signed.Payload), `"`+p.Nonce+`"`, `"`+short+`"`, 1))
		signed.Signature = ed25519.Sign(a.priv, authz.AdminSigningInput(k, signed.Payload))
		p.Nonce = short
	case "key":
		signed.KeyID = "ed25519-NOT-A-KEY-ID" // outside the signed bytes
	default:
		return fmt.Errorf("-bad %q: nonce or key", bad)
	}
	if tamper {
		// The nonce's first character: the payload stays valid JSON with
		// the same claims' shapes, so only the signature can refuse it.
		i := strings.Index(string(signed.Payload), p.Nonce)
		if p.Nonce[0] == 'A' {
			signed.Payload[i] = 'B'
		} else {
			signed.Payload[i] = 'A'
		}
		p.Nonce = string(signed.Payload[i : i+len(p.Nonce)])
	}
	file, err := json.Marshal(map[string]any{"schema": node.AdminRequestFileSchema, "kind": k, "signed": signed})
	if err != nil {
		return err
	}
	if !strings.HasPrefix(name, "admin-request-") {
		name = "admin-request-" + name + ".json"
	}
	if filepath.Base(name) != name {
		return fmt.Errorf("-name %q: a file name in admin_dir, not a path", name) // A3 on #195
	}
	d := a.l.AdminDir
	if err := os.Chmod(d, 0o750); err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(d, name), file, mode)
	if err == nil {
		err = os.Chmod(filepath.Join(d, name), mode) // past the umask
	}
	if cerr := os.Chmod(d, 0o550); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(file)
	out, _ := json.Marshal(map[string]string{"file": name, "request_id": "admin-" + hex.EncodeToString(sum[:8]), "nonce": p.Nonce})
	fmt.Println(string(out))
	return nil
}

// syslogSender is the asset's address as the node's listeners see it.
const syslogSender = "127.0.0.2"

// listeners adds the Syslog listeners asked for (#154): the asset sends
// from syslogSender on each; the TLS listener's certificate and the
// sender's are issued by the run's test CA, which is also the sender CA set.
func listeners(nc *nodeconfigtest.Config, pki *nodeconfigtest.PKI, l *Layout, udp, tlsPort int) error {
	if udp == 0 && tlsPort == 0 {
		return nil
	}
	l.SyslogSender = syslogSender
	if udp != 0 {
		l.SyslogUDP = fmt.Sprintf("127.0.0.1:%d", udp)
		nc.AddListener("a6-udp", "syslog-udp", l.SyslogUDP)
		nc.AddSyslogSender(assetID, "syslog-udp-a6", "syslog-udp", syslogSender, 0)
	}
	if tlsPort == 0 {
		return nil
	}
	l.SyslogTLS = fmt.Sprintf("127.0.0.1:%d", tlsPort)
	nc.AddListener("a6-tls", "syslog-tls", l.SyslogTLS)
	t := nc.Listeners[len(nc.Listeners)-1].TLS
	t.SenderCARef, t.RequireSenderCert = anchorRef, true
	nc.AddSyslogSender(assetID, "syslog-tls-a6", "syslog-tls", syslogSender, 0)
	if _, err := nc.WriteListenerCredential(pki, t.CredentialRef, "127.0.0.1"); err != nil {
		return err
	}
	cert, err := pki.Issue("a6-syslog-sender", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	l.SenderCert, l.SenderKey = filepath.Join(l.Root, "syslog-sender.crt"), filepath.Join(l.Root, "syslog-sender.key")
	if err := os.WriteFile(l.SenderCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(l.SenderKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
}
