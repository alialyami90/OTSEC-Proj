// Command slicehelper prepares the end-to-end slice run (A6, P2-A6). The
// pytest suite (test_slice_e2e.py) runs it, then starts the real binaries:
// the recording simulator as the SEL-751, otsec-collector, otsec node and
// A6's RELP receiver as the upstream collector, each its own process
// (D2-3). Every value it writes is a test value (D2-5), and every endpoint
// is a loopback simulator (D2-10).
//
//	slicehelper setup -root DIR -sim-port N -relp-port N [-every S] [-programdata DIR -node-peer SID]
//	slicehelper install-credential -root DIR      (secret from OTSEC_SLICE_SECRET)
//
// setup writes the node configuration through A5's nodeconfigtest (D2-6),
// the collector's collector.json with a register signed by a key made
// here, and the collector's two stores created an hour in the past, so
// the fresh-state floor (A3 #106) has elapsed: the run stands for a
// collector commissioned earlier, which is the state a site is in. It
// prints a JSON object with the paths the suite needs.
//
// With -programdata, setup writes the inputs of the Windows installer
// instead (P3-A5/A6, OTSEC_SLICE_SERVICE=1 in slicerun.py): node.json
// naming the installed layout under that %ProgramData% (platform/winsvc),
// the TLS reference files in a staging folder for the suite to copy into
// the installed tls_dir, and two collector configurations, which differ
// only in ipc.node_peer. The first names -node-peer, the account running
// the suite, because install-credential is sent from that account and the
// collector's pipe admits one peer; the second names the otsec-node
// service. It creates nothing under %ProgramData% and no collector store:
// the installer creates the folders and the installed collector its own
// stores, under its own account.
//
// install-credential is the administrator's step that the node relays in
// production: it reads the collector's published install key, seals the
// secret to it, signs the request with the administrator's key (C7 0.4,
// D2-11) and sends credential.install over the collector socket as a
// human principal. The secret comes from the environment, never argv
// (V-S11). The administrator's key is a test key setup makes for the run
// and pins in collector.json; its seed stays under the run's root, outside
// the collector's data, as the private key stays with the administrator.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/seal"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
	"otsec.local/otsec/platform/winsvc"
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
	// collectorPipe is the installed collector's pipe, as A6's installer
	// check names it (tests/safety/windows_installer/node.template.json).
	collectorPipe = `\\.\pipe\otsec-collector`
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
	// CollectorPeer is the collector's identity, which install-credential
	// requires of the end of the socket or pipe: this account's uid, or
	// the otsec-collector service SID in the installed layout.
	CollectorPeer string `json:"collector_peer"`
	// The installed layout only (-programdata): the installer's inputs,
	// the staged TLS files, and where they go.
	NodeConfigSource     string `json:"node_config_source,omitempty"`
	CollectorConfig      string `json:"collector_config,omitempty"`
	CollectorConfigFinal string `json:"collector_config_final,omitempty"`
	CollectorConfigPath  string `json:"collector_config_path,omitempty"`
	TLSStage             string `json:"tls_stage,omitempty"`
	TLSDir               string `json:"tls_dir,omitempty"`
	// AdminKey is the test administrator's Ed25519 seed, made by setup.
	AdminKey string `json:"admin_key"`
}

// adminPrincipal is the person the test administrator's key speaks for.
var adminPrincipal = authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: slicehelper setup|install-credential ...")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	root := fs.String("root", "", "the run's directory")
	simPort := fs.Int("sim-port", 0, "setup: the simulator's Telnet port on 127.0.0.1")
	relpPort := fs.Int("relp-port", 0, "setup: the RELP receiver's port on 127.0.0.1")
	every := fs.Int("every", 60, "setup: the SER schedule interval, seconds")
	repo := fs.String("repo", ".", "setup: the repository root, for the fixtures")
	quotas := fs.String("quota", "", "setup: store quotas to change, class=bytes[,class=bytes] (V-S9, V-S12)")
	programData := fs.String("programdata", "", "setup: write the Windows installer's inputs for this %ProgramData%")
	nodePeer := fs.String("node-peer", "", "setup with -programdata: the SID of the account that sends install-credential")
	fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "setup":
		if (*programData == "") != (*nodePeer == "") {
			err = errors.New("-programdata and -node-peer are given together or not at all")
			break
		}
		err = setup(*root, *repo, *simPort, *relpPort, *every, *quotas, *programData, *nodePeer)
	case "install-credential":
		err = installCredential(*root)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "slicehelper:", err)
		os.Exit(1)
	}
}

func setup(root, repo string, simPort, relpPort, every int, quotas, programData, nodePeer string) error {
	if root == "" || simPort == 0 || relpPort == 0 {
		return errors.New("setup needs -root, -sim-port and -relp-port")
	}
	l := Layout{Root: root, NodeID: nodeID, AssetID: assetID, FID: simFID, Serial: simSerial,
		CredentialRef: nodeconfigtest.TestCredentialRef}
	installed := programData != ""
	var coll string
	if installed {
		if err := installedLayout(&l, programData); err != nil {
			return err
		}
	} else {
		var err error
		if coll, err = processLayout(&l); err != nil {
			return err
		}
		nodePeer = l.CollectorPeer
	}

	// The node: one simulated SEL-751 and one required RELP/TLS target.
	nc := nodeconfigtest.New(nodeID, l.StoreDir)
	if installed {
		// Written to the staging folder; the suite copies the files into
		// the installed tls_dir, where they inherit its DACL.
		nc.TLSDir = l.TLSStage
	}
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
	if installed {
		nc.TLSDir = l.TLSDir
		if err := nc.Write(l.NodeConfigSource); err != nil {
			return err
		}
	} else {
		if err := nc.LockTLS(); err != nil {
			return err
		}
		if err := nc.Write(l.NodeConfig); err != nil {
			return err
		}
	}
	// The receiver's server certificate, from the same test CA.
	l.ServerCert, l.ServerKey, l.CA = filepath.Join(root, "relp-server.crt"), filepath.Join(root, "relp-server.key"), filepath.Join(root, "relp-ca.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(pki.Server.PrivateKey)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(stageOr(l.TLSStage, nc.TLSDir), anchorRef+".pem"))
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
	collectorConfig := func(peer string) ([]byte, error) {
		return json.MarshalIndent(map[string]any{
			"format": "otsec.collector-config/0.1", "node_id": nodeID, "policy_version": nc.PolicyVersion,
			"ipc":           map[string]any{"address": l.Socket, "node_peer": peer},
			"assets":        []any{nc.Assets[0]},
			"profiles":      []any{json.RawMessage(profile)},
			"trust_anchors": []any{map[string]any{"key_id": "a6-slice-release", "public_key": base64.StdEncoding.EncodeToString(pub), "status": "active"}},
			"registers":     []any{env},
			"admin_keys": []any{map[string]any{"key_id": authz.AdminKeyID(adminPub),
				"public_key": base64.StdEncoding.EncodeToString(adminPub), "principal": adminPrincipal.ID, "status": "active"}},
		}, "", "  ")
	}
	b, err := collectorConfig(nodePeer)
	if err != nil {
		return err
	}
	if installed {
		final, err := collectorConfig(collectorwire.ServiceSID(collectorwire.NodeService))
		if err != nil {
			return err
		}
		for path, b := range map[string][]byte{l.CollectorConfig: b, l.CollectorConfigFinal: final} {
			if err := os.WriteFile(path, b, 0o600); err != nil {
				return err
			}
		}
	} else {
		if err := os.WriteFile(filepath.Join(coll, "collector.json"), b, 0o600); err != nil {
			return err
		}
		// Both stores, created an hour ago: no first-start marker is
		// needed, and the fresh-state floor has passed.
		aged := time.Now().Add(-time.Hour)
		if err := collector.InitState(filepath.Join(coll, "state", "state.json"), aged); err != nil {
			return err
		}
		if err := collector.InitCredStore(filepath.Join(coll, "credentials", "credentials.json"), nodeID, func() time.Time { return aged }); err != nil {
			return err
		}
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

// processLayout lays the run out under its root for processes the suite
// spawns, and returns the collector's folder.
func processLayout(l *Layout) (string, error) {
	l.CollectorData = filepath.Join(l.Root, "data")
	coll := filepath.Join(l.CollectorData, "collector")
	l.PublicDir = filepath.Join(coll, "public")
	// The administrators' folder both services read clear-suspension.json
	// from (D2-15, #119): on Linux the rule is the mode, 0550, so the test
	// opens it only to leave a file there, as an administrator would.
	l.AdminDir = filepath.Join(l.CollectorData, "config", "admin")
	runDir := filepath.Join(l.Root, "run")
	l.Socket = filepath.Join(runDir, "collector.sock")
	l.StoreDir = filepath.Join(l.Root, "node", "store")
	l.NodeConfig = filepath.Join(l.Root, "node", "node.json")
	l.CollectorPeer = strconv.Itoa(os.Getuid())
	for _, d := range []string{filepath.Join(coll, "state"), filepath.Join(coll, "credentials"), l.PublicDir, runDir, filepath.Dir(l.StoreDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(l.AdminDir, 0o750); err != nil {
		return "", err
	}
	if err := os.Chmod(l.AdminDir, 0o550); err != nil {
		return "", err
	}
	return coll, store.CreateDir(l.StoreDir, "")
}

// installedLayout names the installer's layout under programData
// (platform/winsvc) and the run's staging files under the root.
func installedLayout(l *Layout, programData string) error {
	if !filepath.IsAbs(programData) {
		return fmt.Errorf("-programdata %q is not an absolute path", programData)
	}
	l.CollectorData = winsvc.DataDir(programData)
	l.PublicDir = winsvc.PublicDir(programData)
	l.AdminDir = winsvc.AdminDir(programData)
	l.StoreDir = winsvc.StoreDir(programData)
	l.TLSDir = winsvc.TLSDir(programData)
	l.NodeConfig = winsvc.ConfigPath(programData)
	l.CollectorConfigPath = winsvc.CollectorConfigPath(programData)
	l.Socket = collectorPipe
	l.CollectorPeer = collectorwire.ServiceSID(collectorwire.CollectorService)
	inputs := filepath.Join(l.Root, "install")
	l.NodeConfigSource = filepath.Join(inputs, "node.json")
	l.CollectorConfig = filepath.Join(inputs, "collector-install.json")
	l.CollectorConfigFinal = filepath.Join(inputs, "collector.json")
	l.TLSStage = filepath.Join(inputs, "tls")
	return os.MkdirAll(inputs, 0o700)
}

// stageOr is the staging folder when there is one, else dir.
func stageOr(stage, dir string) string {
	if stage != "" {
		return stage
	}
	return dir
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

func installCredential(root string) error {
	secret := []byte(os.Getenv("OTSEC_SLICE_SECRET"))
	if len(secret) == 0 {
		return errors.New("OTSEC_SLICE_SECRET is not set")
	}
	b, err := os.ReadFile(filepath.Join(root, "layout.json"))
	if err != nil {
		return err
	}
	var l Layout
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	var key struct {
		KeyID       string `json:"key_id"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	kb, err := os.ReadFile(filepath.Join(l.PublicDir, "install-key.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(kb, &key); err != nil {
		return err
	}
	admin := adminPrincipal
	seed, err := os.ReadFile(l.AdminKey)
	if err != nil {
		return err
	}
	rawSeed, err := base64.StdEncoding.Strict().DecodeString(string(seed))
	if err != nil || len(rawSeed) != ed25519.SeedSize {
		return errors.New("the admin test key is not a base64 Ed25519 seed")
	}
	adminPriv := ed25519.NewKeyFromSeed(rawSeed)
	ref := authz.CredentialRef{
		ID: l.CredentialRef, AssetID: l.AssetID, NodeID: l.NodeID, EndpointID: "port1-telnet",
		Transport: authz.TransportTelnet, Purpose: authz.PurposeCollectReadOnly, AccessLevel: "1",
		DownstreamSecurity: authz.DownstreamPlaintext, PlaintextScope: authz.PlaintextLabOnly,
		Version: 1, CreatedBy: admin, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	// The fingerprint is pinned from the published file here; in
	// production the administrator compares it with the commissioning
	// record first (T-12).
	sealed, err := seal.Seal(seal.InstallKey{KeyID: key.KeyID, PublicKey: key.PublicKey}, key.Fingerprint, ref, secret, nil)
	if err != nil {
		return err
	}
	client := collectorclient.New(collectorwire.Endpoint{Address: l.Socket, Peer: l.CollectorPeer})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nonce := make([]byte, authz.AdminNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	now := time.Now().UTC()
	signed, err := authz.SignAdminRequest(adminPriv, authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: authz.KindCredentialInstall, Principal: admin,
		AdminKeyID: authz.AdminKeyID(adminPriv.Public().(ed25519.PublicKey)), NodeID: l.NodeID, InstallKeyID: key.KeyID,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), IssuedAt: now.Format(time.RFC3339),
		// Under the 15-minute maximum less the 2-minute skew allowance, so
		// a collector clock a little ahead still accepts it (A1 on #146).
		ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339),
		CredentialInstall: &authz.CredentialInstallBody{Ref: ref, Sealed: sealed},
	})
	if err != nil {
		return err
	}
	resp, err := client.Do(ctx, &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialInstall,
		RequestID: "a6-slice-install", OnBehalfOf: admin, PolicyVersion: 3, AdminSigned: signed})
	if err != nil {
		return err
	}
	if !resp.Reply.Accepted() {
		return fmt.Errorf("credential.install refused: %+v", resp.Reply.Refusal)
	}
	fmt.Println(`{"event":"credential-installed","collector_seq":` + strconv.FormatUint(resp.Reply.CollectorSeq, 10) + `}`)
	return nil
}
