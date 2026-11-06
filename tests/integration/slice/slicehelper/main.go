// Command slicehelper prepares the end-to-end slice run (A6, P2-A6). The
// pytest suite (test_slice_e2e.py) runs it, then starts the real binaries:
// the recording simulator as the SEL-751, otsec-collector, otsec node and
// A6's RELP receiver as the upstream collector, each its own process
// (D2-3). Every value it writes is a test value (D2-5), and every endpoint
// is a loopback simulator (D2-10).
//
//	slicehelper setup -root DIR -sim-port N -relp-port N [-every S] [-programdata DIR]
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
// the installed tls_dir, and the collector configuration, whose
// ipc.node_peer is the otsec-node service. It creates nothing under
// %ProgramData% and no collector store: the installer creates the folders
// and the installed collector its own stores, under its own account.
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
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/seal"
	"otsec.local/otsec/platform/node"
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
	// NodePeer is the node's identity, which the collector requires of
	// the other end of its socket or pipe (ipc.node_peer): this account's
	// uid, or the otsec-node service SID in the installed layout.
	NodePeer string `json:"node_peer"`
	// The installed layout only (-programdata): the installer's inputs,
	// the staged TLS files, and where they go.
	NodeConfigSource string `json:"node_config_source,omitempty"`
	CollectorConfig  string `json:"collector_config,omitempty"`
	TLSStage         string `json:"tls_stage,omitempty"`
	TLSDir           string `json:"tls_dir,omitempty"`
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
	// The GT-INJ Syslog asset (V-M4), when -gtinj-events is set: it sends
	// from GTINJSender to the syslog-udp listener.
	GTINJAsset  string `json:"gtinj_asset,omitempty"`
	GTINJSender string `json:"gtinj_sender,omitempty"`
	// V-M2, when -config-every is set: the asset another device's
	// approval names, and the seed of a second administrator's key that
	// may not sign node.change_approval.
	OtherAsset  string `json:"other_asset,omitempty"`
	OperatorKey string `json:"operator_key,omitempty"`
	// The mixed node (#466), when -snmp-port is set: the SEL-2731M.
	SNMPAsset string `json:"snmp_asset,omitempty"`
	// V-M1, with -gtmib: each GT-MIB case's asset, by case ID.
	GTMIBAssets map[string]string `json:"gtmib_assets,omitempty"`
	// GTMIBNodeConfig is the node configuration with the GT-MIB entries
	// scheduled. node_config leaves them out, so that the credentials can
	// all be installed before any of them runs, and the run restarts the
	// node on this one.
	GTMIBNodeConfig string `json:"gtmib_node_config,omitempty"`
	// V-M7, with -gtadv-row or -gtadv-operators: each GT-ADV row's asset.
	GTADVAssets map[string]string `json:"gtadv_assets,omitempty"`
}

// leaveAdminFile writes an administrator's file into admin_dir as one
// would on Linux, where the rule is the mode: the directory opened for the
// write and closed again (0550), and the file read-only (0440). On Windows
// the rule is the DACL, which the file inherits from the installed
// config\admin, with an elevated account's owner, Administrators.
func leaveAdminFile(dir, name string, b []byte) error {
	if runtime.GOOS == "windows" {
		return os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	err := os.WriteFile(filepath.Join(dir, name), b, 0o440)
	if cerr := os.Chmod(dir, 0o550); err == nil {
		err = cerr
	}
	return err
}

// adminPrincipal is the person the test administrator's key speaks for,
// and operatorPrincipal the second key's (V-M2), who is not an approver.
var (
	adminPrincipal    = authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}
	operatorPrincipal = authz.Principal{Type: authz.PrincipalHuman, ID: "operator@site-a"}
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: slicehelper setup|install-credential|install-gtmib|admin-file|advisory-file|verify-audit ...")
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
	programData := fs.String("programdata", "", "setup: write the Windows installer's inputs for this %ProgramData%")
	gtinj := fs.String("gtinj-events", "", "setup: add the GT-INJ Syslog asset, sending from 127.0.0.4 to the syslog-udp listener, with an event baseline whose params are this events.json's (V-M4)")
	kind := fs.String("kind", "install", "admin-file: install, revoke, baseline-ack or change-approval")
	name := fs.String("name", "", "admin-file: the file's name, or the <name> in admin-request-<name>.json")
	expires := fs.Duration("expires", 10*time.Minute, "admin-file: the request's lifetime from now (negative: already expired)")
	tamper := fs.Bool("tamper", false, "admin-file: change one payload byte after signing")
	mode := fs.Uint("mode", 0o440, "admin-file: the file's mode")
	bad := fs.String("bad", "", "admin-file: a claim to malform and sign anyway: nonce (21 characters) or key (the envelope's key ID)")
	version := fs.Uint("version", 1, "admin-file: an install's credential version (2 rotates the first)")
	digest := fs.String("digest", "", "admin-file: the baseline a baseline-ack acknowledges, or a change-approval is against (V-M4, V-M2)")
	gtinjSER := fs.String("gtinj-ser", "", "setup: give the slice's asset an event baseline whose params are this series' (V-M4's SER half, D4-47)")
	configEvery := fs.Int("config-every", 0, "setup: read the asset's configuration (sel.config.read_all) every this many seconds instead of its SER (V-M2)")
	snmpPort := fs.Int("snmp-port", 0, "setup: add a SEL-2731M polled over SNMPv3 at this port of 127.0.0.1, under its own register package (the mixed node, #466)")
	gtmibFile := fs.String("gtmib", "", "setup: add one SEL-2731M or SEL-2741M per entry of this JSON file, each polled over SNMPv3 at its own GT-MIB agent; install-gtmib: install each entry's credential (V-M1; see gtmib.go)")
	gtmibEvery := fs.Int("gtmib-every", 3600, "setup: with -gtmib, each entry's every_seconds")
	snmpAsset := fs.String("snmp-asset", "", "install-credential: install an snmpv3 credential for this asset instead of the SEL-751's Telnet one; the keys come hex-encoded from OTSEC_SLICE_SECRET_HEX (V-M1)")
	snmpRef := fs.String("snmp-ref", "", "install-credential: with -snmp-asset, the credential reference ID")
	usmEngine := fs.String("usm-engine-id", "", "install-credential: with -snmp-asset, the pinned engine ID in hex")
	usmUser := fs.String("usm-user", "gt-mib", "install-credential: with -snmp-asset, the USM user name")
	usmAuth := fs.String("usm-auth", string(authz.USMAuthHMACSHA256), "install-credential: with -snmp-asset, the USM authentication protocol")
	usmPriv := fs.String("usm-priv", string(authz.USMPrivAES128), "install-credential: with -snmp-asset, the USM privacy protocol")
	snmpUnlisted := fs.Bool("snmp-unlisted", false, "setup: with -snmp-port, leave the SEL-2731M's profile out of register_versions, so its run names the SEL-751's revision")
	baselineKind := fs.String("baseline-kind", "event", "admin-file: a baseline-ack's kind, event (the GT-INJ asset) or configuration (the slice's asset)")
	device := fs.String("device", "self", "admin-file: a change-approval's asset, self (the slice's) or other (V-M2)")
	window := fs.String("window", "", "admin-file: a change-approval's window, start,end in RFC 3339")
	issued := fs.String("issued", "", "admin-file: the request's issued_at in RFC 3339, its expiry -expires after it (default: now)")
	in := fs.String("in", "", "verify-audit: a file of the audit stream's stored records, one base64 line each, in seq order")
	operator := fs.Bool("operator", false, "admin-file: sign with the second administrator's key, which may not sign node.change_approval (V-M2)")
	gtadvRow := fs.String("gtadv-row", "", "setup: make the asset GT-ADV's device-read row of this name, with R9 on and GT-ADV's set in admin_dir (V-M7)")
	assetOn := fs.Bool("asset", false, "setup: the asset module on, R9 off (V-M8's paired run without R9)")
	vm8On := fs.Bool("vm8", false, "setup: R9 on with advisory test key 0 pinned active and test key 2 pinned revoked, and no set (V-M8)")
	setCase := fs.String("case", "valid", "advisory-file: which set file to leave (see advisoryFile)")
	setVersion := fs.Uint64("set-version", 2, "advisory-file: the set's version")
	gtadvOperators := fs.Bool("gtadv-operators", false, "setup: add GT-ADV's operator rows as assets with no schedule, with R9 on and GT-ADV's set in admin_dir (V-M7)")
	fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "setup":
		err = setup(*root, *repo, *simPort, *relpPort, *every, *quotas, *syslogUDP, *syslogTLS, *programData, *gtinj, *gtinjSER, *configEvery, *snmpPort, *snmpUnlisted, *gtadvRow, *gtadvOperators, *vm8On, *assetOn, *gtmibFile, *gtmibEvery)
	case "advisory-file":
		err = advisoryFile(*root, *repo, *setCase, *setVersion)
	case "install-credential":
		var usm *usmInstall
		if *snmpAsset != "" {
			usm = &usmInstall{asset: *snmpAsset, ref: *snmpRef, usm: authz.USM{UserName: *usmUser, Auth: authz.USMAuth(*usmAuth),
				Priv: authz.USMPriv(*usmPriv), EngineID: *usmEngine, SoleDeviceAttested: true}}
		}
		err = installCredential(*root, usm)
	case "install-gtmib":
		err = installGTMIB(*root, *gtmibFile, *usmAuth)
	case "verify-audit":
		err = verifyAudit(*in)
	case "admin-file":
		r := request{expires: *expires, version: uint32(*version), digest: *digest, baselineKind: authz.BaselineKind(*baselineKind), device: *device, operator: *operator}
		if *window != "" {
			w := strings.Split(*window, ",")
			if len(w) != 2 {
				err = fmt.Errorf("-window %q: want start,end", *window)
				break
			}
			r.window = [2]string{w[0], w[1]}
		}
		if *issued != "" {
			if r.issued, err = time.Parse(time.RFC3339, *issued); err != nil {
				break
			}
		}
		err = adminFile(*root, *kind, *name, r, *tamper, *bad, os.FileMode(*mode))
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "slicehelper:", err)
		os.Exit(1)
	}
}

func setup(root, repo string, simPort, relpPort, every int, quotas string, syslogUDP, syslogTLS int, programData, gtinj, gtinjSER string, configEvery, snmpPort int, snmpUnlisted bool, gtadvRow string, gtadvOperators, vm8On, assetOn bool, gtmibFile string, gtmibEvery int) error {
	if root == "" || simPort == 0 || relpPort == 0 {
		return errors.New("setup needs -root, -sim-port and -relp-port")
	}
	if gtinj != "" && gtinjSER != "" {
		// An event baseline-ack names one asset: the GT-INJ one under
		// -gtinj-events, the slice's under -gtinj-ser (sign).
		return errors.New("-gtinj-events and -gtinj-ser cannot be used together")
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
	}

	// The node: one simulated SEL-751 and one required RELP/TLS target.
	payload, err := os.ReadFile(filepath.Join(repo, "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		return err
	}
	reg, err := register.Decode(payload)
	if err != nil {
		return err
	}
	nc := nodeconfigtest.New(nodeID, l.StoreDir)
	// The node names the revision the collector has active: the register's own.
	nc.RegisterVersion = reg.Revision
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
	// In the installed layout the listener's credential is staged with
	// the rest, and reaches config\tls the same way.
	if err := listeners(nc, pki, &l, syslogUDP, syslogTLS); err != nil {
		return err
	}
	if err := gtinjAsset(nc, &l, gtinj); err != nil {
		return err
	}
	if gtinjSER != "" {
		params, err := seriesParams(gtinjSER)
		if err != nil {
			return err
		}
		nc.EventBaselines = append(nc.EventBaselines, nodeconfigtest.EventBaseline{AssetID: assetID, Params: params})
		nc.Store.Quotas["configuration"] = 32 << 20
	}
	if err := configReads(nc, &l, payload, reg.Revision, configEvery); err != nil {
		return err
	}
	snmpProfile, snmpPayload, err := mixedSNMP(nc, &l, repo, snmpPort, snmpUnlisted)
	if err != nil {
		return err
	}
	if gtmibFile != "" {
		if snmpProfile, snmpPayload, err = gtmibAssets(nc, &l, repo, gtmibFile, gtmibEvery, snmpProfile, snmpPayload); err != nil {
			return err
		}
	}
	if err := gtADV(nc, &l, repo, gtadvRow, gtadvOperators); err != nil {
		return err
	}
	if vm8On {
		vm8(nc)
	}
	if assetOn {
		nc.Asset = &struct{}{}
		nc.Store.Quotas["configuration"] = 64 << 20
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
		if len(l.GTMIBAssets) > 0 {
			l.GTMIBNodeConfig = l.NodeConfig + ".gtmib"
			if err := nc.Write(l.GTMIBNodeConfig); err != nil {
				return err
			}
			nc.Schedule = slices.DeleteFunc(nc.Schedule, func(c nodeconfigtest.Collection) bool {
				return slices.Contains(slices.Collect(maps.Values(l.GTMIBAssets)), c.AssetID)
			})
			if snmpPort == 0 {
				// No scheduled asset uses the profile now, and the loader
				// refuses a revision for none.
				delete(nc.RegisterVersions, nodeconfigtest.TestSNMPProfile)
			}
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
	// V-M2 takes the profile that lists sel.config.read_all, which the
	// collector's own tests use; the slice's lists none.
	profileFile := filepath.Join(repo, "cmd", "otsec-collector", "testdata", "profile-sel-751-ascii.json")
	if configEvery != 0 {
		profileFile = filepath.Join(repo, "modules", "security", "collector", "testdata", "profile-sel-751-ascii.json")
	}
	profile, err := os.ReadFile(profileFile)
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
	adminKey := map[string]any{"key_id": authz.AdminKeyID(adminPub),
		"public_key": base64.StdEncoding.EncodeToString(adminPub), "principal": adminPrincipal.ID, "status": "active"}
	assets := []any{nc.Assets[0]}
	admins := []any{adminKey}
	if configEvery != 0 {
		// V-M2: the administrator approves changes and acknowledges
		// configuration baselines; a second one, the operator, may
		// acknowledge but not approve. The other device is enrolled, so an
		// approval for it is accepted for it, and covers nothing here.
		adminKey["kinds"] = append(slices.Clone(authz.DefaultAdminKinds), authz.KindNodeChangeApproval, authz.KindNodeBaselineAck)
		opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		l.OperatorKey = filepath.Join(root, "operator-test-key.seed")
		if err := os.WriteFile(l.OperatorKey, []byte(base64.StdEncoding.EncodeToString(opPriv.Seed())), 0o600); err != nil {
			return err
		}
		admins = append(admins, map[string]any{"key_id": authz.AdminKeyID(opPub),
			"public_key": base64.StdEncoding.EncodeToString(opPub), "principal": operatorPrincipal.ID, "status": "active",
			"kinds": append(slices.Clone(authz.DefaultAdminKinds), authz.KindNodeBaselineAck)})
		for _, a := range nc.Assets {
			if a["asset_id"] == otherAssetID {
				assets = append(assets, a)
			}
		}
	}
	if gtinjSER != "" {
		// V-M4's SER half acknowledges the slice asset's event baseline.
		adminKey["kinds"] = append(slices.Clone(authz.DefaultAdminKinds), authz.KindNodeBaselineAck)
	}
	if gtinj != "" {
		// V-M4 acknowledges the GT-INJ asset's event baseline, which a key
		// with no kinds may not (C7 0.6), and which the collector accepts
		// only for an asset it enrols.
		adminKey["kinds"] = append(slices.Clone(authz.DefaultAdminKinds), authz.KindNodeBaselineAck)
		for _, a := range nc.Assets {
			if a["asset_id"] == gtinjAssetID {
				assets = append(assets, a) // by ID, not position (C3 on #410)
			}
		}
	}
	profiles, registers := []any{json.RawMessage(profile)}, []any{env}
	if snmpPayload != nil {
		// The SEL-2731M's profile and package, signed by the same release
		// key: the collector selects the package by the profile's firmware
		// allowlist (C3 on #461).
		profiles = append(profiles, json.RawMessage(snmpProfile))
		registers = append(registers, register.Envelope{Contract: register.ContractID, Algorithm: "ed25519", KeyID: "a6-slice-release",
			Payload: snmpPayload, Signature: ed25519.Sign(priv, authz.RegisterSigningInput(snmpPayload))})
		for _, a := range nc.Assets {
			if id, _ := a["asset_id"].(string); id == snmpAssetID || slices.Contains(slices.Collect(maps.Values(l.GTMIBAssets)), id) {
				assets = append(assets, a)
			}
		}
	}
	collectorConfig := func(peer string) ([]byte, error) {
		m := map[string]any{
			"format": "otsec.collector-config/0.1", "node_id": nodeID, "policy_version": nc.PolicyVersion,
			"ipc":           map[string]any{"address": l.Socket, "node_peer": peer},
			"assets":        assets,
			"profiles":      profiles,
			"trust_anchors": []any{map[string]any{"key_id": "a6-slice-release", "public_key": base64.StdEncoding.EncodeToString(pub), "status": "active"}},
			"registers":     registers,
			"admin_keys":    admins,
		}
		if len(l.GTMIBAssets) > 0 {
			// One install per GT-MIB asset, and room for the refused
			// ones (U14), which count against the budget too (D3's notes).
			m["install_limit"] = 2*len(l.GTMIBAssets) + 10
		}
		return json.MarshalIndent(m, "", "  ")
	}
	b, err := collectorConfig(l.NodePeer)
	if err != nil {
		return err
	}
	if installed {
		if err := os.WriteFile(l.CollectorConfig, b, 0o600); err != nil {
			return err
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
	l.NodePeer = strconv.Itoa(os.Getuid())
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
	l.Socket = collectorPipe
	l.NodePeer = collectorwire.ServiceSID(collectorwire.NodeService)
	inputs := filepath.Join(l.Root, "install")
	l.NodeConfigSource = filepath.Join(inputs, "node.json")
	l.CollectorConfig = filepath.Join(inputs, "collector.json")
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
	priv      ed25519.PrivateKey
	principal authz.Principal
}

// request is what one signed request says besides its kind: it expires
// after expires (negative: already expired) from issued (zero: now); an
// install names credential version; a baseline-ack names digest, of
// baselineKind; a change-approval names device's configuration baseline
// digest and window (V-M2).
type request struct {
	expires      time.Duration
	issued       time.Time
	version      uint32
	digest       string
	baselineKind authz.BaselineKind
	device       string
	window       [2]string
	usm          *usmInstall
	operator     bool
}

func loadAdmin(root string, operator bool) (*adminContext, error) {
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
	a.principal = adminPrincipal
	keyFile := a.l.AdminKey
	if operator {
		if a.l.OperatorKey == "" {
			return nil, errors.New("-operator: setup made no operator key (it needs -config-every)")
		}
		a.principal, keyFile = operatorPrincipal, a.l.OperatorKey
	}
	seed, err := os.ReadFile(keyFile)
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

// sign makes a signed request of kind as r says, with a fresh nonce. An
// install seals OTSEC_SLICE_SECRET to the install key as the reference's
// version; a revoke names the run's credential reference; an event
// baseline acknowledgement names the GT-INJ asset, a configuration one
// and a change approval the slice's asset (or, for an approval, the other
// device).
func (a *adminContext) sign(kind authz.RequestKind, r request) (*authz.AdminSigned, []byte, error) {
	admin, expires, version, digest := a.principal, r.expires, r.version, r.digest
	nonce := make([]byte, authz.AdminNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	if !r.issued.IsZero() {
		now = r.issued.UTC()
	}
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
		if r.usm != nil {
			ref, secret, err := r.usm.build(a.l.NodeID, version, admin, now)
			if err != nil {
				return nil, nil, err
			}
			sealed, err := seal.Seal(seal.InstallKey{KeyID: a.key.KeyID, PublicKey: a.key.PublicKey}, a.key.Fingerprint, ref, secret, nil)
			if err != nil {
				return nil, nil, err
			}
			p.CredentialInstall = &authz.CredentialInstallBody{Ref: ref, Sealed: sealed}
			break
		}
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
	case authz.KindNodeBaselineAck:
		asset := gtinjAssetID
		// Without the GT-INJ Syslog asset, an event baseline is the slice
		// asset's (-gtinj-ser).
		if r.baselineKind == authz.BaselineConfiguration || a.l.GTINJAsset == "" {
			asset = a.l.AssetID
		}
		p.NodeBaselineAck = &authz.NodeBaselineAckBody{AssetID: asset, Kind: r.baselineKind, BaselineDigest: digest}
	case authz.KindNodeChangeApproval:
		asset := map[string]string{"self": a.l.AssetID, "other": a.l.OtherAsset}[r.device]
		if asset == "" {
			return nil, nil, fmt.Errorf("-device %q: self, or other with -config-every", r.device)
		}
		p.NodeChangeApproval = &authz.NodeChangeApprovalBody{AssetID: asset, BaselineDigest: digest,
			WindowStart: r.window[0], WindowEnd: r.window[1], Reason: "V-M2 test change"}
	default:
		return nil, nil, fmt.Errorf("kind %q: only install, revoke, baseline-ack and change-approval", kind)
	}
	signed, err := authz.SignAdminRequest(a.priv, p)
	return signed, nonce, err
}

func installCredential(root string, usm *usmInstall) error {
	a, err := loadAdmin(root, false)
	if err != nil {
		return err
	}
	l := a.l
	// Under the 15-minute maximum less the 2-minute skew allowance, so a
	// collector clock a little ahead still accepts it (A1 on #146).
	signed, nonce, err := a.sign(authz.KindCredentialInstall, request{expires: 10 * time.Minute, version: 1, usm: usm})
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
	if usm != nil {
		// The node reads only the first 16 files in admin_dir, so a
		// relayed one is removed, as health asks an administrator to.
		if err := removeAdminFile(l.AdminDir, name); err != nil {
			return err
		}
	}
	fmt.Println(`{"event":"credential-installed","collector_seq":` + strconv.FormatUint(decided.CollectorSeq, 10) + `}`)
	return nil
}

// adminFile leaves one signed admin-request file in admin_dir and returns
// at once (A6, #189): kind install, revoke or baseline-ack, expiring after
// expires (negative: already expired), with one payload byte changed after
// signing when tamper is set, written with mode (0440 is the rule; a
// wider mode is a file the node must not read); an install names
// credential version, and a baseline-ack the GT-INJ asset's event baseline
// digest (V-M4). It prints the file's name,
// its request ID as the node derives it from the bytes (admin- and 16 hex
// digits of their SHA-256) and the nonce.
func adminFile(root, kind, name string, r request, tamper bool, bad string, mode os.FileMode) error {
	a, err := loadAdmin(root, r.operator)
	if err != nil {
		return err
	}
	k := map[string]authz.RequestKind{"install": authz.KindCredentialInstall, "revoke": authz.KindCredentialRevoke,
		"baseline-ack": authz.KindNodeBaselineAck, "change-approval": authz.KindNodeChangeApproval}[kind]
	signed, _, err := a.sign(k, r)
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

// The GT-INJ Syslog asset (V-M4): a second SEL-751 record with no schedule,
// so only the Syslog it sends from gtinjSender reaches its event baseline.
const (
	gtinjAssetID = "6c0e2f4a-1b3d-4e5f-8a7b-9c0d1e2f3a4b"
	gtinjSerial  = "2007GTINJSYSLOG"
	gtinjSender  = "127.0.0.4"
)

// gtinjAsset adds the GT-INJ Syslog asset when events names a GT-INJ
// events.json: its event baseline takes that file's params, which decode
// strictly into C10's (tests/integration/gt_inj/README.md).
func gtinjAsset(nc *nodeconfigtest.Config, l *Layout, events string) error {
	if events == "" {
		return nil
	}
	if l.SyslogUDP == "" {
		return errors.New("-gtinj-events needs -syslog-udp")
	}
	params, err := seriesParams(events)
	if err != nil {
		return err
	}
	// Port 1 is never dialled: the record has no schedule.
	nc.AddSEL751(gtinjAssetID, "127.0.0.1", 1, 60)
	sched := nc.Schedule[:0]
	for _, c := range nc.Schedule {
		if c.AssetID != gtinjAssetID {
			sched = append(sched, c)
		}
	}
	nc.Schedule = sched
	setSerial(nc.Assets[len(nc.Assets)-1], gtinjSerial)
	nc.AddSyslogSender(gtinjAssetID, "syslog-udp-gtinj", "syslog-udp", gtinjSender, 0)
	nc.EventBaselines = append(nc.EventBaselines, nodeconfigtest.EventBaseline{AssetID: gtinjAssetID, Params: params})
	// The baseline and the learner's checkpoints are stored in the asset's
	// configuration stream, as in platform/node's own event-baseline tests.
	nc.Store.Quotas["configuration"] = 32 << 20
	l.GTINJAsset, l.GTINJSender = gtinjAssetID, gtinjSender
	return nil
}

// seriesParams reads a GT-INJ series' params.
func seriesParams(series string) (map[string]any, error) {
	b, err := os.ReadFile(series)
	if err != nil {
		return nil, err
	}
	var f struct {
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Params) == 0 {
		return nil, fmt.Errorf("%s: no params: %v", series, err)
	}
	return f.Params, nil
}

// verifyAudit checks a node's audit stream from its genesis record, as an
// upstream verifier would (V-M2: a deleted or edited approval record is
// detected): the hash chain (C8 VerifyChain), then the configuration and
// collector records (VerifyConfig).
func verifyAudit(in string) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var stored [][]byte
	var recs []*audit.Record
	for _, line := range strings.Fields(string(b)) {
		r, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return err
		}
		stored = append(stored, r)
		if rec, err := audit.ParseRecord(r); err == nil {
			recs = append(recs, rec)
		}
	}
	if err := audit.VerifyChain(nodeID, stored, nil, nil); err != nil {
		return err
	}
	if err := audit.VerifyConfig(recs); err != nil {
		return err
	}
	fmt.Printf("{\"records\":%d}\n", len(stored))
	return nil
}

// The other device of V-M2's approvals: enrolled, never read.
const (
	otherAssetID = "8d1f3b5c-2e4a-4f6b-9c8d-0e1f2a3b4c5d"
	otherSerial  = "2007GTINJCFGOTH"
)

// configReads, when every is set (V-M2), reads the slice's asset with
// sel.config.read_all every that many seconds instead of its SER. The node
// renders snapshots from its own copy of the command register, signed with
// the test register key (D4-40 item 7). The other device's record has no
// schedule.
func configReads(nc *nodeconfigtest.Config, l *Layout, payload []byte, revision uint64, every int) error {
	if every == 0 {
		return nil
	}
	for i, c := range nc.Schedule {
		if c.AssetID == assetID {
			nc.Schedule[i].ID, nc.Schedule[i].Operation, nc.Schedule[i].EverySeconds = "sch-cfg-"+assetID[:8], "sel.config.read_all", every
		}
	}
	if err := nc.WriteCommandRegister(l.Root, payload, revision); err != nil {
		return err
	}
	// Port 1 is never dialled: the record has no schedule.
	nc.AddSEL751(otherAssetID, "127.0.0.1", 1, 60)
	nc.Schedule = slices.DeleteFunc(nc.Schedule, func(c nodeconfigtest.Collection) bool { return c.AssetID == otherAssetID })
	setSerial(nc.Assets[len(nc.Assets)-1], otherSerial)
	nc.Store.Quotas["configuration"] = 32 << 20
	l.OtherAsset = otherAssetID
	return nil
}

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
