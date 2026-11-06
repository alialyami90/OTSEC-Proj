package main

// V-M1's node (D6): one SNMPv3 asset per GT-MIB case, each at its own
// agent's loopback port, with its own engine ID, credential reference and
// USM password (D3's notes on #494: a reference keeps its asset, and a
// shared password is HR-16's case).

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// gtmibEntry is one line of -gtmib's file.
type gtmibEntry struct {
	Case     string `json:"case"`
	AssetID  string `json:"asset_id"`
	Port     int    `json:"port"`
	EngineID string `json:"engine_id"`
	Ref      string `json:"ref"`
	// FirmwareID and ProductFamily are what the asset record declares;
	// empty keeps AddSEL2731M's.
	FirmwareID    string `json:"firmware_id,omitempty"`
	ProductFamily string `json:"product_family,omitempty"`
	// Every is this entry's every_seconds; zero takes -gtmib-every.
	Every int `json:"every,omitempty"`
}

// gtmibAssets adds file's entries to the node, under C2's sel-27x1-rstp
// test package, and returns the SEL-2731 profile and package (loaded here
// unless -snmp-port loaded them).
func gtmibAssets(nc *nodeconfigtest.Config, l *Layout, repo, file string, every int, profile, payload []byte) ([]byte, []byte, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	var es []gtmibEntry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, nil, fmt.Errorf("-gtmib: %w", err)
	}
	if len(es) == 0 {
		return nil, nil, errors.New("-gtmib: no entries")
	}
	if payload == nil {
		if profile, err = os.ReadFile(filepath.Join(repo, "modules", "security", "collector", "testdata", "profile-sel-27x1-rstp.json")); err != nil {
			return nil, nil, err
		}
		if payload, err = os.ReadFile(filepath.Join(repo, "contracts", "adapter", "testdata", "snmp", "register.json")); err != nil {
			return nil, nil, err
		}
	}
	if payload, err = gtmibFirmware(payload); err != nil {
		return nil, nil, err
	}
	l.GTMIBAssets = map[string]string{}
	for _, e := range es {
		if _, dup := l.GTMIBAssets[e.Case]; dup {
			return nil, nil, fmt.Errorf("-gtmib: case %s twice", e.Case)
		}
		n := every
		if e.Every != 0 {
			n = e.Every
		}
		nc.AddSEL2731M(e.AssetID, "127.0.0.1", e.Port, n)
		a := nc.Assets[len(nc.Assets)-1]
		set := map[string]string{"snmp_engine_id": e.EngineID, "firmware_id": e.FirmwareID, "product_family": e.ProductFamily}
		for _, at := range a["attributes"].([]any) {
			m := at.(map[string]any)
			if v := set[m["name"].(string)]; v != "" {
				// The value is written twice (AddSEL2731M): the
				// attribute's and its one observation's.
				m["value"] = v
				m["observations"].([]any)[0].(map[string]any)["value"] = v
			}
		}
		nc.Schedule[len(nc.Schedule)-1].CredentialRef = e.Ref
		l.GTMIBAssets[e.Case] = e.AssetID
	}
	// The asset module's identity records need room (C5 0.8).
	nc.Store.Quotas["configuration"] = 64 << 20
	return profile, payload, nil
}

// usmInstall is an snmpv3 credential to install (install-credential
// -snmp-asset).
type usmInstall struct {
	asset, ref string
	usm        authz.USM
	// secret is the keys; nil reads them from OTSEC_SLICE_SECRET_HEX.
	secret []byte
}

// build is the install's reference and secret: authKey || privKey[:16],
// read hex-encoded from OTSEC_SLICE_SECRET_HEX, since a localized key can
// hold a zero byte that an environment variable cannot (D3's notes).
func (u *usmInstall) build(nodeID string, version uint32, by authz.Principal, now time.Time) (authz.CredentialRef, []byte, error) {
	secret := u.secret
	if secret == nil {
		var err error
		if secret, err = hex.DecodeString(os.Getenv("OTSEC_SLICE_SECRET_HEX")); err != nil || len(secret) == 0 {
			return authz.CredentialRef{}, nil, errors.New("OTSEC_SLICE_SECRET_HEX is not set to hex")
		}
	}
	usm := u.usm
	return authz.CredentialRef{
		ID: u.ref, AssetID: u.asset, NodeID: nodeID, EndpointID: "mgmt-snmpv3",
		Transport: authz.TransportSNMPv3, Purpose: authz.PurposeCollectReadOnly,
		DownstreamSecurity: authz.DownstreamEncryptedAuthenticated, USM: &usm,
		Version: version, CreatedBy: by, CreatedAt: now.Format(time.RFC3339),
	}, secret, nil
}

// removeAdminFile removes a relayed file from admin_dir, opening the
// directory for the write and closing it again (0550), as leaveAdminFile
// does on Linux.
func removeAdminFile(dir, name string) error {
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(dir, name))
	if cerr := os.Chmod(dir, 0o550); err == nil {
		err = cerr
	}
	return err
}

// gtmibBatch is how many install files install-gtmib leaves at a time: the
// node reads the first 16 files in admin_dir, and the slice's own
// install file stays there.
const gtmibBatch = 12

// installGTMIB installs every -gtmib entry's snmpv3 credential through the
// node, gtmibBatch at a time, and removes each file once the collector
// has decided it. The secrets are a JSON object of case ID to hex in
// OTSEC_GTMIB_SECRETS_HEX, never on the command line. auth is every
// credential's USM authentication protocol.
func installGTMIB(root, file, auth string) error {
	a, err := loadAdmin(root, false)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var es []gtmibEntry
	if err := json.Unmarshal(b, &es); err != nil {
		return err
	}
	var secrets map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("OTSEC_GTMIB_SECRETS_HEX")), &secrets); err != nil {
		return fmt.Errorf("OTSEC_GTMIB_SECRETS_HEX: %w", err)
	}
	for len(es) > 0 {
		batch := es[:min(gtmibBatch, len(es))]
		es = es[len(batch):]
		names := map[string]string{}
		for _, e := range batch {
			secret, err := hex.DecodeString(secrets[e.Case])
			if err != nil || len(secret) == 0 {
				return fmt.Errorf("case %s: no secret", e.Case)
			}
			u := &usmInstall{asset: e.AssetID, ref: e.Ref, secret: secret, usm: authz.USM{UserName: "gt-mib",
				Auth: authz.USMAuth(auth), Priv: authz.USMPrivAES128, EngineID: e.EngineID, SoleDeviceAttested: true}}
			signed, nonce, err := a.sign(authz.KindCredentialInstall, request{expires: 10 * time.Minute, version: 1, usm: u})
			if err != nil {
				return fmt.Errorf("case %s: %w", e.Case, err)
			}
			f, err := json.Marshal(map[string]any{"schema": node.AdminRequestFileSchema, "kind": authz.KindCredentialInstall, "signed": signed})
			if err != nil {
				return err
			}
			name := "admin-request-install-" + hex.EncodeToString(nonce) + ".json"
			if err := leaveAdminFile(a.l.AdminDir, name, f); err != nil {
				return err
			}
			names[name] = e.Case
		}
		decided := map[string]node.AdminRequestStatus{}
		deadline := time.Now().Add(4 * node.RelayEverySeconds * time.Second)
		for len(decided) < len(names) {
			if time.Now().After(deadline) {
				return fmt.Errorf("the node did not relay %d of %d files within %s", len(names)-len(decided), len(names), 4*node.RelayEverySeconds*time.Second)
			}
			time.Sleep(250 * time.Millisecond)
			st, err := node.ReadStatus(filepath.Join(a.l.StoreDir, node.StatusFileName))
			if err != nil {
				continue
			}
			for _, r := range st.AdminRequests {
				if _, ok := names[r.File]; ok && r.State != "" && r.State != "waiting" {
					decided[r.File] = r
				}
			}
		}
		for name, r := range decided {
			if r.State != "accepted" {
				return fmt.Errorf("case %s: credential.install %s: %s (%s)", names[name], name, r.State, r.Detail)
			}
			if err := removeAdminFile(a.l.AdminDir, name); err != nil {
				return err
			}
		}
	}
	fmt.Println(`{"event":"gtmib-credentials-installed"}`)
	return nil
}

// gtmibFirmware adds to the run's copy of C2's test package the two other
// FIDs GT-MIB serves in an ok case, so that the collector's firmware check
// (AP-27) lets their runs start: the SEL-2741M of I2 and F6, and the
// R100-V0 of I6, whose branch it allows. The run signs the copy with its
// own release key, as it does the package itself; the file on disk is not
// changed. Both FIDs are labelled as GT-MIB's, not as device facts.
func gtmibFirmware(payload []byte) ([]byte, error) {
	var reg map[string]any
	if err := json.Unmarshal(payload, &reg); err != nil {
		return nil, err
	}
	fw, ok := reg["firmware"].(map[string]any)
	if !ok {
		return nil, errors.New("-gtmib: the SNMP test package has no firmware section")
	}
	cite := map[string]any{"source": "T1", "ref": "invented"}
	fw["known"] = append(fw["known"].([]any),
		map[string]any{"fid": "SEL-2741M-R102-V1-Z003001-D20260408", "branch": "R102", "version": 1, "citation": cite},
		map[string]any{"fid": "SEL-2731M-R100-V0-Z001001-D20231120", "branch": "R100", "version": 0, "citation": cite})
	fw["branches"] = append(fw["branches"].([]any),
		map[string]any{"branch": "R100", "status": "allow", "min_version": 0, "basis": "GT-MIB's I6 (V-M1 runner)", "evidence": map[string]any{"class": "inferred"}})
	return json.MarshalIndent(reg, "", "  ")
}
