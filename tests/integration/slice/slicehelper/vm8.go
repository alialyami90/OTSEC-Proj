package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// V-M8's set cases on the binaries (C6, P4-3-C6). setup -vm8 turns R9 on
// with two advisory anchors, test key 0 active and test key 2 revoked, and
// leaves no set: the suite leaves each file with advisory-file. Test key 1
// is never pinned.

// vm8 turns R9 on for V-M8's set cases.
func vm8(nc *nodeconfigtest.Config) {
	anchor := func(n int, status string) nodeconfigtest.AdvisoryAnchor {
		pub := advisorytest.Key(n).Public().(ed25519.PublicKey)
		return nodeconfigtest.AdvisoryAnchor{KeyID: advisory.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), Status: status}
	}
	nc.Asset = &struct{}{}
	nc.Applicability = &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{anchor(0, "active"), anchor(2, "revoked")}}
	nc.Store.Quotas["configuration"] = 64 << 20
}

// advisoryFile leaves one of V-M8's set files in admin_dir as
// advisory-set.json, replacing any there, and prints its SHA-256, the ID of
// the key that signed it and the code a node must give it ("" for a set it
// must take). Every case but valid is built from GT-ADV's set at version,
// signed with test key 0, with one thing wrong:
//
//	valid               nothing
//	unsigned            the envelope has no signature (malformed, "no signature")
//	unknown-key         signed with test key 1, which is not pinned
//	revoked-key         signed with test key 2, pinned as revoked
//	bad-signature       one signature byte changed
//	truncated           the file cut in half (malformed)
//	no-source           the first entry cites no source (invalid)
//	release-test-only   purpose release, its entries test_only (invalid)
//	other-set           another set_id (wrong_set)
//	differs             the publisher changed (same_version_differs at the version in use)
//
// An older version is the valid case at a lower version.
func advisoryFile(root, repo, kind string, version uint64) error {
	a, err := loadAdmin(root, false)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(repo, "tests", "integration", "gt_adv", "gt_adv.json"))
	if err != nil {
		return err
	}
	var g gtADVFile
	if err := json.Unmarshal(b, &g); err != nil {
		return err
	}
	set, err := gtADVSet(g)
	if err != nil {
		return err
	}
	set.Version = version
	key, code := advisorytest.Key(0), ""
	switch kind {
	case "valid":
	case "unknown-key":
		key, code = advisorytest.Key(1), string(advisory.UnknownKey)
	case "revoked-key":
		key, code = advisorytest.Key(2), string(advisory.RevokedKey)
	case "no-source":
		set.Entries[0].Sources = nil
		code = string(advisory.Invalid)
	case "release-test-only":
		set.Purpose, code = advisory.PurposeRelease, string(advisory.Invalid)
	case "other-set":
		set.SetID, code = "gt-adv-other", string(advisory.WrongSet)
	case "differs":
		set.Publisher, code = "GT-ADV (C6), republished", string(advisory.SameVersionDiffers)
	case "unsigned", "bad-signature", "truncated":
		code = string(advisory.Malformed)
		if kind == "bad-signature" {
			code = string(advisory.BadSignature)
		}
	default:
		return fmt.Errorf("advisory-file: unknown case %q", kind)
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return err
	}
	file := advisorytest.Sign(key, payload)
	switch kind {
	case "unsigned", "bad-signature":
		var env map[string]any
		if err := json.Unmarshal(file, &env); err != nil {
			return err
		}
		if kind == "unsigned" {
			delete(env, "signature")
		} else {
			sig, err := base64.StdEncoding.DecodeString(env["signature"].(string))
			if err != nil {
				return err
			}
			sig[0] ^= 0x01
			env["signature"] = base64.StdEncoding.EncodeToString(sig)
		}
		if file, err = json.Marshal(env); err != nil {
			return err
		}
	case "truncated":
		file = file[:len(file)/2]
	}
	if err := replaceAdminFile(a.l.AdminDir, "advisory-set.json", file); err != nil {
		return err
	}
	out, err := json.Marshal(map[string]any{"file_sha256": sha256Hex(file), "code": code, "payload_sha256": sha256Hex(payload),
		"key_id": advisory.KeyID(key.Public().(ed25519.PublicKey))})
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// replaceAdminFile leaves name in dir in place of any file of that name.
func replaceAdminFile(dir, name string, b []byte) error {
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		err = nil
	}
	if cerr := os.Chmod(dir, 0o550); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return leaveAdminFile(dir, name, b)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
