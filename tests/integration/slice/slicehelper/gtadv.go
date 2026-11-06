package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// V-M7 on the binaries (C6, P4-3-C6): GT-ADV's rows as the node's assets.
// A device-read row is the slice's own asset, its declared firmware ID the
// row's, which the simulator serves, and its controls, if any, the row's
// asset_controls entry (D4-56); an operator row is an asset with a
// declared firmware ID and no schedule, so no session ever reads it. The
// set is GT-ADV's eight advisories in C11's form, signed with advisory
// test key 0, which only a node built with otsec_testclock accepts.

// gtADVSetID and gtADVVersion name the set every V-M7 node is given.
const (
	gtADVSetID   = "gt-adv"
	gtADVVersion = 1
)

type gtADVRow struct {
	ID       string   `json:"id"`
	FID      string   `json:"fid"`
	Source   string   `json:"source"`
	Declared string   `json:"declared_product_family"`
	Controls []string `json:"controls"`
}

type gtADVAdvisory struct {
	ID            string          `json:"id"`
	TestOnly      bool            `json:"test_only"`
	Product       string          `json:"product"`
	Ranges        [][2]*string    `json:"ranges"`
	Preconditions []advisory.Item `json:"preconditions"`
	Mitigations   []advisory.Item `json:"mitigations"`
}

type gtADVFile struct {
	Identities []gtADVRow      `json:"identities"`
	Advisories []gtADVAdvisory `json:"advisories"`
}

// operatorAssetID is operator row i's asset (O1 is 1).
func operatorAssetID(i int) string { return fmt.Sprintf("0a7d0000-0000-4000-8000-%012d", i) }

// gtADV turns applicability on with GT-ADV's set left in admin_dir, makes
// the slice's asset device-read row `row` (none: it stays the slice's),
// and with operators adds GT-ADV's operator rows. It records each row's
// asset in the layout.
func gtADV(nc *nodeconfigtest.Config, l *Layout, repo, row string, operators bool) error {
	if row == "" && !operators {
		return nil
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
	key := advisorytest.Key(0)
	pub := key.Public().(ed25519.PublicKey)
	nc.Asset = &struct{}{}
	// The configuration module's floor and item 3's (C5 0.8) for every
	// asset, with room to spare: 25 MiB and 15 MiB for D1's node.
	nc.Store.Quotas["configuration"] = 64 << 20
	nc.Applicability = &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{{
		KeyID: advisory.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), Status: "active"}}}
	l.GTADVAssets = map[string]string{}
	found := row == ""
	for i, r := range g.Identities {
		switch {
		case r.ID == row && r.Source == "device-read":
			found = true
			setAttr(nc.Assets[0], "firmware_id", r.FID)
			if r.Declared != "" {
				// C1's product_family is a lowercase token: SEL-2730M
				// is declared as sel-2730m.
				setAttr(nc.Assets[0], "product_family", strings.ToLower(r.Declared))
			}
			if len(r.Controls) > 0 {
				// The row's recorded controls (D4-56), beside the asset's
				// C1 record.
				nc.AssetControls = append(nc.AssetControls, nodeconfigtest.AssetControls{AssetID: assetID, Controls: r.Controls})
			}
			l.FID = r.FID
			l.GTADVAssets[r.ID] = assetID
		case operators && r.Source == "operator":
			// Port 1 is never dialled: the record has no schedule.
			id := operatorAssetID(i + 1 - countSource(g, "device-read"))
			nc.AddSEL751(id, "127.0.0.1", 1, 60)
			nc.Schedule = nc.Schedule[:len(nc.Schedule)-1]
			setAttr(nc.Assets[len(nc.Assets)-1], "firmware_id", r.FID)
			l.GTADVAssets[r.ID] = id
		}
	}
	if !found {
		return fmt.Errorf("-gtadv-row %q: GT-ADV has no device-read row of that name", row)
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return err
	}
	return leaveAdminFile(l.AdminDir, "advisory-set.json", advisorytest.Sign(key, payload))
}

func countSource(g gtADVFile, source string) int {
	n := 0
	for _, r := range g.Identities {
		if r.Source == source {
			n++
		}
	}
	return n
}

// gtADVSet is GT-ADV's advisories in C11's form, as the matcher's own
// acceptance test builds them (modules/applicability/gtadv_test.go).
func gtADVSet(g gtADVFile) (*advisory.Set, error) {
	s := &advisory.Set{Contract: advisory.Identifier, SetID: gtADVSetID, Version: gtADVVersion, IssuedAt: "2026-11-05T00:00:00Z",
		Purpose: advisory.PurposeTest, Publisher: "GT-ADV (C6)"}
	for _, a := range g.Advisories {
		aff := advisory.Affected{Vendor: "SEL", Product: a.Product, Scheme: advisory.SchemeSELFID}
		for _, r := range a.Ranges {
			var rr advisory.Range
			if r[0] != nil {
				rr.Introduced = *r[0]
			}
			if r[1] != nil {
				rr.Fixed = *r[1]
			}
			aff.Ranges = append(aff.Ranges, rr)
		}
		s.Entries = append(s.Entries, advisory.Entry{ID: a.ID, TestOnly: a.TestOnly, Title: a.ID,
			Sources:  []advisory.Source{{Kind: advisory.SourceOther, Ref: "GT-ADV", Published: "2026-11-05"}},
			Affected: []advisory.Affected{aff}, Preconditions: a.Preconditions, Mitigations: a.Mitigations})
	}
	return s, s.Validate()
}

// setAttr sets a declared attribute's value, and its observations'.
func setAttr(a map[string]any, name, value string) {
	for _, at := range a["attributes"].([]any) {
		m := at.(map[string]any)
		if m["name"] != name {
			continue
		}
		m["value"] = value
		for _, o := range m["observations"].([]any) {
			o.(map[string]any)["value"] = value
		}
	}
}
