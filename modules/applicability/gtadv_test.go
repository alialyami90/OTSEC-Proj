package applicability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
)

// GT-ADV (C6, tests/integration/gt_adv) is the unit acceptance: every one of
// its 128 cells, on class, reason, unread preconditions, attestation, stale
// mark and the kinds of evidence cited.

type gtRow struct {
	ID       string            `json:"id"`
	FID      string            `json:"fid"`
	Source   finding.Source    `json:"source"`
	Settings map[string]string `json:"settings"`
	Stale    bool              `json:"stale"`
	Controls []string          `json:"controls"`
	Declared string            `json:"declared_product_family"`
}

type gtAdvisory struct {
	ID            string          `json:"id"`
	TestOnly      bool            `json:"test_only"`
	Product       string          `json:"product"`
	Ranges        [][2]*string    `json:"ranges"`
	Preconditions []advisory.Item `json:"preconditions"`
	Mitigations   []advisory.Item `json:"mitigations"`
}

type gtCell struct {
	Class    finding.Class  `json:"class"`
	Reason   finding.Reason `json:"reason"`
	Evidence []string       `json:"evidence"`
	Unread   []string       `json:"unread"`
	Attested bool           `json:"attested"`
	Stale    bool           `json:"stale"`
}

type gtFile struct {
	Identities []gtRow                      `json:"identities"`
	Advisories []gtAdvisory                 `json:"advisories"`
	Cells      map[string]map[string]gtCell `json:"cells"`
}

func loadGT(t testing.TB) gtFile {
	t.Helper()
	b, err := os.ReadFile("../../tests/integration/gt_adv/gt_adv.json")
	if err != nil {
		t.Fatal(err)
	}
	var g gtFile
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// The IDs the rows cite. Each is in the form C12 ties to its source.
const (
	assetID    = "0b6c3a52-6f1d-4c2e-8a7b-3d9e5f1a2b4c"
	recordID   = "11111111-1111-4111-8111-111111111111" // the run that first read the identity
	readID     = "22222222-2222-4222-8222-222222222222" // the latest run that read it again
	snapshotID = "33333333-3333-4333-8333-333333333333" // the settings snapshot
	mismatchID = "44444444-4444-4444-8444-444444444444"
	operatorID = "audit:node-a:7"
	controlID  = "audit:node-a:9"
	readAt     = "2026-11-05T10:00:00Z"
	beforeRead = "2026-11-05T09:59:00Z"
	afterRead  = "2026-11-05T10:05:00Z"
	evaluated  = "2026-11-05T10:10:00Z"
)

// gtSet builds the C11 test set from GT-ADV's advisories.
func gtSet(t testing.TB, g gtFile) *advisory.Set {
	t.Helper()
	s := &advisory.Set{Contract: advisory.Identifier, SetID: "gt-adv", Version: 1, IssuedAt: "2026-11-05T00:00:00Z",
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
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

// gtInput maps one row to the matcher's input. A stale row had a
// configuration change retrieved after its identity read; that change is
// the snapshot it holds.
func gtInput(r gtRow) Input {
	in := Input{AssetID: assetID, EvaluatedUTC: evaluated,
		Identity: Identity{Source: r.Source, Evidence: operatorID, FirmwareID: r.FID}}
	if r.Source == finding.DeviceRead {
		in.Identity.Evidence = recordID
		in.Identity.LatestRead = &finding.Read{ID: readID, AtUTC: readAt}
		// C1 0.3's two device-read sub-spans of the FID. D11's declared
		// product family is not an input at all.
		if m := fidRe.FindStringSubmatch(r.FID); m != nil {
			in.Identity.Model, in.Identity.FirmwareVersion = m[1], m[2]
		}
	}
	at := beforeRead
	if r.Stale {
		at = afterRead
	}
	if len(r.Settings) > 0 {
		in.Settings = &Snapshot{ID: snapshotID, AtUTC: at, Settings: r.Settings}
		in.LatestChange = &finding.Read{ID: snapshotID, AtUTC: at}
	} else if r.Stale {
		in.LatestChange = &finding.Read{ID: snapshotID, AtUTC: at}
	}
	for _, c := range r.Controls {
		in.Controls = append(in.Controls, Control{Key: c, Evidence: controlID})
	}
	return in
}

// cellOf reads a finding back into GT-ADV's terms.
func cellOf(f finding.Finding) gtCell {
	c := gtCell{Class: f.Class, Reason: f.Reason, Evidence: []string{"identity"}, Unread: []string{}}
	kinds := map[string]bool{}
	for i, e := range f.Identity.Evidence {
		if i > 0 && e.ID == snapshotID {
			kinds["config-change"] = true
		}
		c.Stale = c.Stale || e.Stale
	}
	for _, p := range f.Preconditions {
		if p.State == finding.Unread {
			c.Unread = append(c.Unread, p.Name)
		}
		for _, e := range p.Evidence {
			if e.ID == snapshotID {
				kinds["settings"] = true
			}
		}
	}
	for _, m := range f.Mitigations {
		c.Attested = c.Attested || m.OperatorAttested
		for _, e := range m.Evidence {
			switch e.ID {
			case snapshotID:
				kinds["settings"] = true
			case controlID:
				kinds["control"] = true
			}
		}
	}
	for _, k := range []string{"settings", "control", "config-change"} {
		if kinds[k] {
			c.Evidence = append(c.Evidence, k)
		}
	}
	return c
}

func normal(c gtCell) gtCell {
	if c.Unread == nil {
		c.Unread = []string{}
	}
	slices.Sort(c.Unread)
	return c
}

func TestGTADV(t *testing.T) {
	g := loadGT(t)
	set := gtSet(t, g)
	n := 0
	for _, r := range g.Identities {
		got1, err := Evaluate(gtInput(r), set, nil)
		if err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		got2, _ := Evaluate(gtInput(r), set, nil)
		b1, _ := json.Marshal(got1)
		b2, _ := json.Marshal(got2)
		if !bytes.Equal(b1, b2) {
			t.Errorf("%s: two runs gave different bytes", r.ID)
		}
		if len(got1) != len(set.Entries) {
			t.Fatalf("%s: %d findings for %d entries", r.ID, len(got1), len(set.Entries))
		}
		for _, f := range got1 {
			want, ok := g.Cells[f.Advisory][r.ID]
			if !ok {
				t.Fatalf("no cell %s × %s", f.Advisory, r.ID)
			}
			n++
			got := normal(cellOf(f))
			if w := normal(want); fmt.Sprint(got) != fmt.Sprint(w) {
				t.Errorf("%s × %s: got %+v, want %+v", f.Advisory, r.ID, got, w)
			}
		}
	}
	if n != 128 {
		t.Errorf("%d cells checked, want 128", n)
	}
}
