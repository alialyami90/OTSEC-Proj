// Package applicability holds C6's cases for the R9 matcher beyond GT-ADV's
// table. Evidence class: desk (the matcher is a pure function; no device,
// no node).
package applicability

import (
	"strconv"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
	"otsec.local/otsec/modules/applicability"
)

// C1's mismatch ruling on #445 (C4-matcher.md section 6): a later identity
// mismatch adopts nothing, and the identity is not current until a later
// read confirms it. The mismatch is a device read of another FID at the
// asset's address, so the stored FID is contradicted, not merely old. A
// firmware downgrade on the SEL-751 is such a read: ID at Level 0 differs
// from the declared FID, refused.identity_mismatch, and the identity record
// keeps the old FID. The matcher must then not call the asset
// not-applicable from that FID, by version or by a setting: either would
// hide an advisory the device may now be inside. The cells come out as
// applicable-by-version, the identity marked stale and the mismatch cited,
// and they return when a later read confirms the identity.
//
// The rows and advisories are GT-ADV's (tests/integration/gt_adv), copied
// here so this file does not depend on the table's layout.

const (
	asset      = "0b6c3a52-6f1d-4c2e-8a7b-3d9e5f1a2b4c"
	record     = "11111111-1111-4111-8111-111111111111"
	read       = "22222222-2222-4222-8222-222222222222"
	snapshot   = "33333333-3333-4333-8333-333333333333"
	mismatch   = "44444444-4444-4444-8444-444444444444"
	confirming = "55555555-5555-4555-8555-555555555555"
	fid501     = "SEL-751-R501-V0-Z104101-D20260910" // S22 Appendix A (GT-ADV D1, D2)
)

func ehttp() advisory.Item {
	return advisory.Item{Name: "web-enabled", Kind: advisory.KindSetting, Key: "EHTTP", Op: advisory.OpIn, Values: []string{"Y"}}
}

func entry(id string, ranges []advisory.Range, pre []advisory.Item) advisory.Entry {
	return advisory.Entry{ID: id, TestOnly: true, Title: id,
		Sources:       []advisory.Source{{Kind: advisory.SourceOther, Ref: "GT-ADV", Published: "2026-11-05"}},
		Affected:      []advisory.Affected{{Vendor: "SEL", Product: "SEL-751", Scheme: advisory.SchemeSELFID, Ranges: ranges}},
		Preconditions: pre}
}

func set(t *testing.T) *advisory.Set {
	t.Helper()
	s := &advisory.Set{Contract: advisory.Identifier, SetID: "c6-mismatch", Version: 1, IssuedAt: "2026-11-05T00:00:00Z",
		Purpose: advisory.PurposeTest, Publisher: "C6", Entries: []advisory.Entry{
			// TEST-ADV-02: R500-V0 up to R500-V1, web enabled. R501 is outside.
			entry("TEST-ADV-02", []advisory.Range{{Introduced: "R500-V0", Fixed: "R500-V1"}}, []advisory.Item{ehttp()}),
			// TEST-ADV-03's ranges and precondition, without its control.
			entry("TEST-ADV-03", []advisory.Range{{Introduced: "R500-V0"}, {Introduced: "R501-V0"}}, []advisory.Item{ehttp()}),
			// TEST-ADV-07: every branch from V0, no precondition.
			entry("TEST-ADV-07", []advisory.Range{{Introduced: "R400-V0"}, {Introduced: "R401-V0"}, {Introduced: "R402-V0"}, {Introduced: "R500-V0"}, {Introduced: "R501-V0"}}, nil),
		}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

// input is GT-ADV's D1 (EHTTP Y) or D2 (EHTTP N): R501-V0, device-read and
// current, its snapshot read before its latest identity read.
func input(web string) applicability.Input {
	return applicability.Input{AssetID: asset, EvaluatedUTC: "2026-11-05T10:10:00Z",
		Identity: applicability.Identity{Source: finding.DeviceRead, Evidence: record, FirmwareID: fid501,
			Model: "SEL-751", FirmwareVersion: "R501-V0", LatestRead: &finding.Read{ID: read, AtUTC: "2026-11-05T10:00:00Z"}},
		Settings:     &applicability.Snapshot{ID: snapshot, AtUTC: "2026-11-05T09:59:00Z", Settings: map[string]string{"EHTTP": web}},
		LatestChange: &finding.Read{ID: snapshot, AtUTC: "2026-11-05T09:59:00Z"}}
}

func byID(t *testing.T, in applicability.Input, s *advisory.Set) map[string]finding.Finding {
	t.Helper()
	fs, err := applicability.Evaluate(in, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]finding.Finding{}
	for _, f := range fs {
		out[f.Advisory] = f
	}
	return out
}

func TestMismatchHidesNoAdvisory(t *testing.T) {
	s := set(t)
	cases := []struct {
		row, entry       string
		web              string
		before, mismatch finding.Class // without the mismatch (GT-ADV's cell), and with it
	}{
		{"D1", "TEST-ADV-07", "Y", finding.Confirmed, finding.ApplicableByVersion},
		{"D1", "TEST-ADV-02", "Y", finding.NotApplicable, finding.ApplicableByVersion}, // outside-range on the old FID
		{"D2", "TEST-ADV-03", "N", finding.NotApplicable, finding.ApplicableByVersion}, // precondition-not-met on the old snapshot
	}
	for _, c := range cases {
		in := input(c.web)
		if f := byID(t, in, s)[c.entry]; f.Class != c.before {
			t.Fatalf("%s %s without a mismatch: %s, want GT-ADV's %s", c.row, c.entry, f.Class, c.before)
		}

		in.LatestMismatch = &finding.Read{ID: mismatch, AtUTC: "2026-11-05T10:05:00Z"}
		f := byID(t, in, s)[c.entry]
		if f.Class != c.mismatch {
			t.Errorf("%s %s after a mismatch: %s (%s), want %s: the stored FID is contradicted, so it cannot make the asset not-applicable",
				c.row, c.entry, f.Class, f.Reason, c.mismatch)
			continue
		}
		ev := f.Identity.Evidence
		if len(ev) != 2 || ev[0].ID != record || !ev[0].Stale || ev[1].ID != mismatch || ev[1].Source != finding.DeviceRead {
			t.Errorf("%s %s: identity evidence %+v, want the record marked stale, then the mismatch", c.row, c.entry, ev)
		}
		if f.Identity.Version != fid501 {
			t.Errorf("%s %s: the mismatch was adopted: %q", c.row, c.entry, f.Identity.Version)
		}

		// A later read of the declared FID confirms the identity again,
		// and GT-ADV's cell returns.
		in.Identity.LatestRead = &finding.Read{ID: confirming, AtUTC: "2026-11-05T10:06:00Z"}
		if f := byID(t, in, s)[c.entry]; f.Class != c.before {
			t.Errorf("%s %s after a confirming read: %s, want %s", c.row, c.entry, f.Class, c.before)
		}
	}
}

// C1's narrower ruling on #451: the mismatch read is never adopted, but it
// is device-read evidence of what answered. An entry that names the model
// that read reported cannot be product-not-named while the mismatch stands.
// An entry that names neither model still is, and so is every such entry
// when the mismatch read's FID does not parse.
func TestMismatchModelIsNotHidden(t *testing.T) {
	other := func(id, product string) advisory.Entry {
		e := entry(id, []advisory.Range{{Introduced: "R100-V0"}}, nil)
		e.Affected[0].Product = product
		return e
	}
	s := set(t)
	s.Entries = append(s.Entries, other("E1-751A", "SEL-751A"), other("E2-2731M", "SEL-2731M"))
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	const fid751A = "SEL-751A-R100-V1-Z000000-D20250101" // a FID of the shape S22 gives; the SEL-751A is not covered
	type want struct {
		class  finding.Class
		reason finding.Reason // checked only when not empty
	}
	pnn := want{finding.NotApplicable, finding.ProductNotNamed}
	abv := want{class: finding.ApplicableByVersion}
	check := func(step string, in applicability.Input, wants map[string]want) {
		t.Helper()
		got := byID(t, in, s)
		for id, w := range wants {
			f := got[id]
			if f.Class != w.class || (w.reason != "" && f.Reason != w.reason) {
				t.Errorf("%s: %s is %s (%s), want %s (%s)", step, id, f.Class, f.Reason, w.class, w.reason)
				continue
			}
			if f.Identity.Version != fid501 {
				t.Errorf("%s: %s: the mismatch was adopted: %q", step, id, f.Identity.Version)
			}
			if f.Class != finding.ApplicableByVersion {
				continue
			}
			ev := f.Identity.Evidence
			if len(ev) != 2 || ev[0].ID != record || !ev[0].Stale || ev[1].ID != mismatch || ev[1].Source != finding.DeviceRead {
				t.Errorf("%s: %s: identity evidence %+v, want the record marked stale, then the mismatch", step, id, ev)
			}
			if len(f.Preconditions) != 1 || f.Preconditions[0].Name != advisory.ReservedFirmwareVersion || f.Preconditions[0].State != finding.Unread {
				t.Errorf("%s: %s: firmware-version is not unread: %+v", step, id, f.Preconditions)
			}
		}
	}

	// (a) No mismatch: GT-ADV's D1.
	in := input("Y")
	check("(a) no mismatch", in, map[string]want{"E1-751A": pnn, "E2-2731M": pnn, "TEST-ADV-07": {class: finding.Confirmed}})

	// (b) A later mismatch read that reports a SEL-751A.
	in.LatestMismatch = &finding.Read{ID: mismatch, AtUTC: "2026-11-05T10:05:00Z"}
	in.MismatchFID = fid751A
	check("(b) mismatch reports SEL-751A", in, map[string]want{"E1-751A": abv, "E2-2731M": pnn, "TEST-ADV-07": abv})

	// (d) The same mismatch, with a FID that does not parse: no model is used.
	for _, bad := range []string{"", "SEL-751A", "garbage", fid751A + "X"} {
		in.MismatchFID = bad
		check("(d) mismatch FID "+strconv.Quote(bad), in, map[string]want{"E1-751A": pnn, "E2-2731M": pnn, "TEST-ADV-07": abv})
	}

	// (c) A confirming read after the mismatch: back to (a), whatever the
	// mismatch read reported.
	in.MismatchFID = fid751A
	in.Identity.LatestRead = &finding.Read{ID: confirming, AtUTC: "2026-11-05T10:06:00Z"}
	check("(c) confirming read", in, map[string]want{"E1-751A": pnn, "E2-2731M": pnn, "TEST-ADV-07": {class: finding.Confirmed}})
}
