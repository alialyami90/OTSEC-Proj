package store

import (
	"slices"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// C5 0.8 in the SQLite store: the four item 3 series are kept with their
// kinds, identity.read is removable but for its newest, and identity,
// finding and advisory.set are never removable (docs/phase4/C5-c5-0.8.md
// section 7). Evidence class: simulated.

func TestItem3SeriesV08(t *testing.T) {
	db := openConfig(t, storeDir(t), configDB, nil)
	// 1 identity, 2 identity.read, 3 finding, 4 advisory.set, 5 identity.read,
	// 6 identity, 7 finding, 8 advisory.set, 9 identity.read.
	appendSeries(t, db, configDB, cfgA,
		c5.SeriesIdentity, c5.SeriesIdentityRead, c5.SeriesFinding, c5.SeriesAdvisorySet, c5.SeriesIdentityRead,
		c5.SeriesIdentity, c5.SeriesFinding, c5.SeriesAdvisorySet, c5.SeriesIdentityRead)
	want := map[c5.Seq][2]string{
		1: {"evidence", "identity"}, 2: {"working-state", "identity.read"}, 3: {"evidence", "finding"},
		4: {"evidence", "advisory.set"}, 9: {"working-state", "identity.read"},
	}
	for seq, w := range want {
		if k, s := seriesOf(t, db, cfgA, seq); k.String != w[0] || s.String != w[1] {
			t.Errorf("seq %d: %v %v, want %v", seq, k, s, w)
		}
	}
	all := storedSeqs(t, db, cfgA)

	refused := []struct {
		name   string
		series string
		seqs   []c5.Seq
	}{
		{"an older identity record", c5.SeriesIdentity, []c5.Seq{1}},
		{"an older finding", c5.SeriesFinding, []c5.Seq{3}},
		{"an older advisory set", c5.SeriesAdvisorySet, []c5.Seq{4}},
		{"the newest identity.read", c5.SeriesIdentityRead, []c5.Seq{9}},
		{"an older identity.read with the newest", c5.SeriesIdentityRead, []c5.Seq{2, 9}},
		{"an identity record as identity.read", c5.SeriesIdentityRead, []c5.Seq{1}},
	}
	for _, c := range refused {
		if r, err := db.RemoveConfig(bg, cfgA, c.series, c.seqs); !isCode(err, c5.CodeInvalid) || r.Records != 0 {
			t.Errorf("%s: %+v %v", c.name, r, err)
		}
	}
	if got := storedSeqs(t, db, cfgA); !slices.Equal(got, all) {
		t.Fatalf("after the refusals %v, want %v", got, all)
	}

	if r, err := db.RemoveConfig(bg, cfgA, c5.SeriesIdentityRead, []c5.Seq{2, 5}); err != nil || r.Records != 2 {
		t.Fatalf("the older identity.read records: %+v %v", r, err)
	}
	if got := storedSeqs(t, db, cfgA); !slices.Equal(got, []c5.Seq{1, 3, 4, 6, 7, 8, 9}) {
		t.Errorf("after the removal %v", got)
	}
	checkCounted(t, db, "after the removal")
}
