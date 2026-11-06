package store

import "testing"

// C5 0.8 (D4-53; docs/phase4/C5-c5-0.8.md section 7). Evidence class: desk.

func TestSeriesV08(t *testing.T) {
	for got, want := range map[string]string{
		SeriesIdentity: "identity", SeriesFinding: "finding", SeriesAdvisorySet: "advisory.set", SeriesIdentityRead: "identity.read",
	} {
		if got != want {
			t.Errorf("series %q, want %q", got, want)
		}
	}
	if Identifier != "otsec.store/0.8" {
		t.Errorf("identifier %q", Identifier)
	}
}

// identity.read is removable; the three item 3 evidence series are not.
func TestCheckRemoveConfigV08(t *testing.T) {
	const s StreamID = "config/relay1"
	if err := CheckRemoveConfig(s, SeriesIdentityRead, []Seq{3}); err != nil {
		t.Errorf("identity.read: %v", err)
	}
	for _, series := range []string{SeriesIdentity, SeriesFinding, SeriesAdvisorySet} {
		if err := CheckRemoveConfig(s, series, []Seq{3}); !isCode(err, CodeInvalid) {
			t.Errorf("%s: %v, want CodeInvalid", series, err)
		}
		if err := CheckRemoveConfig("advisory", series, []Seq{3}); !isCode(err, CodeInvalid) {
			t.Errorf("%s on the advisory stream: %v, want CodeInvalid", series, err)
		}
	}
}
