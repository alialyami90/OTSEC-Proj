package event

import (
	"reflect"
	"testing"
)

func TestAlign(t *testing.T) {
	cases := []struct {
		name       string
		prev, next []string
		want       AlignResult
	}{
		{"first read", nil, []string{"a", "b"}, AlignResult{AlignStatusFirstRead, []int{0, 1}, 0}},
		{"no change", []string{"a", "b"}, []string{"a", "b"}, AlignResult{AlignStatusOK, []int{}, 0}},
		{"append", []string{"a", "b"}, []string{"a", "b", "c"}, AlignResult{AlignStatusOK, []int{2}, 0}},
		{"append with front drop", []string{"a", "b", "c"}, []string{"b", "c", "d", "e"}, AlignResult{AlignStatusOK, []int{2, 3}, 0}},
		{"identical records anchored", []string{"a", "x"}, []string{"a", "x", "x", "x"}, AlignResult{AlignStatusOK, []int{2, 3}, 0}},
		// Overlap of 2 or 1 both fit: keep the possibly-new x, flag it (R-A4-2).
		{"identical records unanchored", []string{"x", "x"}, []string{"x", "x", "y"}, AlignResult{AlignStatusAmbiguous, []int{1, 2}, 1}},
		{"wrapped past previous read", []string{"a", "b"}, []string{"c", "d"}, AlignResult{AlignStatusGap, []int{0, 1}, 0}},
		{"cleared then one record", []string{"a", "b"}, []string{"z"}, AlignResult{AlignStatusGap, []int{0}, 0}},
		{"cleared and empty", []string{"a", "b"}, []string{}, AlignResult{AlignStatusGap, []int{}, 0}},
		{"record removed from the middle", []string{"a", "b", "c"}, []string{"a", "c", "d"}, AlignResult{AlignStatusGap, []int{0, 1, 2}, 0}},
		{"empty to empty", []string{}, []string{}, AlignResult{AlignStatusOK, nil, 0}},
		{"empty to records", []string{}, []string{"a"}, AlignResult{AlignStatusGap, []int{0}, 0}},
		{"shorter read than previous overlap", []string{"a", "b", "c", "d"}, []string{"c"}, AlignResult{AlignStatusGap, []int{0}, 0}},
	}
	for _, c := range cases {
		got := Align(c.prev, c.next)
		if got.Status != c.want.Status || got.PossibleDuplicates != c.want.PossibleDuplicates ||
			len(got.Added) != len(c.want.Added) || (len(got.Added) > 0 && !reflect.DeepEqual(got.Added, c.want.Added)) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// The alignment keys of the golden rows exclude the row number, so a new
// event that renumbers every row on the SEL-751 (row 1 is the newest) is
// not a gap (R-A4-1). The keys here are the golden examples' own.
func TestAlignGoldenKeysSurviveRenumbering(t *testing.T) {
	var keys []string
	for _, n := range []string{"8", "7", "6", "5", "4", "3", "2", "1"} {
		keys = append(keys, load(t, "testdata/valid/sel751-fig10-16-row"+n+".json").Native.AlignmentKey)
	}
	next := append(append([]string{}, keys...), "sha256:new-record")
	got := Align(keys, next)
	if got.Status != AlignStatusOK || !reflect.DeepEqual(got.Added, []int{8}) {
		t.Fatalf("got %+v", got)
	}
	// Rows 8 and 7 share a timestamp but differ in element, so their keys differ.
	if keys[0] == keys[1] {
		t.Fatal("distinct rows produced the same key")
	}
}
