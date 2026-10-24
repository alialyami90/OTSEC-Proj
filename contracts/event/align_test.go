package event

import (
	"errors"
	"reflect"
	"testing"
)

func TestAlign(t *testing.T) {
	cases := []struct {
		name       string
		prev, next []string
		status     AlignStatus
		added      []int
		dups       []int
		removed    []int
	}{
		{"first read", nil, []string{"a", "b"}, AlignStatusFirstRead, []int{0, 1}, nil, nil},
		{"no change", []string{"a", "b"}, []string{"a", "b"}, AlignStatusOK, nil, nil, nil},
		{"append", []string{"a", "b"}, []string{"a", "b", "c"}, AlignStatusOK, []int{2}, nil, nil},
		{"append with front drop", []string{"a", "b", "c"}, []string{"b", "c", "d", "e"}, AlignStatusOK, []int{2, 3}, nil, nil},
		{"identical records anchored", []string{"a", "x"}, []string{"a", "x", "x", "x"}, AlignStatusOK, []int{2, 3}, nil, nil},
		// Overlap of 2 or 1 both fit: keep the possibly-new x, flag it (R-A4-2).
		{"identical records unanchored", []string{"x", "x"}, []string{"x", "x", "y"}, AlignStatusAmbiguous, []int{1, 2}, []int{1}, nil},
		{"periodic tail", []string{"a", "a", "a"}, []string{"a", "a", "a", "a"}, AlignStatusAmbiguous, []int{1, 2, 3}, []int{1, 2}, nil},
		{"wrapped past previous read", []string{"a", "b"}, []string{"c", "d"}, AlignStatusGap, []int{0, 1}, nil, nil},
		{"cleared then one record", []string{"a", "b"}, []string{"z"}, AlignStatusGap, []int{0}, nil, nil},
		{"cleared and empty", []string{"a", "b"}, []string{}, AlignStatusGap, nil, nil, nil},
		// A6 C4 review change 1 (V-S4): records already stored are not
		// stored again; the removed or changed record is reported.
		{"record removed from the middle", []string{"a", "b", "c", "d"}, []string{"a", "c", "d", "e"}, AlignStatusGap, []int{3}, nil, []int{1}},
		{"record changed in place", []string{"a", "b", "c"}, []string{"a", "B", "c", "d"}, AlignStatusGap, []int{1, 2, 3}, []int{2}, []int{1}},
		// A6 re-check S-1: 0' has 0's key but follows a new record, so it is new.
		{"old key after a new record", []string{"1", "3", "0"}, []string{"4", "0", "5"}, AlignStatusGap, []int{0, 1, 2}, []int{1}, nil},
		{"record missing at the end", []string{"a", "b", "c", "d"}, []string{"c"}, AlignStatusGap, nil, nil, []int{3}},
		{"reordered", []string{"a", "x", "b"}, []string{"x", "a", "c"}, AlignStatusGap, []int{1, 2}, []int{1}, []int{2}},
		{"empty to empty", []string{}, []string{}, AlignStatusOK, nil, nil, nil},
		// SEL "No Data Available", then rows (A1 D1-7, A6 question 4).
		{"empty to records", []string{}, []string{"a", "b"}, AlignStatusOK, []int{0, 1}, nil, nil},
	}
	same := func(a, b []int) bool { return len(a) == len(b) && (len(a) == 0 || reflect.DeepEqual(a, b)) }
	for _, c := range cases {
		got, err := Align(c.prev, c.next)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.Status != c.status || !same(got.Added, c.added) || !same(got.PossibleDuplicates, c.dups) || !same(got.Removed, c.removed) {
			t.Errorf("%s: got %+v, want status %s added %v dups %v removed %v", c.name, got, c.status, c.added, c.dups, c.removed)
		}
	}
}

// For every pair of reads: Added holds valid, distinct indices, and every
// record of the new read that is not added is matched, one for one, by a
// record of the previous read. So nothing is lost and nothing matched is
// stored twice.
func TestAlignNeverLosesOrRestores(t *testing.T) {
	reads := [][]string{
		{"a", "b", "c"}, {"b", "c", "d"}, {"x"}, {"a", "c"}, {"c", "a"}, {"a", "a", "b"}, {"b", "a", "a"}, {},
	}
	for _, prev := range reads {
		for _, next := range reads {
			r, err := Align(prev, next)
			if err != nil {
				t.Fatal(err)
			}
			added := map[int]bool{}
			for _, j := range r.Added {
				if j < 0 || j >= len(next) || added[j] {
					t.Fatalf("%v -> %v: bad Added %v", prev, next, r.Added)
				}
				added[j] = true
			}
			count := map[string]int{}
			for _, k := range prev {
				count[k]++
			}
			for j, k := range next {
				if !added[j] {
					if count[k] == 0 {
						t.Errorf("%v -> %v: %q at %d neither added nor in the previous read", prev, next, k, j)
					}
					count[k]--
				}
			}
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
	got, err := Align(keys, next)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != AlignStatusOK || !reflect.DeepEqual(got.Added, []int{8}) {
		t.Fatalf("got %+v", got)
	}
	// Rows 8 and 7 share a timestamp but differ in element, so their keys differ.
	if keys[0] == keys[1] {
		t.Fatal("distinct rows produced the same key")
	}
}

// D1-12: a read over MaxAlignRows on either side is refused before anything
// is allocated; a read of exactly MaxAlignRows is aligned.
func TestAlignRefusesOversizeRead(t *testing.T) {
	rows := func(n int, tag string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = tag
		}
		return out
	}
	big := rows(50000, "x")
	limit := rows(MaxAlignRows, "y")
	for _, c := range []struct {
		name       string
		prev, next []string
	}{
		{"oversize next", limit, big},
		{"oversize prev", big, limit},
		{"oversize next on first read", nil, big},
		{"one over", limit, rows(MaxAlignRows+1, "z")},
	} {
		if _, err := Align(c.prev, c.next); !errors.Is(err, ErrAlignTooLong) {
			t.Errorf("%s: got %v, want ErrAlignTooLong", c.name, err)
		}
		if a := testing.AllocsPerRun(5, func() { Align(c.prev, c.next) }); a != 0 {
			t.Errorf("%s: %v allocations, want none", c.name, a)
		}
	}
	// At the ceiling, the gap path runs: every key differs between the reads.
	r, err := Align(limit, rows(MaxAlignRows, "w"))
	if err != nil || r.Status != AlignStatusGap || len(r.Added) != MaxAlignRows {
		t.Fatalf("at the ceiling: status %s, %d added, err %v", r.Status, len(r.Added), err)
	}
}
