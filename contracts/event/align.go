package event

// AlignStatus is the outcome of comparing two consecutive reads of a
// ring-buffer source. Closed.
type AlignStatus string

const (
	AlignStatusFirstRead AlignStatus = "first-read"
	AlignStatusOK        AlignStatus = "ok"
	AlignStatusGap       AlignStatus = "gap"
	AlignStatusAmbiguous AlignStatus = "ambiguous"
)

// AlignResult says which records of the new read are new.
type AlignResult struct {
	Status AlignStatus
	// Added are indices into the new read, in order: the records to store.
	// A record already stored from the previous read is never in Added.
	Added []int
	// PossibleDuplicates are the indices in Added that may already have been
	// stored, because identical records make the match uncertain. They are
	// stored with alignment possible-duplicate and the producer emits
	// ser.alignment-ambiguous: a visible duplicate is preferred to a lost
	// record.
	PossibleDuplicates []int
	// Removed are indices into the previous read of records that are missing
	// from the new read although later records survived, so they did not
	// simply age out of the front of the buffer. Set only with Status gap.
	// They are evidence of a cleared, edited or restarted buffer and go into
	// the ser.gap health event.
	Removed []int
}

// Align compares two consecutive reads of one ring buffer, each a list of
// alignment keys in chronological order (oldest first). Between reads the
// device appends at the end and drops from the front, so the new read
// should equal prev[d:] followed by the added records, for some d.
//
// The rule (A6 C-13, R-A4-1, R-A4-2, V-S4):
//
//   - prev nil: first read; every record is added.
//   - prev empty (the device answered that its buffer is empty, for example
//     SEL "No Data Available", S22 p. 7.75): ok, every record is added.
//     Nothing can have been dropped from an empty read, so a cleared buffer
//     raises exactly one gap, at the clear (A1 decision D1-7).
//   - exactly one d fits: ok.
//   - more than one d fits (periodic identical records without an anchor):
//     ambiguous. The smallest overlap is used, so every record that may be
//     new is kept; the first records of Added are PossibleDuplicates.
//   - no d fits: gap. Records were removed or changed, the buffer was
//     cleared, the device restarted, or the buffer wrapped past the previous
//     read. The two reads are matched on their longest common subsequence,
//     so records already stored are not stored again under new IDs. Records
//     of the new read outside the match are added; those whose key also
//     occurs in the previous read are PossibleDuplicates. Records of the
//     previous read outside the match, after the first matched one, are
//     Removed. Every added record that is not a possible duplicate carries
//     gap-before, and the producer emits ser.gap.
//
// What cannot be detected: if the buffer wraps completely between two reads,
// so that the new read shares nothing with the previous one, the records in
// between are lost without trace. Align reports gap when the previous read
// held records, but after an empty read the loss is invisible, and in
// neither case can it say how many records were lost: the SEL-751 record
// carries no sequence number (C-06). Polling often enough that the buffer
// cannot wrap between reads is the producer's job.
//
// Identical records within one read stay separate records: alignment works
// on positions, never on a per-record key.
func Align(prev, next []string) AlignResult {
	if prev == nil {
		return AlignResult{Status: AlignStatusFirstRead, Added: indices(0, len(next))}
	}
	if len(prev) == 0 {
		return AlignResult{Status: AlignStatusOK, Added: indices(0, len(next))}
	}
	var fits []int
	for d := 0; d < len(prev); d++ {
		tail := prev[d:]
		if len(tail) <= len(next) && equal(tail, next[:len(tail)]) {
			fits = append(fits, d)
		}
	}
	if len(fits) == 0 {
		return realign(prev, next)
	}
	d := fits[len(fits)-1]
	added := indices(len(prev)-d, len(next))
	if len(fits) == 1 {
		return AlignResult{Status: AlignStatusOK, Added: added}
	}
	return AlignResult{Status: AlignStatusAmbiguous, Added: added, PossibleDuplicates: added[:fits[len(fits)-1]-fits[0]]}
}

// realign matches two reads that do not overlap as a suffix and a prefix,
// on their longest common subsequence. Ties are broken the same way every
// time: equal keys are matched as early as possible, and otherwise a record
// of the previous read is skipped before one of the new read.
func realign(prev, next []string) AlignResult {
	n, m := len(prev), len(next)
	// lcs[i*(m+1)+j] is the length of the LCS of prev[i:] and next[j:].
	lcs := make([]int32, (n+1)*(m+1))
	at := func(i, j int) int32 { return lcs[i*(m+1)+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			v := max(at(i+1, j), at(i, j+1))
			if prev[i] == next[j] {
				v = at(i+1, j+1) + 1
			}
			lcs[i*(m+1)+j] = v
		}
	}
	matchedPrev := make([]bool, n)
	matchedNext := make([]bool, m)
	for i, j := 0, 0; i < n && j < m; {
		switch {
		case prev[i] == next[j]:
			matchedPrev[i], matchedNext[j] = true, true
			i, j = i+1, j+1
		case at(i+1, j) >= at(i, j+1):
			i++
		default:
			j++
		}
	}
	inPrev := make(map[string]bool, n)
	for _, k := range prev {
		inPrev[k] = true
	}
	r := AlignResult{Status: AlignStatusGap, Added: []int{}}
	for j := range next {
		if !matchedNext[j] {
			r.Added = append(r.Added, j)
			if inPrev[next[j]] {
				r.PossibleDuplicates = append(r.PossibleDuplicates, j)
			}
		}
	}
	first := -1
	for i := range prev {
		if matchedPrev[i] {
			if first < 0 {
				first = i
			}
		} else if first >= 0 {
			r.Removed = append(r.Removed, i)
		}
	}
	return r
}

func indices(from, to int) []int {
	out := make([]int, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

func equal(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
