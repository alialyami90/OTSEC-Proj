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
	// Added are indices into the new read, in order.
	Added []int
	// PossibleDuplicates is how many of the first Added records may already
	// have been stored. Non-zero only when Status is ambiguous.
	PossibleDuplicates int
}

// Align compares two consecutive reads of one ring buffer, each a list of
// alignment keys in chronological order (oldest first). Between reads the
// device appends at the end and drops from the front, so the new read
// should equal prev[d:] followed by the added records, for some d.
//
// Capacity is the buffer's size in records (SEL-751: 1,024, S22 Table
// 7.63), or 0 when it is not known.
//
// The rule (A6 C-13, R-A4-1, R-A4-2):
//
//   - prev nil: first read; every record is added.
//   - prev empty (the device answered that its buffer is empty, for example
//     SEL "No Data Available", S22 p. 7.75): ok, every record is added,
//     unless the new read fills the buffer (len(next) >= capacity), when it
//     may have wrapped since the empty read: gap. With capacity unknown (0)
//     a non-empty read after an empty one is a gap: a false gap is visible,
//     a missed one is not.
//   - prev non-empty and next empty: gap (buffer cleared or device restart).
//   - no d leaves an overlap of at least one record: gap. Every record of the
//     new read is added with alignment gap-before, and the producer emits a
//     ser.gap health event. Causes include a wrapped buffer, a cleared buffer,
//     a device restart and a removed record.
//   - exactly one d fits: ok.
//   - more than one d fits (periodic identical records without an anchor):
//     ambiguous. The smallest overlap is used, so every record that may be
//     new is kept; the first PossibleDuplicates added records carry
//     possible-duplicate, and the producer emits ser.alignment-ambiguous. A
//     visible duplicate is preferred to a lost record.
//
// Identical records within one read stay separate records: alignment works
// on positions, never on a per-record key.
func Align(prev, next []string, capacity int) AlignResult {
	if prev == nil {
		return AlignResult{Status: AlignStatusFirstRead, Added: indices(0, len(next))}
	}
	if len(prev) == 0 {
		if len(next) == 0 || (capacity > 0 && len(next) < capacity) {
			return AlignResult{Status: AlignStatusOK, Added: indices(0, len(next))}
		}
		return AlignResult{Status: AlignStatusGap, Added: indices(0, len(next))}
	}
	var fits []int
	for d := 0; d < len(prev); d++ {
		tail := prev[d:]
		if len(tail) <= len(next) && equal(tail, next[:len(tail)]) {
			fits = append(fits, d)
		}
	}
	if len(fits) == 0 {
		return AlignResult{Status: AlignStatusGap, Added: indices(0, len(next))}
	}
	d := fits[len(fits)-1]
	added := indices(len(prev)-d, len(next))
	if len(fits) == 1 {
		return AlignResult{Status: AlignStatusOK, Added: added}
	}
	return AlignResult{Status: AlignStatusAmbiguous, Added: added, PossibleDuplicates: fits[len(fits)-1] - fits[0]}
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
