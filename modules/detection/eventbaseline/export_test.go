package eventbaseline

// SetPairCap lowers the new-type pair cap for a test; SetPairPruning turns
// the sweep of expired pairs off. Each returns the function that puts it back.
func SetPairCap(n int) (restore func()) {
	old := pairCap
	pairCap = n
	return func() { pairCap = old }
}

func SetPairPruning(on bool) (restore func()) {
	old := pairPrune
	pairPrune = on
	return func() { pairPrune = old }
}

// PairCount is the number of pending (rule, type) records the detector holds.
func (d *Detector) PairCount() int { return len(d.pairs) }

// SetNewSeenMax lowers the new-type memory for a test.
func SetNewSeenMax(n int) (restore func()) {
	old := newSeenMax
	newSeenMax = n
	return func() { newSeenMax = old }
}

// ListedHeld is the held breaks the detector's pending records list, which
// the next alarm of each pair will carry.
func (d *Detector) ListedHeld() (n int64) {
	for _, pd := range d.pairs {
		n += pd.total
	}
	return n
}
