package eventbaseline

// SetSnapshotLimit lowers the largest snapshot for a test and returns the
// function that puts it back.
func SetSnapshotLimit(n int) (restore func()) {
	old := snapshotLimit
	snapshotLimit = n
	return func() { snapshotLimit = old }
}
