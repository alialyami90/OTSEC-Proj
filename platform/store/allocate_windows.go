package store

import "os"

// allocateFile makes f n bytes long. On NTFS, extending a file that is not
// sparse allocates its clusters (TestReserveHoldsItsSpace reads the
// allocation back); the bytes past what was written read as zeros.
func allocateFile(f *os.File, n int64) error { return f.Truncate(n) }
