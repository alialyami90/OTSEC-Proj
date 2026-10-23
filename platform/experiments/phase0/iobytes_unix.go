//go:build !windows

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// bytesWritten returns the bytes this process has passed to write calls
// (Linux /proc/self/io wchar), or -1 where that is not available.
func bytesWritten() int64 {
	f, err := os.Open("/proc/self/io")
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "wchar: "); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
	}
	return -1
}
