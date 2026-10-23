//go:build !windows

package main

import "syscall"

func fsFree(dir string) int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return -1
	}
	return int64(st.Bavail) * st.Bsize
}
