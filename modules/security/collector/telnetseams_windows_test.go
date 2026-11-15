//go:build windows

package collector

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lingerOn reads SO_LINGER's l_onoff. Windows' struct linger is two
// u_shorts.
func lingerOn(fd uintptr) (bool, error) {
	var l [2]uint16
	n := int32(unsafe.Sizeof(l))
	err := windows.Getsockopt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_LINGER, (*byte)(unsafe.Pointer(&l)), &n)
	return l[0] != 0, err
}

// tcpInfoV0 matches TCP_INFO_v0's layout in mstcpip.h, and sioTCPInfo is
// _WSAIORW(IOC_VENDOR, 39). A wrong offset would read another field as
// BytesInFlight or BytesRetrans.
func TestTCPInfoV0Layout(t *testing.T) {
	var i tcpInfoV0
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"size", unsafe.Sizeof(i), 88},
		{"BytesInFlight", unsafe.Offsetof(i.BytesInFlight), 28},
		{"BytesOut", unsafe.Offsetof(i.BytesOut), 48},
		{"BytesRetrans", unsafe.Offsetof(i.BytesRetrans), 68},
		{"SynRetrans", unsafe.Offsetof(i.SynRetrans), 84},
		{"SIO_TCP_INFO", sioTCPInfo, 0xD8000027},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d, want %d", c.name, c.got, c.want)
		}
	}
}
