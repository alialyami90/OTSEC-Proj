//go:build windows

package collector

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioTCPInfo is SIO_TCP_INFO, _WSAIORW(IOC_VENDOR, 39) (mstcpip.h).
// golang.org/x/sys has neither it nor TCP_INFO_v0.
const sioTCPInfo = windows.IOC_INOUT | windows.IOC_VENDOR | 39

// tcpInfoV0 is TCP_INFO_v0 (mstcpip.h; Windows 10 1703 and later).
type tcpInfoV0 struct {
	State             uint32 // TCPSTATE
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint8 // BOOLEAN
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
}

// readTCPInfo is WSAIoctl(SIO_TCP_INFO) at version 0, which reads and sets
// nothing. Its documentation gives WSAEINVAL when the control code is not a
// valid command or does not apply to the socket, which is how a build before
// 1703 answers (desk: not run on such a build); any other error is a failed
// call. Windows has no unsent-octets field (§1.4).
func readTCPInfo(fd uintptr) (sockCounts, error) {
	version := uint32(0)
	var info tcpInfoV0
	var n uint32
	err := windows.WSAIoctl(windows.Handle(fd), sioTCPInfo,
		(*byte)(unsafe.Pointer(&version)), uint32(unsafe.Sizeof(version)),
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &n, nil, 0)
	if errors.Is(err, windows.WSAEINVAL) {
		return sockCounts{}, nil
	}
	if err != nil {
		return sockCounts{}, err
	}
	return sockCounts{
		supported: uintptr(n) >= unsafe.Offsetof(info.BytesRetrans)+unsafe.Sizeof(info.BytesRetrans),
		unacked:   uint64(info.BytesInFlight),
		retrans:   uint64(info.BytesRetrans),
	}, nil
}
