//go:build windows

package collectorwire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Evidence class: this file compiles (GOOS=windows go vet) and has not yet
// run on Windows. It runs on the owner's PC once Go is installed there
// (D1-26); until then every statement below about Windows behaviour is
// documented but untested.

const (
	pipeBufferBytes = 64 << 10
	// clientAccess is what the node opens the pipe with, and all the DACL
	// grants it: read data, write data, read attributes, synchronize. Not
	// GENERIC_WRITE, because on a pipe FILE_APPEND_DATA is
	// FILE_CREATE_PIPE_INSTANCE, which would let the client create a
	// competing instance of the collector's pipe.
	clientAccess = 0x0001 | 0x0002 | 0x0080 | 0x00100000
)

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// Listen creates the collector's named pipe. The first instance is created
// with FILE_FLAG_FIRST_PIPE_INSTANCE, so if any other process already holds
// the name the collector refuses to start instead of sharing it; and one
// instance is always kept open, so the name is never free for another
// process to take. Remote clients are rejected by the pipe itself. The DACL
// grants SYSTEM and the collector's own account full access (needed to
// create further instances) and ep.Peer clientAccess only.
//
// Accept returns a connection only once the client's token, read at
// identification level, holds ep.Peer. Any other client is disconnected
// before a byte is read, and Accept returns an error wrapping
// ErrPeerRefused.
func Listen(ep Endpoint) (net.Listener, error) {
	if !strings.HasPrefix(strings.ToLower(ep.Address), `\\.\pipe\`) {
		return nil, fmt.Errorf(`collectorwire: %q is not a local pipe name (\\.\pipe\...)`, ep.Address)
	}
	peer, err := parseSID(ep.Peer)
	if err != nil {
		return nil, err
	}
	self, err := CurrentIdentity()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)(A;;0x%08x;;;%s)", self, clientAccess, peer.String()))
	if err != nil {
		return nil, fmt.Errorf("collectorwire: pipe DACL: %w", err)
	}
	name, err := windows.UTF16PtrFromString(ep.Address)
	if err != nil {
		return nil, err
	}
	closeEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	l := &pipeListener{
		name: name, addr: pipeAddr(ep.Address), peer: peer, closeEv: closeEv,
		sa: &windows.SecurityAttributes{SecurityDescriptor: sd},
	}
	l.sa.Length = uint32(unsafe.Sizeof(*l.sa))
	if l.next, err = l.instance(true); err != nil {
		windows.CloseHandle(closeEv)
		return nil, fmt.Errorf("collectorwire: create %s: %w", ep.Address, err)
	}
	return l, nil
}

type pipeListener struct {
	name    *uint16
	addr    pipeAddr
	peer    *windows.SID
	sa      *windows.SecurityAttributes
	closeEv windows.Handle

	acceptMu sync.Mutex // one Accept at a time; Close waits for it
	mu       sync.Mutex
	next     windows.Handle // the instance waiting for the next client
	closed   bool
}

func (l *pipeListener) instance(first bool) (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(l.name, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, pipeBufferBytes, pipeBufferBytes, 0, l.sa)
}

func (l *pipeListener) Accept() (net.Conn, error) {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	h := l.next
	l.mu.Unlock()

	if err := connectPipe(h, l.closeEv); err != nil {
		return nil, err
	}
	// Create the next instance before handing this one off, so the name
	// stays held by the collector. If that fails the listener cannot go on
	// safely: it stops, and the service fails closed.
	nh, err := l.instance(false)
	l.mu.Lock()
	if err != nil {
		l.next = 0
		l.closed = true
	} else {
		l.next = nh
	}
	l.mu.Unlock()
	if err != nil {
		windows.DisconnectNamedPipe(h)
		windows.CloseHandle(h)
		return nil, fmt.Errorf("collectorwire: create next pipe instance: %w", err)
	}
	if err := checkClient(h, l.peer); err != nil {
		windows.DisconnectNamedPipe(h)
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %v", ErrPeerRefused, err)
	}
	return newPipeConn(h, l.addr), nil
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed && l.next == 0 && l.closeEv == 0 {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()
	windows.SetEvent(l.closeEv)
	l.acceptMu.Lock() // wait for a pending Accept to see the event
	defer l.acceptMu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next != 0 {
		windows.CloseHandle(l.next)
		l.next = 0
	}
	if l.closeEv != 0 {
		windows.CloseHandle(l.closeEv)
		l.closeEv = 0
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

// connectPipe waits for a client on an overlapped pipe instance, or until
// cancel is signalled.
func connectPipe(h, cancel windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev}
	switch err := windows.ConnectNamedPipe(h, ov); err {
	case nil, windows.ERROR_PIPE_CONNECTED:
		return nil
	case windows.ERROR_IO_PENDING:
	default:
		return err
	}
	which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, cancel}, false, windows.INFINITE)
	var n uint32
	if err != nil || which != windows.WAIT_OBJECT_0 {
		windows.CancelIoEx(h, ov)
		windows.GetOverlappedResult(h, ov, &n, true) // the kernel is done with ov after this
		if err != nil {
			return err
		}
		return net.ErrClosed
	}
	return windows.GetOverlappedResult(h, ov, &n, false)
}

// checkClient reads the client's token at identification level and accepts
// it only if it holds want. The node opens the pipe with
// SECURITY_IDENTIFICATION, and the collector holds no SeImpersonatePrivilege
// (W-2), so the thread token can be queried but not used to act as the
// client.
func checkClient(h windows.Handle, want *windows.SID) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", e)
	}
	var tok windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// A thread still carrying the client's token must not run any more
		// collector code.
		panic("collectorwire: RevertToSelf failed: " + rerr.Error())
	}
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer tok.Close()
	return tokenHolds(tok, want)
}

// Dial opens the collector's pipe at identification level and returns the
// connection only if the server process's token holds ep.Peer. Nothing is
// sent before the check.
//
// Open item for the PC run: a service process token's default DACL may not
// grant another service TOKEN_QUERY. If it does not, Dial fails closed, and
// the collector must grant the node's SID TOKEN_QUERY on its own token at
// startup.
func Dial(ctx context.Context, ep Endpoint) (net.Conn, error) {
	want, err := parseSID(ep.Peer)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(ep.Address)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	for {
		h, err = windows.CreateFile(name, clientAccess, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := checkServer(h, want); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %v", ErrPeerRefused, err)
	}
	return newPipeConn(h, pipeAddr(ep.Address)), nil
}

func checkServer(h windows.Handle, want *windows.SID) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		return fmt.Errorf("GetNamedPipeServerProcessId: %w", err)
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess %d: %w", pid, err)
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return fmt.Errorf("OpenProcessToken %d: %w", pid, err)
	}
	defer tok.Close()
	return tokenHolds(tok, want)
}

// tokenHolds accepts a token whose user is want, or which carries want as
// an enabled group that is not deny-only. A service's own SID appears in its
// process token as such a group.
func tokenHolds(tok windows.Token, want *windows.SID) error {
	u, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	if u.User.Sid.Equals(want) {
		return nil
	}
	g, err := tok.GetTokenGroups()
	if err != nil {
		return err
	}
	for _, a := range g.AllGroups() {
		if a.Attributes&windows.SE_GROUP_ENABLED != 0 && a.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 && a.Sid.Equals(want) {
			return nil
		}
	}
	return fmt.Errorf("token user %s does not hold %s", u.User.Sid.String(), want.String())
}

// CurrentIdentity returns this process's token user SID.
func CurrentIdentity() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

func parseSID(s string) (*windows.SID, error) {
	if s == "" {
		return nil, errors.New("collectorwire: endpoint has no peer identity")
	}
	sid, err := windows.StringToSid(s)
	if err != nil {
		return nil, fmt.Errorf("collectorwire: peer %q is not a SID: %w", s, err)
	}
	return sid, nil
}

// pipeConn is a net.Conn over an overlapped pipe handle. os.NewFile
// associates the handle with the runtime's I/O completion port (Go 1.25 and
// later), which gives reads and writes deadlines.
type pipeConn struct {
	*os.File
	addr pipeAddr
}

func newPipeConn(h windows.Handle, a pipeAddr) *pipeConn {
	return &pipeConn{File: os.NewFile(uintptr(h), string(a)), addr: a}
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.addr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.addr }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }
