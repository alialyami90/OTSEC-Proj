//go:build windows

package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"otsec.local/otsec/modules/security/collectorwire"
)

// A6's independent test of the collector pipe between two installed
// services (A3, #180; D3-9 as proposed). The claims, from #180's text:
//
//	(a) a node service dials a collector service under another virtual
//	    account and verifies it, because the collector's Listen granted the
//	    node PROCESS_QUERY_LIMITED_INFORMATION and TOKEN_QUERY;
//	(b) with those rights the node gains nothing else: it cannot read the
//	    collector's memory, duplicate its handles, terminate it, or
//	    duplicate, impersonate or assign its token;
//	(c) a server under any other account is refused, even one that grants
//	    the node the same rights, and nothing is sent to it;
//	(d) a server under the collector's own account that has not granted
//	    the rights (a pipe made without Listen) is refused: the check fails
//	    closed.
//
// The accounts are real Windows virtual service accounts (NT SERVICE\name),
// each a service running this test binary as TestA6PipeHelper. The test
// makes services, so it runs only on the GitHub-hosted Windows runner,
// never on the owner's PC (D2-13). There it must run: a runner that is not
// elevated fails it.
//
// Evidence class: the hosted Windows runner.

func TestA6PipeHelper(t *testing.T) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		t.Skip("runs only as a service that TestA6PipeIdentityServices starts")
	}
	svc.Run("", a6pipeHelper{})
}

type a6pipeHelper struct{}

// a6pipeResult is what a helper role writes for the test to read.
type a6pipeResult struct {
	PID      uint32            `json:"pid,omitempty"`
	Err      string            `json:"err,omitempty"`
	Refused  bool              `json:"refused,omitempty"`
	Received int               `json:"received"`
	Probes   map[string]string `json:"probes,omitempty"`
}

func (a6pipeHelper) Execute(args []string, _ <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running}
	defer func() { s <- svc.Status{State: svc.StopPending} }()
	if len(args) < 2 {
		return false, 1
	}
	var r a6pipeResult
	var out string
	switch args[1] {
	case "serve": // pipe, peer, ready, out
		if len(args) != 6 {
			return false, 1
		}
		out = args[5]
		r = a6serve(args[2], args[3], args[4])
	case "raw": // pipe, peer, ready, out
		if len(args) != 6 {
			return false, 1
		}
		out = args[5]
		r = a6raw(args[2], args[3], args[4])
	case "dial": // pipe, peer, server pid, out
		if len(args) != 6 {
			return false, 1
		}
		out = args[5]
		pid, err := strconv.ParseUint(args[4], 10, 32)
		if err != nil {
			return false, 2
		}
		r = a6dial(args[2], args[3], uint32(pid))
	default:
		return false, 1
	}
	b, _ := json.Marshal(r)
	if os.WriteFile(out, b, 0o644) != nil {
		return false, 3
	}
	return false, 0
}

// a6ready tells the test this process's ID once its pipe exists.
func a6ready(path string, err error) {
	b, _ := json.Marshal(a6pipeResult{PID: windows.GetCurrentProcessId(), Err: errString(err)})
	os.WriteFile(path, b, 0o644)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// a6count reads from c for a few seconds and returns how many bytes came.
func a6count(c io.ReadCloser) int {
	n := make(chan int, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(c, 1<<10))
		n <- len(b)
	}()
	select {
	case got := <-n:
		return got
	case <-time.After(5 * time.Second):
		c.Close()
		return <-n
	}
}

// a6serve is a collector: collectorwire.Listen with the node as peer, one
// connection accepted, and what arrives on it counted.
func a6serve(pipe, peer, ready string) a6pipeResult {
	ln, err := collectorwire.Listen(collectorwire.Endpoint{Address: pipe, Peer: peer})
	a6ready(ready, err)
	if err != nil {
		return a6pipeResult{Err: err.Error()}
	}
	timer := time.AfterFunc(60*time.Second, func() { ln.Close() })
	defer timer.Stop()
	c, err := ln.Accept()
	ln.Close()
	if err != nil {
		return a6pipeResult{Err: "accept: " + err.Error()}
	}
	defer c.Close()
	return a6pipeResult{Received: a6count(c)}
}

// a6raw is a server that makes the pipe itself, open to the node, without
// Listen and so without granting the node anything.
func a6raw(pipe, peer, ready string) a6pipeResult {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + peer + ")")
	if err != nil {
		a6ready(ready, err)
		return a6pipeResult{Err: err.Error()}
	}
	name, _ := windows.UTF16PtrFromString(pipe)
	h, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0,
		&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
	a6ready(ready, err)
	if err != nil {
		return a6pipeResult{Err: err.Error()}
	}
	f := os.NewFile(uintptr(h), pipe)
	connected := make(chan error, 1)
	go func() { connected <- windows.ConnectNamedPipe(h, nil) }()
	select {
	case err := <-connected:
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			f.Close()
			return a6pipeResult{Err: "connect: " + err.Error()}
		}
	case <-time.After(60 * time.Second):
		f.Close()
		return a6pipeResult{Err: "no client"}
	}
	defer f.Close()
	return a6pipeResult{Received: a6count(f)}
}

// a6dial is the node: Dial with the collector as peer, two bytes sent on
// success, and then what the node can open of the server process and its
// token beyond the two granted rights.
func a6dial(pipe, peer string, pid uint32) a6pipeResult {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var r a6pipeResult
	c, err := collectorwire.Dial(ctx, collectorwire.Endpoint{Address: pipe, Peer: peer})
	r.Err, r.Refused = errString(err), errors.Is(err, collectorwire.ErrPeerRefused)
	if err == nil {
		c.Write([]byte("a6"))
		c.Close()
	}
	r.Probes = map[string]string{}
	open := func(label string, access uint32) {
		h, err := windows.OpenProcess(access, false, pid)
		if err != nil {
			r.Probes[label] = err.Error()
			return
		}
		windows.CloseHandle(h)
		r.Probes[label] = "ok"
	}
	open("process query limited", windows.PROCESS_QUERY_LIMITED_INFORMATION)
	open("process query", windows.PROCESS_QUERY_INFORMATION)
	open("process vm read", windows.PROCESS_VM_READ)
	open("process dup handle", windows.PROCESS_DUP_HANDLE)
	open("process terminate", windows.PROCESS_TERMINATE)
	open("process read control", windows.READ_CONTROL)
	open("process write dac", windows.WRITE_DAC)
	open("process synchronize", windows.SYNCHRONIZE)
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return r
	}
	defer windows.CloseHandle(p)
	token := func(label string, access uint32) {
		var tok windows.Token
		if err := windows.OpenProcessToken(p, access, &tok); err != nil {
			r.Probes[label] = err.Error()
			return
		}
		tok.Close()
		r.Probes[label] = "ok"
	}
	token("token query", windows.TOKEN_QUERY)
	token("token duplicate", windows.TOKEN_DUPLICATE)
	token("token impersonate", windows.TOKEN_IMPERSONATE)
	token("token assign primary", windows.TOKEN_ASSIGN_PRIMARY)
	token("token adjust default", windows.TOKEN_ADJUST_DEFAULT)
	token("token adjust privileges", windows.TOKEN_ADJUST_PRIVILEGES)
	token("token write dac", windows.WRITE_DAC)
	return r
}

func TestA6PipeIdentityServices(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("makes services: the GitHub-hosted Windows runner only (D2-13)")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("the hosted runner is not elevated: this test must run there, not skip")
	}
	tag := a6tag(t)
	dir := `C:\a6cw-` + tag
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "a6cw.test.exe")
	a6copy(t, self, exe)

	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	service := func(name string) *mgr.Service {
		s, err := m.CreateService(name, exe, mgr.Config{DisplayName: "OTSEC A6 pipe identity test " + name, ServiceStartName: `NT SERVICE\` + name,
			SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "-test.run=^TestA6PipeHelper$")
		if err != nil {
			t.Fatalf("create service %s: %v", name, err)
		}
		t.Cleanup(func() {
			s.Control(svc.Stop)
			s.Delete()
			s.Close()
		})
		return s
	}
	colName, nodeName, otherName := "a6cwcol"+tag, "a6cwnode"+tag, "a6cwother"+tag
	colSvc, nodeSvc, otherSvc := service(colName), service(nodeName), service(otherName)
	colSID, nodeSID := collectorwire.ServiceSID(colName), collectorwire.ServiceSID(nodeName)

	wait := func(s *mgr.Service, label string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			st, err := s.Query()
			if err == nil && st.State == svc.Stopped {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: service did not stop: %+v %v", label, st, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	readResult := func(path, label string) a6pipeResult {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: no result: %v", label, err)
		}
		var r a6pipeResult
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		t.Logf("%s: %s", label, b)
		return r
	}
	// scenario runs role on server, waits for its pipe, dials it from the
	// node service, and returns the server's and the node's results.
	scenario := func(label string, server *mgr.Service, role string) (srv, node a6pipeResult) {
		t.Helper()
		pipe := `\\.\pipe\a6cw-` + tag + "-" + label
		ready, sout, nout := filepath.Join(dir, label+".ready"), filepath.Join(dir, label+".server"), filepath.Join(dir, label+".node")
		if err := server.Start(role, pipe, nodeSID, ready, sout); err != nil {
			t.Fatalf("%s: start server: %v", label, err)
		}
		var r a6pipeResult
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			if b, err := os.ReadFile(ready); err == nil && json.Unmarshal(b, &r) == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the server never made its pipe", label)
			}
		}
		if r.Err != "" {
			t.Fatalf("%s: server: %s", label, r.Err)
		}
		if err := nodeSvc.Start("dial", pipe, colSID, fmt.Sprint(r.PID), nout); err != nil {
			t.Fatalf("%s: start node: %v", label, err)
		}
		wait(nodeSvc, label+" node")
		wait(server, label+" server")
		return readResult(sout, label+" server"), readResult(nout, label+" node")
	}

	// (a) and (b): the collector, through Listen.
	srv, node := scenario("collector", colSvc, "serve")
	if node.Err != "" || srv.Received != 2 {
		t.Errorf("(a) the node did not reach the collector: node %q, collector received %d bytes (%s)", node.Err, srv.Received, srv.Err)
	}
	for probe, want := range map[string]bool{
		"process query limited": true, "process query": false, "process vm read": false, "process dup handle": false,
		"process terminate": false, "process read control": false, "process write dac": false, "process synchronize": false,
		"token query": true, "token duplicate": false, "token impersonate": false, "token assign primary": false,
		"token adjust default": false, "token adjust privileges": false, "token write dac": false,
	} {
		got, ok := node.Probes[probe]
		if !ok {
			t.Errorf("(b) %s: not probed", probe)
		} else if (got == "ok") != want {
			t.Errorf("(b) the node's %s on the collector: %s, want allowed=%v", probe, got, want)
		}
	}

	// (c): a server under another account that grants the node the same
	// rights, through Listen. Refused, and nothing reaches it.
	srv, node = scenario("other", otherSvc, "serve")
	if !node.Refused || srv.Received != 0 {
		t.Errorf("(c) another account's server: node %q (refused %v), server received %d bytes", node.Err, node.Refused, srv.Received)
	}

	// (d): a pipe under the collector's account made without Listen, so
	// nothing is granted. Refused, and nothing reaches it.
	srv, node = scenario("raw", colSvc, "raw")
	if !node.Refused || srv.Received != 0 {
		t.Errorf("(d) the collector's account without the grant: node %q (refused %v), server received %d bytes", node.Err, node.Refused, srv.Received)
	}
	if got := node.Probes["process query limited"]; got == "ok" {
		t.Errorf("(d) control: the node opened a server that granted nothing (%s), so (a) does not show the grant is what lets it in", got)
	}
}
