//go:build windows

package collectorwire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func testAddress(t *testing.T) string {
	b := make([]byte, 8)
	rand.Read(b)
	return `\\.\pipe\otsec-test-` + hex.EncodeToString(b)
}

// otherIdentity is LocalService, which the test process does not run as.
func otherIdentity(t *testing.T) string {
	if self(t) == "S-1-5-19" {
		t.Skip("test runs as LocalService")
	}
	return "S-1-5-19"
}

func TestListenRefusesRemotePipeName(t *testing.T) {
	if ln, err := Listen(Endpoint{Address: `\\server\pipe\x`, Peer: self(t)}); err == nil {
		ln.Close()
		t.Fatal("listened on a remote pipe name")
	}
}

// A client that opens the waiting instance and closes it before Accept is
// called makes ConnectNamedPipe fail with ERROR_NO_DATA. Accept must treat
// that as no connection and serve the next client; it once returned the
// error, which stopped the collector's Serve loop (A6's flake in
// TestTransportRefusesOtherServer under load).
func TestAcceptAfterClientWentAway(t *testing.T) {
	ln, ep := listenSelf(t, self(t))
	name, err := windows.UTF16PtrFromString(ep.Address)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, clientAccess, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatalf("open the waiting instance: %v", err)
	}
	windows.CloseHandle(h)

	type accepted struct {
		b   []byte
		err error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- accepted{err: err}
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 2)
		_, err = io.ReadFull(c, b)
		done <- accepted{b, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ep)
	if err != nil {
		t.Fatalf("Dial after a client went away: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if a := <-done; a.err != nil || string(a.b) != "ok" {
		t.Fatalf("Accept after a client went away: %q %v", a.b, a.err)
	}
}

// Listen grants the peer PROCESS_QUERY_LIMITED_INFORMATION on this process
// and TOKEN_QUERY on its token, exactly those, in one entry each however
// often it is called, and keeps every other entry.
// Without them a node under another virtual account cannot check the
// collector, and every dial fails closed (A5's service-mode dry run).
func TestListenGrantsPeerQuery(t *testing.T) {
	b := make([]byte, 8)
	rand.Read(b)
	peer := ServiceSID("otsec-test-" + hex.EncodeToString(b))
	sid, err := windows.StringToSid(peer)
	if err != nil {
		t.Fatal(err)
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.READ_CONTROL, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	objects := []struct {
		name string
		h    windows.Handle
		want windows.ACCESS_MASK
	}{
		{"process", windows.CurrentProcess(), windows.PROCESS_QUERY_LIMITED_INFORMATION},
		{"token", windows.Handle(tok), windows.TOKEN_QUERY},
	}
	before := make([][]allowEntry, len(objects))
	for i, o := range objects {
		before[i] = allowEntries(t, o.h)
		for _, e := range before[i] {
			if e.sid.Equals(sid) {
				t.Fatalf("%s: the new SID already has an entry", o.name)
			}
		}
	}

	// Twice, as a restarted listener in the same process would: the grant
	// merges into one entry per object (A5 on #180).
	for range 2 {
		ln, err := Listen(Endpoint{Address: testAddress(t), Peer: peer})
		if err != nil {
			t.Fatal(err)
		}
		ln.Close()
	}

	for i, o := range objects {
		after := allowEntries(t, o.h)
		var got []windows.ACCESS_MASK
		var rest []allowEntry
		for _, e := range after {
			if e.sid.Equals(sid) {
				got = append(got, e.mask)
			} else {
				rest = append(rest, e)
			}
		}
		if len(got) != 1 || got[0] != o.want {
			t.Errorf("%s: peer entries %#x, want exactly one of %#x", o.name, got, o.want)
		}
		if len(rest) != len(before[i]) {
			t.Errorf("%s: %d other entries after Listen, %d before", o.name, len(rest), len(before[i]))
			continue
		}
		for j := range rest {
			if !rest[j].sid.Equals(before[i][j].sid) || rest[j].mask != before[i][j].mask {
				t.Errorf("%s: entry %d changed from %s %#x to %s %#x", o.name, j,
					before[i][j].sid, before[i][j].mask, rest[j].sid, rest[j].mask)
			}
		}
	}
}

type allowEntry struct {
	sid  *windows.SID
	mask windows.ACCESS_MASK
}

// allowEntries lists the allow entries of h's DACL, in order.
func allowEntries(t *testing.T, h windows.Handle) []allowEntry {
	t.Helper()
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	var out []allowEntry
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		c, err := sid.Copy()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, allowEntry{c, ace.Mask})
	}
	return out
}
