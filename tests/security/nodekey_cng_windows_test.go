//go:build windows

package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"otsec.local/otsec/modules/security/nodekey"
)

// A6's independent tests of the node key claims A1 set on #157 (D3-7):
//
//	(a) no account can export the private key, under any blob type;
//	(b) a plain user and a service account that is not the node service
//	    can neither open the key nor sign with it;
//	(c) the node service can sign and cannot export.
//
// The accounts are real: Windows virtual service accounts (NT SERVICE\name,
// the kind the node and collector services run as) and LocalSystem, each a
// service running this test binary as TestA6NodeKeyHelper; a local user
// logged on and impersonated; and this elevated process as Administrators.
// Each refusal has a control: a second key that grants the same account
// use, which it must then be able to sign with, so a refusal is the key's
// DACL and not the rig.
//
// The test makes machine keys, services and a local user, so it runs only
// on the GitHub-hosted Windows runner, never on the owner's PC (D2-13).
// There it must run: a runner that is not elevated fails it.
//
// Evidence class: the hosted Windows runner (Software KSP); the TPM
// provider is not covered (T-2).

var (
	a6ncrypt     = windows.NewLazySystemDLL("ncrypt.dll")
	a6OpenProv   = a6ncrypt.NewProc("NCryptOpenStorageProvider")
	a6OpenKey    = a6ncrypt.NewProc("NCryptOpenKey")
	a6ExportKey  = a6ncrypt.NewProc("NCryptExportKey")
	a6SetProp    = a6ncrypt.NewProc("NCryptSetProperty")
	a6FreeObject = a6ncrypt.NewProc("NCryptFreeObject")
	a6netapi     = windows.NewLazySystemDLL("netapi32.dll")
	a6NetUserAdd = a6netapi.NewProc("NetUserAdd")
	a6NetUserDel = a6netapi.NewProc("NetUserDel")
	a6advapi     = windows.NewLazySystemDLL("advapi32.dll")
	a6LogonUser  = a6advapi.NewProc("LogonUserW")
)

const (
	a6MachineKey = 0x20
	a6Silent     = 0x40
	a6Persist    = 0x80000000
	// NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
	a6AllowExport = 0x1 | 0x2
)

// a6PrivateBlobs are the blob types that carry a private key, or wrap one
// for transport. Each must be refused for every account.
var a6PrivateBlobs = []string{
	"ECCPRIVATEBLOB", "ECCFULLPRIVATEBLOB", "PRIVATEBLOB", "PKCS8_PRIVATEKEY",
	"OpaqueTransport", "PKCS7_ENVELOPE", "CAPIPRIVATEBLOB", "RSAFULLPRIVATEBLOB",
}

func a6status(r uintptr) string {
	if r == 0 {
		return ""
	}
	return fmt.Sprintf("0x%08X", uint32(r))
}

func a6utf16(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

// keyProbe is what one account could do with one key. An empty string is
// success; otherwise the error.
type keyProbe struct {
	SID         string            `json:"sid"`
	Open        string            `json:"open"`
	Public      string            `json:"public"`
	Sign        string            `json:"sign"`
	Sig         []byte            `json:"sig"`
	Export      map[string]string `json:"export"`
	SetPolicy   map[string]string `json:"set_policy"`
	ExportAfter map[string]string `json:"export_after"`
}

func a6openKey(name string) (uintptr, string) {
	var prov, key uintptr
	if r, _, _ := a6OpenProv.Call(uintptr(unsafe.Pointer(&prov)), a6utf16("Microsoft Software Key Storage Provider"), 0); r != 0 {
		return 0, "provider " + a6status(r)
	}
	defer a6FreeObject.Call(prov)
	r, _, _ := a6OpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), a6utf16(name), 0, a6MachineKey|a6Silent)
	if r != 0 {
		return 0, a6status(r)
	}
	return key, ""
}

func a6export(key uintptr, blob string) string {
	buf := make([]byte, 16384)
	var n uint32
	r, _, _ := a6ExportKey.Call(key, 0, a6utf16(blob), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)), a6Silent)
	if r == 0 {
		return ""
	}
	return a6status(r)
}

func a6exportAll(name string) map[string]string {
	out := map[string]string{}
	key, err := a6openKey(name)
	if err != "" {
		for _, b := range a6PrivateBlobs {
			out[b] = "open " + err
		}
		return out
	}
	defer a6FreeObject.Call(key)
	for _, b := range a6PrivateBlobs {
		out[b] = a6export(key, b)
	}
	return out
}

// probe runs as the account under test: the process's, or the thread's
// when impersonating.
func probe(name string, digest []byte) keyProbe {
	p := keyProbe{Export: map[string]string{}, SetPolicy: map[string]string{}}
	if u, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser(); err == nil {
		p.SID = u.User.Sid.String()
	}
	// Sign the way the node does, through the package under test.
	if s, err := (nodekey.CNG{}).Open(name); err != nil {
		p.Sign = "open: " + err.Error()
	} else if sig, err := s.Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		p.Sign = err.Error()
	} else {
		p.Sig = sig
	}
	key, err := a6openKey(name)
	p.Open = err
	if err != "" {
		return p
	}
	defer a6FreeObject.Call(key)
	p.Public = a6export(key, "ECCPUBLICBLOB")
	for _, b := range a6PrivateBlobs {
		p.Export[b] = a6export(key, b)
	}
	// Try to turn export on, persisted and for this handle only.
	for label, flags := range map[string]uintptr{"persist": a6Persist | a6Silent, "handle": a6Silent} {
		v := uint32(a6AllowExport)
		r, _, _ := a6SetProp.Call(key, a6utf16("Export Policy"), uintptr(unsafe.Pointer(&v)), 4, flags)
		p.SetPolicy[label] = a6status(r)
	}
	for _, b := range a6PrivateBlobs {
		if e := a6export(key, b); e == "" {
			p.Export[b+" (same handle, after set policy)"] = ""
		}
	}
	p.ExportAfter = a6exportAll(name)
	return p
}

// TestA6NodeKeyHelper is the service body: the parent starts it with the
// key name, the digest in hex and the output path.
func TestA6NodeKeyHelper(t *testing.T) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		t.Skip("runs only as a service that TestA6NodeKeyClaims starts")
	}
	svc.Run("", a6helper{})
}

type a6helper struct{}

func (a6helper) Execute(args []string, _ <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running}
	defer func() { s <- svc.Status{State: svc.StopPending} }()
	if len(args) != 4 {
		return false, 1
	}
	digest, err := hex.DecodeString(args[2])
	if err != nil {
		return false, 2
	}
	b, _ := json.Marshal(probe(args[1], digest))
	if os.WriteFile(args[3], b, 0o644) != nil {
		return false, 3
	}
	return false, 0
}

func a6tag(t *testing.T) string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// a6user makes a local user with a random password and returns its
// impersonation token (network logon, as a remote client would have).
func a6user(t *testing.T, name string) (windows.Token, string) {
	t.Helper()
	pw := "A6!" + a6tag(t) + a6tag(t) + "zZ9"
	type userInfo1 struct {
		Name, Password *uint16
		PasswordAge    uint32
		Priv           uint32
		HomeDir        *uint16
		Comment        *uint16
		Flags          uint32
		ScriptPath     *uint16
	}
	un, _ := windows.UTF16PtrFromString(name)
	pp, _ := windows.UTF16PtrFromString(pw)
	ui := userInfo1{Name: un, Password: pp, Priv: 1 /* USER_PRIV_USER */, Flags: 0x0001 | 0x10000 /* UF_SCRIPT | UF_DONT_EXPIRE_PASSWD */}
	var parm uint32
	if r, _, _ := a6NetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&ui)), uintptr(unsafe.Pointer(&parm))); r != 0 {
		t.Fatalf("NetUserAdd %s: %d (parm %d)", name, r, parm)
	}
	t.Cleanup(func() { a6NetUserDel.Call(0, uintptr(unsafe.Pointer(un))) })
	var tok windows.Token
	dot, _ := windows.UTF16PtrFromString(".")
	if r, _, e := a6LogonUser.Call(uintptr(unsafe.Pointer(un)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pp)),
		3 /* LOGON32_LOGON_NETWORK */, 0, uintptr(unsafe.Pointer(&tok))); r == 0 {
		t.Fatalf("LogonUser %s: %v", name, e)
	}
	defer tok.Close()
	var imp windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { imp.Close() })
	u, err := imp.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return imp, u.User.Sid.String()
}

// asUser runs probe on a locked thread impersonating tok.
func asUser(t *testing.T, tok windows.Token, name string, digest []byte) keyProbe {
	t.Helper()
	ch := make(chan keyProbe)
	go func() {
		runtime.LockOSThread() // the thread keeps the token only if it is reverted
		if err := windows.SetThreadToken(nil, tok); err != nil {
			ch <- keyProbe{Open: "impersonate: " + err.Error(), Sign: "impersonate"}
			return
		}
		p := probe(name, digest)
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
		ch <- p
	}()
	return <-ch
}

func a6copy(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestA6NodeKeyClaims(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("makes machine keys, services and a local user: the GitHub-hosted Windows runner only (D2-13)")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("the hosted runner is not elevated: this test must run there, not skip")
	}
	tag := a6tag(t)

	// A directory every test account can read, for the binary and results.
	dir := `C:\a6nk-` + tag
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
	exe := filepath.Join(dir, "a6nk.test.exe")
	a6copy(t, self, exe)

	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	service := func(name, account string) *mgr.Service {
		s, err := m.CreateService(name, exe, mgr.Config{DisplayName: "OTSEC A6 node key test " + name, ServiceStartName: account,
			SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "-test.run=^TestA6NodeKeyHelper$")
		if err != nil {
			t.Fatalf("create service %s as %s: %v", name, account, err)
		}
		t.Cleanup(func() {
			s.Control(svc.Stop)
			s.Delete()
			s.Close()
		})
		return s
	}
	nodeName, otherName, sysName := "a6nknode"+tag, "a6nkother"+tag, "a6nksys"+tag
	nodeSvc := service(nodeName, `NT SERVICE\`+nodeName)
	otherSvc := service(otherName, `NT SERVICE\`+otherName)
	sysSvc := service(sysName, "LocalSystem")
	sidOf := func(account string) string {
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil {
			t.Fatalf("SID of %s: %v", account, err)
		}
		return sid.String()
	}
	nodeSID, otherSID := sidOf(`NT SERVICE\`+nodeName), sidOf(`NT SERVICE\`+otherName)
	userTok, userSID := a6user(t, "a6nk"+tag)

	// The node key, made and restricted as Request does, and control keys
	// that grant the other accounts what the node key grants the node.
	mkKey := func(ref string, users ...string) (string, *ecdsa.PublicKey) {
		keys := nodekey.CNG{Users: users}
		name := nodekey.KeyName("nodekey_"+ref, 1)
		s, err := keys.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		t.Cleanup(func() {
			if err := keys.Delete(name); err != nil {
				t.Errorf("delete %s: %v", name, err)
			}
		})
		if err := keys.Restrict(s); err != nil {
			t.Fatalf("restrict %s: %v", name, err)
		}
		return name, s.Public().(*ecdsa.PublicKey)
	}
	nodeKey, nodePub := mkKey("a6n"+tag, nodeSID)
	otherKey, otherPub := mkKey("a6o"+tag, otherSID)
	userKey, userPub := mkKey("a6u"+tag, userSID)
	sum := sha256.Sum256([]byte("a6 node key " + tag))
	digest := sum[:]

	run := func(s *mgr.Service, label, key string) keyProbe {
		t.Helper()
		out := filepath.Join(dir, label+".json")
		os.Remove(out)
		if err := s.Start(key, hex.EncodeToString(digest), out); err != nil {
			t.Fatalf("%s: start: %v", label, err)
		}
		deadline := time.Now().Add(90 * time.Second)
		for {
			st, err := s.Query()
			if err == nil && st.State == svc.Stopped {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: service did not stop: %+v %v", label, st, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("%s: no result: %v", label, err)
		}
		var p keyProbe
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		t.Logf("%s: %s", label, b)
		return p
	}
	signs := func(label string, p keyProbe, pub *ecdsa.PublicKey) {
		t.Helper()
		if p.Open != "" || p.Sign != "" || !ecdsa.VerifyASN1(pub, digest, p.Sig) {
			t.Errorf("%s: cannot use the key: open %q sign %q (signature verifies: %v)", label, p.Open, p.Sign, ecdsa.VerifyASN1(pub, digest, p.Sig))
		}
	}
	refused := func(label string, p keyProbe) {
		t.Helper()
		if p.Open == "" || p.Sign == "" || len(p.Sig) != 0 {
			t.Errorf("%s: opened or signed with the node key: open %q sign %q", label, p.Open, p.Sign)
		}
	}
	noExport := func(label string, p keyProbe) {
		t.Helper()
		if p.Open != "" {
			t.Errorf("%s: the export claim needs an account that can open the key: open %s", label, p.Open)
			return
		}
		if p.Public != "" {
			t.Errorf("%s: the public half did not export (%s), so the handle is not usable as a control", label, p.Public)
		}
		for blob, e := range p.Export {
			if e == "" {
				t.Errorf("%s: exported %s", label, blob)
			}
		}
		for blob, e := range p.ExportAfter {
			if e == "" {
				t.Errorf("%s: exported %s on a new handle after trying to set the export policy %v", label, blob, p.SetPolicy)
			}
		}
		if len(p.Export) < len(a6PrivateBlobs) || len(p.ExportAfter) != len(a6PrivateBlobs) {
			t.Errorf("%s: not every blob type was tried: %v %v", label, p.Export, p.ExportAfter)
		}
	}

	// (c) The node service signs and cannot export.
	node := run(nodeSvc, "node-service", nodeKey)
	if node.SID != nodeSID {
		t.Fatalf("the node service ran as %s, want %s", node.SID, nodeSID)
	}
	signs("node service", node, nodePub)
	noExport("node service", node)

	// (b) Another service account and a plain user can neither open nor sign.
	other := run(otherSvc, "other-service", nodeKey)
	if other.SID != otherSID {
		t.Fatalf("the other service ran as %s, want %s", other.SID, otherSID)
	}
	refused("another service account", other)
	signs("another service account, control key", run(otherSvc, "other-service-control", otherKey), otherPub)
	user := asUser(t, userTok, nodeKey, digest)
	if user.SID != userSID {
		t.Fatalf("the probe ran as %s, want the user %s", user.SID, userSID)
	}
	t.Logf("plain user: %+v", user)
	refused("plain user", user)
	signs("plain user, control key", asUser(t, userTok, userKey, digest), userPub)

	// (a) Nobody exports: SYSTEM and Administrators, who hold full control.
	sys := run(sysSvc, "system", nodeKey)
	if sys.SID != "S-1-5-18" {
		t.Fatalf("the SYSTEM service ran as %s", sys.SID)
	}
	noExport("SYSTEM", sys)
	admin := probe(nodeKey, digest)
	t.Logf("administrator: %+v", admin)
	noExport("elevated administrator", admin)
	// Whether the KSP refuses turning export on is logged, not asserted:
	// the claim is that nothing exports, which noExport checks after it.
	t.Logf("set export policy: node service %v, SYSTEM %v, administrator %v", node.SetPolicy, sys.SetPolicy, admin.SetPolicy)
}
