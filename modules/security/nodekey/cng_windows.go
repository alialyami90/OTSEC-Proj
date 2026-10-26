package nodekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	providerSoftware      = "Microsoft Software Key Storage Provider"
	providerPlatform      = "Microsoft Platform Crypto Provider"
	ecdsaP256Algorithm    = "ECDSA_P256"
	eccPublicBlob         = "ECCPUBLICBLOB"
	exportPolicyProperty  = "Export Policy"
	securityDescrProperty = "Security Descr"
	ecdsaPublicP256Magic  = 0x31534345
	ncryptMachineKeyFlag  = 0x20
	ncryptSilentFlag      = 0x40
	ncryptPersistFlag     = 0x80000000
	nteBadKeyset          = 0x80090016
	nteExists             = 0x8009000F
	daclSecurityInfo      = windows.DACL_SECURITY_INFORMATION
	protectedDACLInfo     = windows.PROTECTED_DACL_SECURITY_INFORMATION
)

type cngStatus uintptr

func (s cngStatus) Error() string { return fmt.Sprintf("CNG status 0x%08X", uint32(s)) }

func call(p *windows.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if uint32(r) != 0 {
		return cngStatus(uint32(r))
	}
	return nil
}

func utf16(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

func (c CNG) open() (uintptr, error) {
	name := providerSoftware
	if c.Platform {
		name = providerPlatform
	}
	var h uintptr
	if err := call(procOpenStorageProvider, uintptr(unsafe.Pointer(&h)), utf16(name), 0); err != nil {
		return 0, fmt.Errorf("nodekey: open %s: %w", name, err)
	}
	return h, nil
}

func free(h uintptr) { procFreeObject.Call(h) }

// sddl is the key's final DACL: SYSTEM and Administrators have full
// control, the listed users may use it, and nobody else has any right.
// Administrators keep use of the key because the Software KSP needs read
// and write on the key to change its DACL or delete it (CI on #157, see
// TestCNGRightsProbe), and an administrator can act as SYSTEM in any case:
// the boundary is non-export and every other account.
func (c CNG) sddl() (string, error) {
	var b strings.Builder
	b.WriteString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	for _, u := range c.Users {
		sid, err := windows.StringToSid(u)
		if err != nil {
			return "", fmt.Errorf("nodekey: user %q is not a SID", u)
		}
		fmt.Fprintf(&b, "(A;;GR;;;%s)", sid.String())
	}
	return b.String(), nil
}

func setDACL(key uintptr, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	return call(procSetProperty, key, utf16(securityDescrProperty), uintptr(unsafe.Pointer(sd)), uintptr(sd.Length()),
		uintptr(daclSecurityInfo|protectedDACLInfo))
}

func currentUser() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

func (c CNG) Create(name string) (crypto.Signer, error) {
	if !keyNamePattern.MatchString(name) {
		return nil, fmt.Errorf("nodekey: key name %q", name)
	}
	if _, err := c.sddl(); err != nil {
		return nil, err // a bad user SID is refused before any key exists
	}
	prov, err := c.open()
	if err != nil {
		return nil, err
	}
	defer free(prov)
	var key uintptr
	if err := call(procCreatePersistedKey, prov, uintptr(unsafe.Pointer(&key)), utf16(ecdsaP256Algorithm), utf16(name), 0,
		ncryptMachineKeyFlag|ncryptSilentFlag); err != nil {
		if s, ok := err.(cngStatus); ok && s == nteExists {
			return nil, fmt.Errorf("nodekey: create %s: the key exists", name)
		}
		return nil, fmt.Errorf("nodekey: create %s: %w", name, err)
	}
	fail := func(err error) (crypto.Signer, error) {
		procDeleteKey.Call(key, 0) // frees the handle
		return nil, fmt.Errorf("nodekey: create %s: %w", name, err)
	}
	policy := uint32(0) // no export of any kind
	if err := call(procSetProperty, key, utf16(exportPolicyProperty), uintptr(unsafe.Pointer(&policy)), 4,
		ncryptPersistFlag|ncryptSilentFlag); err != nil {
		return fail(err)
	}
	if err := call(procFinalizeKey, key, ncryptSilentFlag); err != nil {
		return fail(err)
	}
	pub, err := publicKey(key)
	if err != nil {
		return fail(err)
	}
	return &cngSigner{key: key, pub: pub}, nil
}

// Restrict sets the key's final DACL (sddl), once, through the handle
// Create returned: until then the key has the provider's default DACL for
// a machine key. The KSP checks a later DACL change or delete against the
// DACL then in force, through any handle: a change needs generic write,
// not write-DAC alone, and a delete needs delete (TestCNGRightsProbe, CI
// on #157). Administrators' full control covers both.
func (c CNG) Restrict(created crypto.Signer) error {
	s, ok := created.(*cngSigner)
	if !ok {
		return errors.New("nodekey: restrict: not a key this provider created")
	}
	sddl, err := c.sddl()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := setDACL(s.key, sddl); err != nil {
		return fmt.Errorf("nodekey: restrict: %w", err)
	}
	return nil
}

func (c CNG) openKey(name string) (uintptr, error) {
	if !keyNamePattern.MatchString(name) {
		return 0, fmt.Errorf("nodekey: key name %q", name)
	}
	prov, err := c.open()
	if err != nil {
		return 0, err
	}
	defer free(prov)
	var key uintptr
	if err := call(procOpenKey, prov, uintptr(unsafe.Pointer(&key)), utf16(name), 0, ncryptMachineKeyFlag|ncryptSilentFlag); err != nil {
		if s, ok := err.(cngStatus); ok && s == nteBadKeyset {
			return 0, fmt.Errorf("%w: %s", ErrNoKey, name)
		}
		return 0, fmt.Errorf("nodekey: open %s: %w", name, err)
	}
	return key, nil
}

func (c CNG) Open(name string) (crypto.Signer, error) {
	key, err := c.openKey(name)
	if err != nil {
		return nil, err
	}
	pub, err := publicKey(key)
	if err != nil {
		free(key)
		return nil, fmt.Errorf("nodekey: open %s: %w", name, err)
	}
	return &cngSigner{key: key, pub: pub}, nil
}

func (c CNG) Delete(name string) error {
	key, err := c.openKey(name)
	if errors.Is(err, ErrNoKey) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := call(procDeleteKey, key, ncryptSilentFlag); err != nil {
		free(key)
		return fmt.Errorf("nodekey: delete %s: %w", name, err)
	}
	return nil
}

// publicKey reads the key's public half (BCRYPT_ECCKEY_BLOB).
func publicKey(key uintptr) (*ecdsa.PublicKey, error) {
	buf := make([]byte, 8+64)
	var n uint32
	if err := call(procExportKey, key, 0, utf16(eccPublicBlob), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)), 0); err != nil {
		return nil, err
	}
	if n != 72 || binary.LittleEndian.Uint32(buf) != ecdsaPublicP256Magic || binary.LittleEndian.Uint32(buf[4:]) != 32 {
		return nil, errors.New("not an ECDSA P-256 public key")
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, buf[8:72]...))
}

// cngSigner signs with a CNG key. The handle stays open for the life of
// the process, as the key is in use for as long as the node runs.
type cngSigner struct {
	mu  sync.Mutex
	key uintptr
	pub *ecdsa.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs digest, which the caller hashed, and returns the ASN.1 form
// crypto/ecdsa and TLS use.
func (s *cngSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("nodekey: empty digest")
	}
	sig := make([]byte, 64)
	var n uint32
	s.mu.Lock()
	err := call(procSignHash, s.key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("nodekey: sign: %w", err)
	}
	if n != 64 {
		return nil, fmt.Errorf("nodekey: sign: %d bytes", n)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
}

// securityDescriptor reads the key's DACL (tests).
func (c CNG) securityDescriptor(name string) (*windows.SECURITY_DESCRIPTOR, error) {
	key, err := c.openKey(name)
	if err != nil {
		return nil, err
	}
	defer free(key)
	var n uint32
	call(procGetProperty, key, utf16(securityDescrProperty), 0, 0, uintptr(unsafe.Pointer(&n)), uintptr(daclSecurityInfo))
	if n == 0 {
		return nil, errors.New("no security descriptor")
	}
	buf := make([]byte, n)
	if err := call(procGetProperty, key, utf16(securityDescrProperty), uintptr(unsafe.Pointer(&buf[0])), uintptr(n),
		uintptr(unsafe.Pointer(&n)), uintptr(daclSecurityInfo)); err != nil {
		return nil, err
	}
	return (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0])), nil // buf stays reachable through it
}

// dacl returns the key's DACL as SDDL (tests, for the log).
func (c CNG) dacl(name string) (string, error) {
	sd, err := c.securityDescriptor(name)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}

// keyACEs returns the key's DACL as allow-ACE masks by SID string, and
// whether the DACL is protected (tests). Any ACE other than an allow ACE is
// an error: the DACL this package writes has none.
func (c CNG) keyACEs(name string) (map[string]uint32, bool, error) {
	sd, err := c.securityDescriptor(name)
	if err != nil {
		return nil, false, err
	}
	control, _, err := sd.Control()
	if err != nil {
		return nil, false, err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return nil, false, err
	}
	out := map[string]uint32{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return nil, false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return nil, false, fmt.Errorf("ACE %d has type %d", i, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		out[sid] |= uint32(ace.Mask)
	}
	return out, control&windows.SE_DACL_PROTECTED != 0, nil
}

// exportPrivate tries to read the private key out (tests: it must fail).
func (c CNG) exportPrivate(name string) error {
	key, err := c.openKey(name)
	if err != nil {
		return err
	}
	defer free(key)
	buf := make([]byte, 4096)
	var n uint32
	for _, blob := range []string{"ECCPRIVATEBLOB", "PKCS8_PRIVATEKEY"} {
		if err := call(procExportKey, key, 0, utf16(blob), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&n)), ncryptSilentFlag); err == nil {
			return fmt.Errorf("%s exported", blob)
		}
	}
	return nil
}
