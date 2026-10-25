//go:build windows

package collector

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// keyProtection names how the store key is protected on this platform. A
// store written on another platform, or with another protection, is refused.
//
// Windows uses user-scope DPAPI under the collector's virtual account (A3
// credential design, section 3, option 2). Never CRYPTPROTECT_LOCAL_MACHINE:
// any process on the node could then decrypt it (AP-1). The TPM option
// (option 1) waits on T-2.
const keyProtection = "dpapi-user"

// dpapiEntropy is DPAPI's optional entropy: it is not secret, but it keeps
// a blob from another program under the same account from being accepted.
var dpapiEntropy = []byte("otsec.collector/0.1 store-key")

func protectKey(key []byte) ([]byte, error) {
	in := blob(key)
	ent := blob(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out, false), nil
}

func unprotectKey(b []byte) ([]byte, error) {
	in := blob(b)
	ent := blob(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	key := takeBlob(&out, true)
	if len(key) != storeKeyLen {
		clear(key)
		return nil, errStoreKeyLength
	}
	return key, nil
}

func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies a DPAPI output buffer into Go memory and frees it, wiping
// it first when it held the plaintext key.
func takeBlob(out *windows.DataBlob, wipe bool) []byte {
	if out.Data == nil {
		return nil
	}
	src := unsafe.Slice(out.Data, out.Size)
	b := make([]byte, len(src))
	copy(b, src)
	if wipe {
		clear(src)
	}
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return b
}
