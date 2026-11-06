package agent

// GT-MIB's own USM cryptography, from the texts:
//
//   - password to key: RFC 3414 section 2.6 and Appendix A.2 (one megabyte
//     of the repeated password through the hash), with the hash of the
//     user's authentication protocol (RFC 7860 section 5);
//   - key localization: RFC 3414 section 2.6, H(Ku || snmpEngineID || Ku);
//   - HMAC-SHA-2: RFC 7860 section 4 (usmHMAC192SHA256AuthProtocol, a
//     24-octet MAC; usmHMAC384SHA512AuthProtocol, a 48-octet MAC), computed
//     over the whole message with the MAC field set to N zero octets
//     (sections 4.2.1 and 4.2.2);
//   - HMAC-SHA-96: RFC 3414 section 7, kept only so the agent can be a
//     SHA-1 user for U4 (the client never offers it);
//   - CFB128-AES-128: RFC 3826 section 3.1, with the first 16 octets of the
//     localized privacy key as the AES key and the IV boots || time || salt,
//     each most significant byte first, and no padding.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 3414 section 7, for U4's SHA-1-only agent
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// Auth is a USM authentication protocol.
type Auth string

const (
	AuthSHA256 Auth = "hmac-sha-256" // usmHMAC192SHA256AuthProtocol
	AuthSHA512 Auth = "hmac-sha-512" // usmHMAC384SHA512AuthProtocol
	AuthSHA1   Auth = "hmac-sha-1"   // usmHMACSHAAuthProtocol, U4 only
)

func (a Auth) hash() func() hash.Hash {
	switch a {
	case AuthSHA256:
		return sha256.New
	case AuthSHA512:
		return sha512.New
	case AuthSHA1:
		return sha1.New
	}
	panic("unknown auth " + string(a))
}

// MACLen is N, the MAC's length in octets (RFC 7860 section 4.1; RFC 3414
// section 7.1: 12 for HMAC-SHA-96).
func (a Auth) MACLen() int {
	switch a {
	case AuthSHA256:
		return 24
	case AuthSHA512:
		return 48
	case AuthSHA1:
		return 12
	}
	panic("unknown auth " + string(a))
}

// PasswordToKey is Ku (RFC 3414 Appendix A.2): the password repeated to
// fill 1048576 octets, hashed.
func PasswordToKey(a Auth, password []byte) []byte {
	if len(password) == 0 {
		panic("empty password")
	}
	h := a.hash()()
	buf := make([]byte, 64)
	idx := 0
	for count := 0; count < 1048576; count += 64 {
		for i := range buf {
			buf[i] = password[idx%len(password)]
			idx++
		}
		h.Write(buf)
	}
	return h.Sum(nil)
}

// Localize is Kul = H(Ku || snmpEngineID || Ku) (RFC 3414 section 2.6).
func Localize(a Auth, ku, engineID []byte) []byte {
	h := a.hash()()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

// MAC computes the truncated HMAC over whole, which must already carry N
// zero octets in its MAC field.
func MAC(a Auth, key, whole []byte) []byte {
	m := hmac.New(a.hash(), key)
	m.Write(whole)
	return m.Sum(nil)[:a.MACLen()]
}

// aesCFB runs CFB128-AES-128 (RFC 3826 sections 3.1.2.1 to 3.1.4) with
// the first 16 octets of the localized privacy key.
func aesCFB(privKey []byte, boots, time uint32, salt []byte, data []byte, encrypt bool) ([]byte, error) {
	if len(privKey) < 16 {
		return nil, fmt.Errorf("privacy key of %d octets", len(privKey))
	}
	if len(salt) != 8 {
		return nil, fmt.Errorf("salt of %d octets", len(salt))
	}
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:], boots)
	binary.BigEndian.PutUint32(iv[4:], time)
	copy(iv[8:], salt)
	out := make([]byte, len(data))
	if encrypt {
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, data) //nolint:staticcheck // RFC 3826 fixes CFB128
	} else {
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, data) //nolint:staticcheck // RFC 3826 fixes CFB128
	}
	return out, nil
}

// User is one usmUserTable row: the localized keys for this agent's engine.
type User struct {
	Name    string
	Auth    Auth   // "" for a noAuthNoPriv-only user
	Priv    bool   // usmAesCfb128PrivProtocol
	AuthKey []byte // localized
	PrivKey []byte // localized with the auth protocol's hash; AES uses 16 octets
}

// NewUser localizes password for engineID under auth, with AES privacy if
// priv. The same password serves both keys, as the test credential has one.
func NewUser(name string, auth Auth, priv bool, password string, engineID []byte) User {
	u := User{Name: name, Auth: auth, Priv: priv}
	if auth != "" {
		ku := PasswordToKey(auth, []byte(password))
		u.AuthKey = Localize(auth, ku, engineID)
		if priv {
			u.PrivKey = Localize(auth, ku, engineID)
		}
	}
	return u
}
