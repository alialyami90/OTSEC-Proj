package snmpv3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// The USM algorithms the platform allows (D4-49 Q2): HMAC-SHA-256 and
// HMAC-SHA-512 for authentication (RFC 7860) and AES-128 in CFB mode for
// privacy (RFC 3826). There is no other: no MD5, SHA-1, DES or AES-256, no
// noAuth or noPriv session, and no fallback to any of them.
//
// The keys are localized already (RFC 3414 §2.6): C7 0.8 seals the
// authentication key followed by the 16-octet AES key (#446). The client
// never sees a password and never localizes a key, so a mismatched engine ID
// cannot make it localize to the wrong one.
//
// Evidence: desk. These rules are written from RFC 3414, 3826 and 7860 as
// the author knows them; the RFC texts are not in the project files, and no
// RFC test vector has been run. The interoperability test is GT-MIB's agent
// and, later, hardware.

// AuthProto names an authentication protocol by C7 0.8's value.
type AuthProto string

const (
	HMACSHA256 AuthProto = "hmac-sha-256" // usmHMAC192SHA256AuthProtocol: 24-octet digest
	HMACSHA512 AuthProto = "hmac-sha-512" // usmHMAC384SHA512AuthProtocol: 48-octet digest
)

// PrivProto names a privacy protocol by C7 0.8's value.
type PrivProto string

const AES128 PrivProto = "aes-128" // usmAesCfb128Protocol

// Keys are a user's localized keys for one engine.
type Keys struct {
	User    string
	Auth    AuthProto
	AuthKey []byte // 32 octets for SHA-256, 64 for SHA-512
	Priv    PrivProto
	PrivKey []byte // 16 octets
}

func (p AuthProto) hash() (func() hash.Hash, int, int, bool) {
	switch p {
	case HMACSHA256:
		return sha256.New, 32, 24, true
	case HMACSHA512:
		return sha512.New, 64, 48, true
	}
	return nil, 0, 0, false
}

// check refuses keys of any other protocol or length.
func (k Keys) check() error {
	_, keyLen, _, ok := k.Auth.hash()
	switch {
	case !ok:
		return fmt.Errorf("snmpv3: authentication protocol %q is not allowed", k.Auth)
	case len(k.AuthKey) != keyLen:
		return fmt.Errorf("snmpv3: %s key is %d octets, want %d", k.Auth, len(k.AuthKey), keyLen)
	case k.Priv != AES128:
		return fmt.Errorf("snmpv3: privacy protocol %q is not allowed", k.Priv)
	case len(k.PrivKey) != 16:
		return fmt.Errorf("snmpv3: aes-128 key is %d octets, want 16", len(k.PrivKey))
	case k.User == "" || len(k.User) > 32:
		return fmt.Errorf("snmpv3: user name of %d octets", len(k.User))
	}
	return nil
}

// digestLen is the length of msgAuthenticationParameters.
func (k Keys) digestLen() int {
	_, _, n, _ := k.Auth.hash()
	return n
}

// mac is the truncated HMAC of the message with its digest zeroed.
func (k Keys) mac(wire []byte, off int) []byte {
	h, _, n, _ := k.Auth.hash()
	z := append([]byte(nil), wire...)
	clear(z[off : off+n])
	m := hmac.New(h, k.AuthKey)
	m.Write(z)
	return m.Sum(nil)[:n]
}

// sign fills the zeroed digest of an encoded message in place.
func (k Keys) sign(wire []byte, m *message) {
	copy(wire[m.AuthOff:], k.mac(wire, m.AuthOff))
}

// verify reports whether a received message's digest is the right length
// and authenticates under the keys.
func (k Keys) verify(wire []byte, m *message) bool {
	n := k.digestLen()
	if len(m.USM.AuthParams) != n {
		return false
	}
	return hmac.Equal(m.USM.AuthParams, k.mac(wire, m.AuthOff))
}

// cfb runs AES-128-CFB (RFC 3826 §3.1): the IV is the authoritative engine's
// boots and time, four octets each, then the eight-octet salt that travels in
// msgPrivacyParameters.
func (k Keys) cfb(boots, time int64, salt []byte, in []byte, encrypt bool) ([]byte, error) {
	if len(salt) != 8 {
		return nil, fmt.Errorf("snmpv3: msgPrivacyParameters of %d octets, want 8", len(salt))
	}
	block, err := aes.NewCipher(k.PrivKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:], uint32(time))
	copy(iv[8:], salt)
	out := make([]byte, len(in))
	// CFB is deprecated in the standard library for new designs that lack
	// authentication; RFC 3826 fixes it, and USM authenticates the message.
	if encrypt {
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, in)
	} else {
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, in)
	}
	return out, nil
}
