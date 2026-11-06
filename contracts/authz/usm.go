package authz

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// USMAuth is an snmpv3 credential's authentication protocol (0.8). Closed
// list, holding only the strong values, so a weaker protocol cannot be named
// (D4-49 Q2, D4-51): RFC 7860's usmHMAC192SHA256AuthProtocol and
// usmHMAC384SHA512AuthProtocol. MD5 and SHA-1 are not in it.
type USMAuth string

const (
	USMAuthHMACSHA256 USMAuth = "hmac-sha-256"
	USMAuthHMACSHA512 USMAuth = "hmac-sha-512"
)

// KeyLen is the length of a key localized with the protocol's hash (RFC
// 3414 section 2.6, RFC 7860): the hash's output size. It is 0 for a value
// outside the list.
func (a USMAuth) KeyLen() int {
	switch a {
	case USMAuthHMACSHA256:
		return 32
	case USMAuthHMACSHA512:
		return 64
	}
	return 0
}

// USMPriv is an snmpv3 credential's privacy protocol (0.8). Closed list: RFC
// 3826's usmAesCfb128Protocol. DES and AES-256 are not in it; AES-256 has no
// RFC and S29 does not say which key extension the device uses.
type USMPriv string

const USMPrivAES128 USMPriv = "aes-128"

// KeyLen is the privacy key's length: AES-128 takes the first 16 bytes of
// the key localized with the authentication protocol's hash (RFC 3826
// section 1.2). It is 0 for a value outside the list.
func (p USMPriv) KeyLen() int {
	if p == USMPrivAES128 {
		return 16
	}
	return 0
}

// USM is an snmpv3 credential's user (0.8): the USM user name, the two
// protocols, and the authoritative engine ID its keys are localized to,
// pinned at commissioning (D4-49 Q1, HR-16). The level is always authPriv,
// and there is no field for another. The keys are the sealed secret, never
// the password (USMSecretLen), so a key taken from one collector opens no
// other device that shares the password.
type USM struct {
	UserName string  `json:"user_name"`
	Auth     USMAuth `json:"auth"`
	Priv     USMPriv `json:"priv"`
	// EngineID is the authoritative engine ID in lowercase hex: RFC 3411's
	// SnmpEngineID, 5 to 32 octets, and from 0.9 never all zeros or all
	// 'ff'H (RFC 3411 section 5). The collector refuses a session when it
	// differs from the asset's declared snmp_engine_id (C1 0.3), and the
	// client stops when discovery reports another (C11 section 4 rule 2).
	EngineID string `json:"engine_id"`
	// SoleDeviceAttested records the installing person's statement
	// that this device's USM password is used on no other device. The
	// platform cannot see it from outside; with a shared password, the holder
	// of one device's password can localize keys for every other pinned
	// engine ID (C2 on #437). It must be true.
	SoleDeviceAttested bool `json:"sole_device_attested"`
}

var (
	usmUserPattern     = regexp.MustCompile(`^[!-~]{1,32}$`)
	usmEngineIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{2}){5,32}$`)
)

// Validate checks the user on its own.
func (u *USM) Validate() error {
	switch {
	case !usmUserPattern.MatchString(u.UserName):
		return errors.New("authz: usm user_name is not 1 to 32 printable ASCII characters")
	case u.Auth.KeyLen() == 0:
		return fmt.Errorf("authz: usm auth %q is not %s or %s", u.Auth, USMAuthHMACSHA256, USMAuthHMACSHA512)
	case u.Priv.KeyLen() == 0:
		return fmt.Errorf("authz: usm priv %q is not %s", u.Priv, USMPrivAES128)
	case !usmEngineIDPattern.MatchString(u.EngineID):
		return errors.New("authz: usm engine_id is not 5 to 32 octets in lowercase hex")
	case strings.Trim(u.EngineID, "0") == "" || strings.Trim(u.EngineID, "f") == "":
		// RFC 3411 section 5, SnmpEngineID: never all zeros or all 'ff'H (0.9).
		return errors.New("authz: usm engine_id is all zeros or all ff")
	case !u.SoleDeviceAttested:
		return errors.New("authz: usm needs the installer's attestation that the password is this device's alone")
	}
	return nil
}

// USMSecretLen is the length of an snmpv3 credential's secret: the localized
// authentication key followed by the privacy key, 48 bytes with
// hmac-sha-256 and 80 with hmac-sha-512. It is 0 for an invalid USM.
func USMSecretLen(u *USM) int {
	a, p := u.Auth.KeyLen(), u.Priv.KeyLen()
	if a == 0 || p == 0 {
		return 0
	}
	return a + p
}

// ErrUSMSecretRejected is returned for localized keys that fail
// ValidateUSMSecret. The error never includes the keys.
var ErrUSMSecretRejected = errors.New("authz: usm keys rejected at write time")

// SplitUSMSecret checks an snmpv3 secret and returns its two keys, which
// alias secret. It is the write-time rule for an snmpv3 credential, in place
// of ValidateSecret: the secret is exactly USMSecretLen bytes, and neither key
// is all zero bytes, which no hash output is.
func SplitUSMSecret(secret []byte, u *USM) (authKey, privKey []byte, err error) {
	n := USMSecretLen(u)
	if n == 0 || len(secret) != n {
		return nil, nil, fmt.Errorf("%w: not %d bytes", ErrUSMSecretRejected, n)
	}
	a := u.Auth.KeyLen()
	authKey, privKey = secret[:a:a], secret[a:]
	if subtle.ConstantTimeCompare(authKey, make([]byte, len(authKey))) == 1 ||
		subtle.ConstantTimeCompare(privKey, make([]byte, len(privKey))) == 1 {
		return nil, nil, fmt.Errorf("%w: a key is all zero bytes", ErrUSMSecretRejected)
	}
	return authKey, privKey, nil
}
