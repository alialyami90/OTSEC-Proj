// Package seal seals a device secret to one collector's install key, and
// opens it inside that collector (C7 SealedSecret, algorithm
// x25519-hkdf-sha256-aes256gcm; A3 credential design, section 4).
//
// The admin's sealing client calls Seal on the admin's own machine, so the
// node service relays ciphertext it cannot open. Seal refuses to run without
// a fingerprint the admin pinned at commissioning (T-12, D2-5): without it, a
// node service that substituted its own public key would receive the secret.
// The collector calls Open.
//
// C7 names the algorithm but not its parameters. This package fixes them for
// 0.1, and they are a C7 0.2 candidate:
//
//   - The sender makes an ephemeral X25519 key pair and computes the shared
//     secret with the recipient's public key. An all-zero shared secret (a
//     low-order public key) is refused by crypto/ecdh.
//   - key = HKDF-SHA256(ikm = shared secret, salt = empty,
//     info = Info + ephemeral public key + recipient public key), 32 bytes.
//     Both public keys are in info, so the key is bound to this sender key
//     and this recipient.
//   - AES-256-GCM with a random 12-byte nonce and authz.SealAAD(ref) as
//     additional data, so a sealed secret opens only for the exact reference
//     version, asset, node, endpoint, transport and access level it was
//     sealed for.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"otsec.local/otsec/contracts/authz"
)

// Info is the HKDF info prefix.
const Info = "otsec.authz/0.1 " + authz.SealAlg + "\n"

// InstallKey is a collector's public install key as the node publishes it.
// It is public; its integrity is what the pinned fingerprint protects.
type InstallKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64, 32 bytes
}

var (
	// ErrNoPinnedFingerprint is returned by Seal when no fingerprint was
	// pinned at commissioning (T-12).
	ErrNoPinnedFingerprint = errors.New("seal: no pinned install-key fingerprint; refusing to seal")
	// ErrFingerprintMismatch is returned by Seal when the published key is
	// not the one pinned at commissioning (T-12).
	ErrFingerprintMismatch = errors.New("seal: install key does not match the pinned fingerprint; refusing to seal")
	// ErrOpen is returned by Open for any sealed secret that does not open.
	// It never says why, and never carries any of the plaintext.
	ErrOpen = errors.New("seal: sealed secret does not open")
)

// Fingerprint is the SHA-256 of the raw 32-byte public key, as "sha256:"
// and 64 lowercase hex digits. The collector writes it to the Event Log and
// the install tool's console; the admin records it at commissioning.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// KeyID is the key ID that goes with a public key: "x25519-" and the first
// 16 hex digits of its fingerprint. It is derived, so a published key ID
// that does not match its key is refused.
func KeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "x25519-" + hex.EncodeToString(sum[:8])
}

// NormalizeFingerprint lowercases a fingerprint and removes spaces and the
// colons people insert between hex pairs, after the "sha256:" prefix. It
// returns "" for anything that is not a SHA-256 fingerprint.
func NormalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	rest, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return ""
	}
	rest = strings.NewReplacer(" ", "", ":", "").Replace(rest)
	if len(rest) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(rest); err != nil {
		return ""
	}
	return "sha256:" + rest
}

// PublicKeyBytes decodes and checks an install key: strict base64 of 32
// bytes, a key X25519 accepts, and the key ID derived from it.
func (k InstallKey) PublicKeyBytes() ([]byte, error) {
	pub, err := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
	if err != nil || len(pub) != 32 {
		return nil, errors.New("seal: install key is not 32 bytes of strict base64")
	}
	if _, err := ecdh.X25519().NewPublicKey(pub); err != nil {
		return nil, fmt.Errorf("seal: install key: %v", err)
	}
	if k.KeyID != KeyID(pub) {
		return nil, fmt.Errorf("seal: key id %q does not belong to the install key", k.KeyID)
	}
	return pub, nil
}

// Seal encrypts secret to the collector install key for ref. pinned is the
// fingerprint recorded at commissioning; Seal refuses to run when it is
// empty or differs from the key's. rnd is the randomness source; nil means
// crypto/rand. Seal does not keep or modify secret.
func Seal(key InstallKey, pinned string, ref authz.CredentialRef, secret []byte, rnd io.Reader) (authz.SealedSecret, error) {
	if strings.TrimSpace(pinned) == "" {
		return authz.SealedSecret{}, ErrNoPinnedFingerprint
	}
	pub, err := key.PublicKeyBytes()
	if err != nil {
		return authz.SealedSecret{}, err
	}
	want := NormalizeFingerprint(pinned)
	if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(Fingerprint(pub))) != 1 {
		return authz.SealedSecret{}, ErrFingerprintMismatch
	}
	if len(secret) == 0 || len(secret) > authz.MaxSecretLen {
		return authz.SealedSecret{}, fmt.Errorf("seal: secret must be 1 to %d bytes", authz.MaxSecretLen)
	}
	if err := ref.Validate(); err != nil {
		return authz.SealedSecret{}, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	recipient, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return authz.SealedSecret{}, err
	}
	eph, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return authz.SealedSecret{}, err
	}
	aead, err := deriveAEAD(eph, recipient, eph.PublicKey().Bytes(), pub)
	if err != nil {
		return authz.SealedSecret{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return authz.SealedSecret{}, err
	}
	ct := aead.Seal(nil, nonce, secret, authz.SealAAD(ref))
	s := authz.SealedSecret{
		Alg:                authz.SealAlg,
		RecipientKeyID:     key.KeyID,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:         base64.StdEncoding.EncodeToString(ct),
	}
	return s, s.Validate()
}

// Open decrypts a sealed secret with the collector's install key. It checks
// the envelope (SealedSecret.Validate) and that it names this key. Every
// failure is ErrOpen. The caller owns the returned slice and wipes it.
func Open(priv *ecdh.PrivateKey, ref authz.CredentialRef, s authz.SealedSecret) ([]byte, error) {
	if priv == nil || s.Validate() != nil {
		return nil, ErrOpen
	}
	if s.RecipientKeyID != KeyID(priv.PublicKey().Bytes()) {
		return nil, ErrOpen
	}
	ephBytes, _ := base64.StdEncoding.Strict().DecodeString(s.EphemeralPublicKey) // checked by Validate
	nonce, _ := base64.StdEncoding.Strict().DecodeString(s.Nonce)
	ct, _ := base64.StdEncoding.Strict().DecodeString(s.Ciphertext)
	eph, err := ecdh.X25519().NewPublicKey(ephBytes)
	if err != nil {
		return nil, ErrOpen
	}
	aead, err := deriveAEAD(priv, eph, ephBytes, priv.PublicKey().Bytes())
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := aead.Open(nil, nonce, ct, authz.SealAAD(ref))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// deriveAEAD computes the shared secret of own and peer, and the AES-256-GCM
// key from it. ephPub and recipientPub are the two public keys, whichever
// side holds the private half.
func deriveAEAD(own *ecdh.PrivateKey, peer *ecdh.PublicKey, ephPub, recipientPub []byte) (cipher.AEAD, error) {
	shared, err := own.ECDH(peer)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	info := Info + string(ephPub) + string(recipientPub)
	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
