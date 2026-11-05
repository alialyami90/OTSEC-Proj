// Package advisorytest is the one source of advisory test keys (C11 1.6, C6
// on #437). Every test that signs an advisory set gets its key from Key, and
// the release build's refusal list, advisory.TestKeyIDs, is the key IDs of
// these seeds; a contract test holds the two together.
//
// The seeds are published here on purpose: this repository is public, so a
// test key's private half is known to everyone. Seed n is the SHA-256 of
// "otsec.advisory test key <n>". GT-ADV's signer and the signing tool under
// tests/ use the same seeds.
package advisorytest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"otsec.local/otsec/contracts/advisory"
)

// Seeds are the published Ed25519 seeds, in hex.
var Seeds = []string{
	"5295c3ceb2fe42617b344c9f0b170cacdc0833a55df0ee97ca29abccc86e6ad4",
	"222dd452e2a77343bf05390ce774c8b286c00e63c65b676c8717ab91b5f734f4",
	"7547e80aa8767cef89b633f83244451bffd4566bbd0f2359779ccc3b1e874463",
	"2eefd08781632db35058de19c17d2b4a3324dd48d8b51ca7c997ea6cf7dae0bc",
}

// Key returns test key n. It panics on an n outside Seeds, which is a test's
// own mistake.
func Key(n int) ed25519.PrivateKey {
	seed, err := hex.DecodeString(Seeds[n])
	if err != nil {
		panic(fmt.Sprintf("advisorytest: seed %d: %v", n, err))
	}
	return ed25519.NewKeyFromSeed(seed)
}

// Anchor returns test key n as an active advisory anchor.
func Anchor(n int) advisory.Anchor {
	pub := Key(n).Public().(ed25519.PublicKey)
	return advisory.Anchor{KeyID: advisory.KeyID(pub), PublicKey: pub, Status: advisory.KeyActive}
}

// Sign returns the envelope's bytes for payload, signed with priv.
func Sign(priv ed25519.PrivateKey, payload []byte) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	env := advisory.Envelope{
		Contract:  advisory.Identifier,
		Algorithm: "ed25519",
		KeyID:     advisory.KeyID(pub),
		Payload:   payload,
		Signature: ed25519.Sign(priv, advisory.SigningInput(payload)),
	}
	b, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	return b
}
