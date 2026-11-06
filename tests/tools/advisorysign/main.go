// Command advisorysign signs a C11 advisory set with a published test key, so
// that C6's tests can build sets for V-M7 and V-M8 (P4-3-C3). It is test
// tooling: it lives under tests/, is linked into neither binary, and signs
// only with advisorytest's keys, whose private halves are public. A release
// build refuses those keys as anchors (advisory.TestKeyIDs), so nothing it
// signs is accepted outside a build tagged otsec_testclock.
//
// Usage:
//
//	go run ./tests/tools/advisorysign -key 0 < set.json > advisory-set.json
//	go run ./tests/tools/advisorysign -key 0 -anchor
//
// The first form reads the set's payload bytes as they are and writes the
// signed envelope. It signs the bytes it is given, valid or not, so a test
// can build invalid sets on purpose; it does not validate them. It refuses
// two things. A payload more than one byte over advisory.MaxSetPayload is
// refused, not cut, so an oversized case is never signed as a valid prefix.
// A payload whose purpose is release is refused too: a test key has no
// business on one, and refusing it means nobody makes one by mistake. A Go
// test that needs such a set on purpose calls advisorytest.Sign. The second
// prints test key n's key ID and public key in base64, for a test node's
// anchors.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
)

func main() {
	n := flag.Int("key", 0, "the advisorytest key to sign with")
	anchor := flag.Bool("anchor", false, "print the key's ID and public key instead of signing")
	flag.Parse()
	if *n < 0 || *n >= len(advisorytest.Seeds) {
		fmt.Fprintf(os.Stderr, "advisorysign: -key must be 0 to %d\n", len(advisorytest.Seeds)-1)
		os.Exit(2)
	}
	priv := advisorytest.Key(*n)
	if *anchor {
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("%s %s\n", advisory.KeyID(pub), base64.StdEncoding.EncodeToString(pub))
		return
	}
	// One byte over the bound is signed, so a test can build a set the
	// verifier refuses for its size. Anything longer is refused, not cut:
	// signing a prefix could turn an oversized negative case into a valid
	// set without anyone noticing (C5 on #449).
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, advisory.MaxSetPayload+2))
	if err != nil {
		fmt.Fprintf(os.Stderr, "advisorysign: %v\n", err)
		os.Exit(1)
	}
	if len(payload) > advisory.MaxSetPayload+1 {
		fmt.Fprintf(os.Stderr, "advisorysign: the payload is over %d bytes; it is refused, not cut\n", advisory.MaxSetPayload+1)
		os.Exit(1)
	}
	var head struct {
		Purpose advisory.Purpose `json:"purpose"`
	}
	if json.Unmarshal(payload, &head) == nil && head.Purpose == advisory.PurposeRelease {
		fmt.Fprintln(os.Stderr, "advisorysign: refusing to sign a release set with a test key")
		os.Exit(1)
	}
	os.Stdout.Write(advisorytest.Sign(priv, payload))
}
