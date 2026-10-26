package nodekey

import "crypto"

// CNG keeps keys in Windows CNG as machine keys whose export policy is off
// (credential design section 9). A key is used where it lives: Open returns
// a crypto.Signer that asks CNG to sign, and nothing can read the private
// key out, not the node and not an administrator.
//
// Create makes the key with a DACL that lets SYSTEM and the creating
// administrator use it, so the administrator's tool can sign the
// certificate request; Restrict then replaces the DACL, through the handle
// Create returned, with the one the key keeps: SYSTEM and Users may use it,
// and Administrators may only read and change the DACL and delete the key.
// The collector service is in neither. Request calls Restrict after the
// certificate request is signed. The administrator's tool runs elevated.
//
// On other systems every method returns an error.
type CNG struct {
	// Platform selects the Microsoft Platform Crypto Provider (TPM) in
	// place of the Microsoft Software Key Storage Provider. Use it only
	// where T-2 shows the TPM works.
	Platform bool
	// Users are the SIDs, as strings, that may use a key after Restrict,
	// beside SYSTEM: the node service's SID (NT SERVICE\otsec-node) in
	// production.
	Users []string
}

func (c CNG) Provider() Provider {
	if c.Platform {
		return ProviderCNGPlatform
	}
	return ProviderCNGSoftware
}

// restricter is a Keys whose new keys need a final step once the
// certificate request is signed (CNG). It is given the signer Create
// returned, because only the creating handle may still change the key.
type restricter interface {
	Restrict(created crypto.Signer) error
}
