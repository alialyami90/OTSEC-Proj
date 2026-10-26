package nodekey

import "crypto"

// CNG keeps keys in Windows CNG as machine keys whose export policy is off
// (credential design section 9). A key is used where it lives: Open returns
// a crypto.Signer that asks CNG to sign, and nothing can read the private
// key out, not the node and not an administrator.
//
// Create makes the key with the provider's default DACL for a machine key,
// so the administrator's tool can sign the certificate request. Request
// then calls Restrict, which sets the DACL the key keeps, once, through the
// handle Create returned: SYSTEM and Administrators have full control, and
// the listed Users (the node service) may use the key. No other account,
// the collector service among them, has any right. Administrators are not
// excluded from use: an administrator must keep write-DAC and delete to
// retire the key, write-DAC lets them grant themselves use, and they can
// act as SYSTEM in any case (TestCNGRightsProbe, CI on #157). The
// administrator's tool runs elevated.
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
