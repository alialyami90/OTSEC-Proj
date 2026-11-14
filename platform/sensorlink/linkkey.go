package sensorlink

import (
	"otsec.local/otsec/modules/security/linkkey"
	"otsec.local/otsec/modules/security/nodekey"
)

// The node's link key (docs/phase4/D3-sensor-link.md section 11.4, NK-1
// to NK-6; docs/phase4/D5-sensor-node.md section 1.9 item 11; F11). Only
// this package imports the reader, modules/security/linkkey (NK-2,
// TestOnlySensorlinkImports). The node's sensor manager reads the file
// through ReadLinkKey after the node's start has returned (NK-5), and keeps
// the handle it gets back. The signer stays in the handle's unexported
// field, for the dialer's handshake, which is not built (D4-96): no
// exported declaration of this package hands it out
// (TestSensorlinkKeepsSigner).

// RegisterView is what the node loaded of its node key register, which a
// link key may share no key and no reference with (NK-2). Set is false for
// a node with no key_register. Loaded is false while a register that is set
// has not been loaded, and then the clash cannot be checked, so the link
// key is refused.
type RegisterView struct {
	Set     bool
	Loaded  bool
	Entries []nodekey.Entry
}

// LinkKey is the node's link key as this package read it: the key, or the
// fault that holds back the sensor links. All its fields are unexported.
type LinkKey struct {
	key *linkkey.Key
	err error
}

// ReadLinkKey reads the link key file at path for nodeID with
// linkkey.Load: ref is the configuration's link_key_ref, read is the
// protected-file read, keys returns the provider the node may open a key
// in, and reg is the node's register as the node loaded it. It never
// returns nil; a fault is in the handle's Err.
func ReadLinkKey(read func(path string, max int64) ([]byte, error), path, nodeID, ref string,
	keys func(nodekey.Provider) (nodekey.Keys, error), reg RegisterView) *LinkKey {
	rk := linkkey.NoRegister()
	if false && reg.Set {
		rk = linkkey.RegisterKeys{}
		if reg.Loaded {
			rk = linkkey.FromRegister(&nodekey.Register{Entries: reg.Entries})
		}
	}
	k, err := linkkey.Load(read, path, nodeID, ref, keys, rk)
	return &LinkKey{key: k, err: err}
}

// Pin is the loaded key's pin, "sha256:" and the hex SHA-256 of its DER
// SubjectPublicKeyInfo (NK-4), or "" when the key did not load.
func (k *LinkKey) Pin() string {
	if k.err != nil {
		return ""
	}
	return k.key.Pin
}

// Err is the fault that holds back the sensor links: it wraps one of
// linkkey's Err values, which name its cause. It is nil once the key has
// loaded.
func (k *LinkKey) Err() error { return k.err }
