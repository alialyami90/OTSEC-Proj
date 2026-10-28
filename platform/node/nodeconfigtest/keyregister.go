package nodeconfigtest

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"time"

	"otsec.local/otsec/modules/security/nodekey"
)

// The references WriteKeyRegister installs.
const (
	ClientKeyRef   = "nodekey_client01"
	AnchorsRef     = "nodekey_anchors01"
	ListenerKeyRef = "nodekey_listener01"
	// KeyAdmin installs every entry.
	KeyAdmin = "admin@site-a"
)

// WriteKeyRegister writes a node key register, register.json in TLSDir,
// as an administrator's tool would, and names it in key_register: a
// lab-files client key for the node's name signed by p's CA, valid until
// notAfter, and p's CA as trust anchors; with listenerHost set, a
// listener key for that host too. The keys are lab-files keys in TLSDir,
// so lab_tls_files stays set. It returns the register so a test can
// change it and write it again with WriteRegister.
func (c *Config) WriteKeyRegister(p *PKI, listenerHost string, notAfter time.Time) (*nodekey.Register, error) {
	return c.WriteKeyRegisterAt(p, listenerHost, notAfter, time.Now())
}

// WriteKeyRegisterAt is WriteKeyRegister with the entries installed at the
// time at, which must fall inside the certificates' period: the register
// refuses to install an expired certificate, so a register whose certificate
// has expired by the time the node loads it is made by installing in the
// past, as time would.
func (c *Config) WriteKeyRegisterAt(p *PKI, listenerHost string, notAfter, at time.Time) (*nodekey.Register, error) {
	reg := nodekey.NewRegister(c.NodeID)
	keys := nodekey.LabFiles{Dir: c.TLSDir}
	now := at
	install := func(ref, name string, usage x509.ExtKeyUsage) error {
		csr, err := reg.Request(keys, ref, pkix.Name{CommonName: name}, KeyAdmin, now)
		if err != nil {
			return err
		}
		cert, err := p.Sign(csr, usage, notAfter)
		if err != nil {
			return err
		}
		return reg.Install(ref, [][]byte{cert}, KeyAdmin, now)
	}
	if err := install(ClientKeyRef, c.NodeID, x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	if listenerHost != "" {
		if err := install(ListenerKeyRef, listenerHost, x509.ExtKeyUsageServerAuth); err != nil {
			return nil, err
		}
	}
	if err := reg.SetAnchors(AnchorsRef, [][]byte{p.CA()}, KeyAdmin, now); err != nil {
		return nil, err
	}
	if err := c.WriteRegister(reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// WriteRegister writes reg as TLSDir's register.json and names it in
// key_register.
func (c *Config) WriteRegister(reg *nodekey.Register) error {
	b, err := reg.Marshal()
	if err != nil {
		return err
	}
	c.KeyRegister = filepath.Join(c.TLSDir, "register.json")
	return os.WriteFile(c.KeyRegister, b, 0o600)
}
