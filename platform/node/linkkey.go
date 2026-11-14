package node

import (
	"path/filepath"
	"slices"

	"otsec.local/otsec/platform/sensorlink"
	"otsec.local/otsec/platform/store/protect"
)

// The node's link key (docs/phase4/D5-sensor-node.md section 1.9 item 11;
// docs/phase4/D3-sensor-link.md section 11.4, NK-1 to NK-6; F11). It is in
// a file of its own beside the key register, never in it, so nothing in
// Start, NewForwarding or NewListening reads it. The sensor manager reads
// it, through platform/sensorlink, once the node has resolved its
// references and handed it the register (KeysResolved), and at each step
// it asks for until the key loads. Any fault in it holds back the sensor
// links only: the node runs and collects, and AlarmSensorLinkKey stands
// (NK-5). This package never opens the key: it passes the providers to
// platform/sensorlink, which keeps the signer
// (TestNodeOpensNoProviderKey). No dial is built (D4-96).

// AlarmSensorLinkKey: the node's link key did not load, so no sensor link
// is made. The node runs and collects without it, and the manager reads
// the file again at each step until the key loads, against the register
// view KeysResolved handed it: a register that loads only later (a
// RecordNodeKeys retry) is not seen until a restart. It is raised once for
// each fault, and again only for another (NK-5).
const AlarmSensorLinkKey = "sensor-link-key"

// LinkKeyFileName is the link key file, beside key_register, or in tls_dir
// on a node without one (lab_tls_files).
const LinkKeyFileName = "linkkey.json"

// linkKeyPath is where the link key file is, or "" on a node with neither
// key_register nor tls_dir.
func (c *Config) linkKeyPath() string {
	switch {
	case c.KeyRegister != "":
		return filepath.Join(filepath.Dir(c.KeyRegister), LinkKeyFileName)
	case c.TLSDir != "":
		return filepath.Join(c.TLSDir, LinkKeyFileName)
	}
	return ""
}

// KeysResolved hands the sensor manager the node key register as the node
// loaded it, once every reference of the configuration is resolved and the
// register recorded (Run calls it after RecordNodeKeys), and asks the
// manager for a step. The manager reads no link key before it. It is
// called on the goroutine that resolved the references, so the register
// is read there. Without the network_sensor section it does nothing.
func (r *Runtime) KeysResolved() {
	if r.cfg.NetworkSensor == nil {
		return
	}
	v := sensorlink.RegisterView{Set: r.cfg.KeyRegister != ""}
	if ks := r.cfg.keys; v.Set && ks != nil {
		v.Loaded, v.Entries = true, slices.Clone(ks.reg.Entries)
	}
	r.linkReg.Store(&v)
	r.kickSensorManager()
}

// stepLinkKey reads the link key until it loads. Only the sensor manager's
// step calls it, after the node's start has returned (NK-5).
func (r *Runtime) stepLinkKey() {
	m, reg := r.smgr, r.linkReg.Load()
	if m.linkKey != nil || reg == nil {
		return
	}
	path, fault := r.cfg.linkKeyPath(), ""
	var k *sensorlink.LinkKey
	if path == "" {
		fault = "neither key_register nor tls_dir is set, so the node has no place for its link key file"
	} else {
		ks := &keyStore{}
		if r.cfg.LabTLSFiles {
			ks.lab = r.cfg.TLSDir
		}
		k = sensorlink.ReadLinkKey(readProtected, path, string(r.cfg.NodeID), r.cfg.NetworkSensor.LinkKeyRef, ks.provider, *reg)
		if err := k.Err(); err != nil {
			fault = err.Error()
		}
	}
	if fault == "" {
		m.linkKey, m.linkFault = k, ""
		return
	}
	if fault != m.linkFault {
		m.linkFault = fault
		r.opt.Status.Raise("", AlarmSensorLinkKey, "sensor "+r.sensorID()+": the link key did not load, so no sensor link is made; SER, Syslog and forwarding go on. The file is read again at each step, against the key register as the node loaded it when it resolved its references, so a register that loads only later needs a restart: "+fault)
	}
}

// readProtected reads a file under the protected-file rule, its directory
// first, as the key register is read (nodeKeys).
func readProtected(path string, max int64) ([]byte, error) {
	if err := protect.CheckDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return protect.ReadFile(path, max)
}

// linkKeyPin is the loaded link key's pin, or "" (NK-4).
func (r *Runtime) linkKeyPin() string {
	if k := r.smgr.linkKey; k != nil {
		return k.Pin()
	}
	return ""
}
