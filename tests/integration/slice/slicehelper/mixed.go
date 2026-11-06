package main

import (
	"os"
	"path/filepath"

	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// snmpAssetID is the mixed node's SEL-2731M (#466).
const snmpAssetID = "3c8e5f21-9d4a-4b6c-8f32-8d5e1e7b9c24"

// mixedSNMP adds a SEL-2731M polled over SNMPv3 at port to the node: the
// mixed node of C5's register_versions (#466), the SEL-751 under
// register_version and the SEL-2731M under its profile's entry, unless
// unlisted. It returns the collector's SEL-2731 test profile and C2's
// sel-27x1-rstp test package (revision 1) for collector.json. No
// credential is installed for the SEL-2731M, so a run the collector
// accepts past its register check (step 5 of decideRun) stops at the
// credential (step 10) and never sends a datagram.
func mixedSNMP(nc *nodeconfigtest.Config, l *Layout, repo string, port int, unlisted bool) (profile, payload []byte, err error) {
	if port == 0 {
		return nil, nil, nil
	}
	if profile, err = os.ReadFile(filepath.Join(repo, "modules", "security", "collector", "testdata", "profile-sel-27x1-rstp.json")); err != nil {
		return nil, nil, err
	}
	if payload, err = os.ReadFile(filepath.Join(repo, "contracts", "adapter", "testdata", "snmp", "register.json")); err != nil {
		return nil, nil, err
	}
	nc.AddSEL2731M(snmpAssetID, "127.0.0.1", port, 60)
	// AddSEL2731M turns the asset module on, whose identity records need
	// room in the configuration class (C5 0.8).
	nc.Store.Quotas["configuration"] = 32 << 20
	if unlisted {
		delete(nc.RegisterVersions, nodeconfigtest.TestSNMPProfile)
	}
	l.SNMPAsset = snmpAssetID
	return profile, payload, nil
}
