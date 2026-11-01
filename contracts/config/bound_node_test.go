package config_test

import (
	"testing"

	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/platform/node"
)

// C9's record cap is the number the node holds the configuration database to.
// Were they to drift, a snapshot C9 accepts could be refused at the commit, or
// the headroom would be wrong (B1 on #345).
func TestRecordCapIsTheNodes(t *testing.T) {
	if config.RecordCap != node.ConfigRecordBytes {
		t.Errorf("config.RecordCap %d, node.ConfigRecordBytes %d: change them together", config.RecordCap, node.ConfigRecordBytes)
	}
}
