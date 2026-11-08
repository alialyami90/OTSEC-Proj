package node

import (
	"testing"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/sensorlink"
)

// The network database's commit cap holds a whole release of the intake
// hold (D1 in D4-72), and only that database's cap is raised.
func TestNetworkCommitBytes(t *testing.T) {
	if n := int64(sensorlink.HoldRecordCap) * c5.MinRecordBytes; n > NetworkCommitBytes {
		t.Fatalf("a release can commit %d bytes, over NetworkCommitBytes %d", n, NetworkCommitBytes)
	}
	if g := groupFor(c5.Database{ID: NetworkDB}, c5.GroupOptions{}); g.CommitBytes() != NetworkCommitBytes {
		t.Fatalf("the network database's cap is %d", g.CommitBytes())
	}
	if g := groupFor(c5.Database{ID: NetworkDB}, c5.GroupOptions{}); g.CommitRecords() < sensorlink.HoldRecordCap {
		t.Fatalf("the network database's record cap is %d", g.CommitRecords())
	}
	if g := groupFor(c5.Database{ID: AuditDB}, c5.GroupOptions{}); g.CommitBytes() != c5.DefaultGroup.CommitBytes() {
		t.Fatalf("the audit database's cap is %d", g.CommitBytes())
	}
}
