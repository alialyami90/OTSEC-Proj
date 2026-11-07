package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// A node whose reserve flush fails raises reserve-recreate-failed and does
// not collect (P4-H4, ADR-0004 item 8), for a fault in the file's flush and
// in the folder's.
func TestNodeWithAFailedReserveFlushDoesNotCollect(t *testing.T) {
	for _, step := range []string{"file", "folder"} {
		t.Run(step, func(t *testing.T) {
			defer store.FailReserveFlush(step, errors.New("injected flush fault"))()
			dir := t.TempDir()
			storeDir := filepath.Join(dir, "store")
			if err := store.CreateDir(storeDir, ""); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "node.json")
			nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751("2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "", 2323, 300)
			if err := nc.WriteInstallKey("ik_test_first"); err != nil {
				t.Fatal(err)
			}
			if err := nc.Write(path); err != nil {
				t.Fatal(err)
			}
			cfg, err := node.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			st := node.NewStatus(node.StatusPath(cfg), nil, nil)
			rt, err := node.Start(context.Background(), cfg, node.RuntimeOptions{Status: st})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close()
			if rt.Collecting() {
				t.Fatal("the node collects with no reserve")
			}
			raised := false
			for _, a := range st.Snapshot("site-a-node1").Alarms {
				raised = raised || a.Code == string(c5.AlarmReserveRecreateFailed)
			}
			if !raised {
				t.Fatalf("no %s alarm: %+v", c5.AlarmReserveRecreateFailed, st.Snapshot("site-a-node1").Alarms)
			}
		})
	}
}
