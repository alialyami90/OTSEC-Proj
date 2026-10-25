package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/node"
)

// The collector reads the node's administrator file, so the name, the
// schema and the size bound are the node's.
func TestClearFileIsTheNodes(t *testing.T) {
	if collector.ClearSuspensionFileName != node.ClearSuspensionFileName ||
		collector.ClearSuspensionSchema != node.ClearSuspensionSchema ||
		collector.MaxClearSuspensionBytes != node.MaxClearSuspensionBytes {
		t.Fatal("the collector's clear-suspension.json differs from the node's")
	}
}

// TestServeAssetClear runs C7 0.2 asset.clear_suspension through the
// binary's own wiring, on the socket: a folder the collector could write is
// refused, and a protected one with a matching file clears the suspension
// durably. Linux checks the mode only (development platform); the Windows
// DACL rules are platform/store's tests and the PC run.
func TestServeAssetClear(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows service path needs the installer's WER exclusion and the service accounts (PC run)")
	}
	const (
		assetID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
		ref     = "5d0c9a41-7e2b-4f68-a913-2c6e8b0f4d57"
	)
	data := t.TempDir()
	l := newLayout(data)
	sockDir := filepath.Join(t.TempDir(), "run")
	for _, d := range []string{filepath.Dir(l.state), filepath.Dir(l.credentials), filepath.Dir(l.publicKey), sockDir, l.admin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.Chmod(l.admin, 0o700) })
	socket := filepath.Join(sockDir, "collector.sock")
	if err := os.WriteFile(l.config, marshal(t, testConfig(t, socket)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.provision, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The first start creates the state; a run's outcome then suspends the
	// asset, as the pipeline does.
	r, err := start(data, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	st, err := collector.OpenState(l.state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SuspendAsset(assetID, asset.SuspendAuthFailed, ref); err != nil {
		t.Fatal(err)
	}
	clearFile := `{"schema":"` + collector.ClearSuspensionSchema + `","asset_id":"` + assetID + `","ref":"` + ref + `"}`
	if err := os.WriteFile(filepath.Join(l.admin, collector.ClearSuspensionFileName), []byte(clearFile), 0o440); err != nil {
		t.Fatal(err)
	}

	r, err = start(data, log)
	if err != nil {
		t.Fatal(err)
	}
	defer r.stop()
	client := collectorclient.New(collectorwire.Endpoint{Address: socket, Peer: strconv.Itoa(os.Getuid())})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: "req-asset-clear",
		OnBehalfOf:     authz.Principal{Type: authz.PrincipalNode, ID: testNode},
		PolicyVersion:  3,
		AssetClearSusp: &authz.AssetClearSuspBody{AssetID: assetID, Ref: ref}}

	// The folder is still writable by its owner, the collector's account.
	resp, err := client.Do(ctx, req)
	if err != nil || resp.Reply.Refusal == nil || resp.Reply.Refusal.Code != authz.RefuseSuspensionMismatch || !strings.Contains(resp.Reply.Refusal.Detail, "0700") {
		t.Fatalf("writable folder: %+v %v", resp.Reply, err)
	}
	if err := os.Chmod(l.admin, 0o550); err != nil {
		t.Fatal(err)
	}
	if resp, err = client.Do(ctx, req); err != nil || !resp.Reply.Accepted() {
		t.Fatalf("clear: %+v %v", resp.Reply, err)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if st, err = collector.OpenState(l.state, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckSuspended(assetID); err != nil {
		t.Fatalf("still suspended after the clear: %v", err)
	}
}
