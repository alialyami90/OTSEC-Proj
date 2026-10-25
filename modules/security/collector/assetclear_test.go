package collector

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

const (
	suspendingRun = "5d0c9a41-7e2b-4f68-a913-2c6e8b0f4d57" // the invocation that suspended the asset
	laterRun      = "9a3e6c12-4b7d-4e01-8f25-6d1b0c7a9e48"
	otherAsset    = "c41f8a2d-6b0e-4e97-8d13-5a2c9f7b0e64"
)

var nodePrincipal = authz.Principal{Type: authz.PrincipalNode, ID: testNode}

// adminFile stands in for the administrators' folder: what ReadClearFile
// returns, and how often it was read.
type adminFile struct {
	b     []byte
	err   error
	reads int
}

func (a *adminFile) read() ([]byte, error) {
	a.reads++
	return a.b, a.err
}

func clearFileFor(assetID, ref string) []byte {
	return []byte(`{"schema":"` + ClearSuspensionSchema + `","asset_id":"` + assetID + `","ref":"` + ref + `"}`)
}

func clearRequest(assetID, ref string) *authz.CollectorRequest {
	return &authz.CollectorRequest{
		Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: "req-asset-clear",
		OnBehalfOf: nodePrincipal, PolicyVersion: policyVersion,
		AssetClearSusp: &authz.AssetClearSuspBody{AssetID: assetID, Ref: ref},
	}
}

// suspendedPipeline is a pipeline whose asset an earlier run suspended,
// with the administrators' folder holding file.
func suspendedPipeline(t *testing.T, file *adminFile) *pipeFixture {
	t.Helper()
	f := newPipeline(t, func(c *PipelineConfig, _ *pipeFixture) {
		if file != nil {
			c.ReadClearFile = file.read
		}
	})
	if err := f.state.SuspendAsset(testAsset, adapter.FailedAuthRejected, suspendingRun); err != nil {
		t.Fatal(err)
	}
	return f
}

// stillSuspended fails the test unless the asset is suspended by the
// suspending run, in memory and on disk.
func (f *pipeFixture) stillSuspended(t *testing.T, by string) {
	t.Helper()
	for _, s := range []*State{f.state, f.reopenState(t)} {
		if err := s.CheckSuspended(testAsset); err == nil || !strings.Contains(err.Error(), by) {
			t.Fatalf("asset not suspended by %s: %v", by, err)
		}
	}
}

func (f *pipeFixture) reopenState(t *testing.T) *State {
	t.Helper()
	s, err := OpenState(f.state.path, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAssetClearDenials: every way an asset clear can fail leaves the asset
// suspended, and the refusal is numbered, so the node's collector.request
// record shows the denial (D2-15; A1's conditions on the design, A6's list).
func TestAssetClearDenials(t *testing.T) {
	for _, c := range []struct {
		name string
		file *adminFile // nil: no folder configured
		req  *authz.CollectorRequest
		want authz.RefusalCode
	}{
		{"no folder configured", nil, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"request without a file", &adminFile{err: fs.ErrNotExist}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"refused folder", &adminFile{err: errors.New("directory admin has mode 0770")}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"stale file", &adminFile{b: clearFileFor(testAsset, laterRun)}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"file for another asset", &adminFile{b: clearFileFor(otherAsset, suspendingRun)}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"request and file name another suspension", &adminFile{b: clearFileFor(testAsset, laterRun)}, clearRequest(testAsset, laterRun), authz.RefuseSuspensionMismatch},
		{"other schema", &adminFile{b: []byte(strings.Replace(string(clearFileFor(testAsset, suspendingRun)), ClearSuspensionSchema, "otsec.clear-suspension/9.0", 1))}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"unknown field", &adminFile{b: []byte(strings.Replace(string(clearFileFor(testAsset, suspendingRun)), `{`, `{"all":true,`, 1))}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"duplicate ref", &adminFile{b: []byte(strings.Replace(string(clearFileFor(testAsset, suspendingRun)), `"ref"`, `"ref":"`+laterRun+`","ref"`, 1))}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"trailing data", &adminFile{b: append(clearFileFor(testAsset, suspendingRun), clearFileFor(testAsset, laterRun)...)}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"empty file", &adminFile{b: []byte{}}, clearRequest(testAsset, suspendingRun), authz.RefuseSuspensionMismatch},
		{"asset not enrolled", &adminFile{b: clearFileFor(otherAsset, suspendingRun)}, clearRequest(otherAsset, suspendingRun), authz.RefuseAssetNotEnrolled},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := suspendedPipeline(t, c.file)
			reply, work := f.pipe.Handle(context.Background(), c.req)
			if work != nil || refusalOf(reply) != c.want || reply.CollectorSeq == 0 {
				t.Fatalf("reply %+v, want %s", reply, c.want)
			}
			f.stillSuspended(t, suspendingRun)
			if c.file != nil && c.want == authz.RefuseSuspensionMismatch && c.file.reads != 1 {
				t.Errorf("the file was read %d times", c.file.reads)
			}
		})
	}
}

// TestAssetClearPrincipal: only the node relays a clear. A person or a
// schedule is refused before the file is read (C7 Validate refuses them
// too; this is the pipeline's own check).
func TestAssetClearPrincipal(t *testing.T) {
	for _, p := range []authz.Principal{pipeAdmin, schedule, {Type: authz.PrincipalSystem, ID: "svc"}} {
		file := &adminFile{b: clearFileFor(testAsset, suspendingRun)}
		f := suspendedPipeline(t, file)
		req := clearRequest(testAsset, suspendingRun)
		req.OnBehalfOf = p
		if reply, _ := f.pipe.Handle(context.Background(), req); refusalOf(reply) != authz.RefusePrincipal {
			t.Fatalf("%s: %+v", p.Type, reply)
		}
		if file.reads != 0 {
			t.Fatalf("%s: the file was read", p.Type)
		}
		f.stillSuspended(t, suspendingRun)
	}
}

// TestAssetClear: the request, the file and the suspension match, so the
// suspension is lifted durably and the next run reaches the runner. A
// planted file alone never lifted it, and the same clear does not lift a
// later suspension.
func TestAssetClear(t *testing.T) {
	file := &adminFile{b: clearFileFor(testAsset, suspendingRun)}
	f := suspendedPipeline(t, file)
	f.installCanary(t)
	f.clock.t = f.clock.t.Add(time.Hour) // past the fresh-state floor
	// The file alone, with no request: the run is still refused.
	if reply, _ := f.run(t, pipeRun("sel.id", "")); refusalOf(reply) != authz.RefuseAssetSuspended || file.reads != 0 {
		t.Fatalf("run with only the file: %+v (reads %d)", reply, file.reads)
	}
	reply, work := f.pipe.Handle(context.Background(), clearRequest(testAsset, suspendingRun))
	if !reply.Accepted() || work != nil || reply.InvocationID != "" {
		t.Fatalf("clear: %+v", reply)
	}
	for _, s := range []*State{f.state, f.reopenState(t)} {
		if err := s.CheckSuspended(testAsset); err != nil {
			t.Fatalf("still suspended: %v", err)
		}
	}
	if reply, _ := f.run(t, pipeRun("sel.id", "")); !reply.Accepted() || f.runner.count() != 1 {
		t.Fatalf("run after the clear: %+v", reply)
	}
	// A retry after a lost reply: the asset is already clear, so it is
	// accepted and changes nothing (A5 on #117).
	if again, _ := f.pipe.Handle(context.Background(), clearRequest(testAsset, suspendingRun)); !again.Accepted() {
		t.Fatalf("repeat: %+v", again)
	}
	if err := f.state.CheckSuspended(testAsset); err != nil {
		t.Fatal(err)
	}
	// A run suspends the asset again: the old clear, file and request
	// alike, does not lift the new suspension.
	if err := f.state.SuspendAsset(testAsset, adapter.FailedAuthRejected, laterRun); err != nil {
		t.Fatal(err)
	}
	if again, _ := f.pipe.Handle(context.Background(), clearRequest(testAsset, suspendingRun)); refusalOf(again) != authz.RefuseSuspensionMismatch {
		t.Fatalf("old clear after a new suspension: %+v", again)
	}
	f.stillSuspended(t, laterRun)
}

// TestAssetClearReinstalled: a reinstalled collector holds no suspensions,
// so a clear that matches the administrator's file is accepted and the
// node's "collector still suspended" status can settle (A5 on #117). A
// request that does not match the file is still refused.
func TestAssetClearReinstalled(t *testing.T) {
	f := newPipeline(t, func(c *PipelineConfig, _ *pipeFixture) {
		c.ReadClearFile = (&adminFile{b: clearFileFor(testAsset, suspendingRun)}).read
	})
	if reply, _ := f.pipe.Handle(context.Background(), clearRequest(testAsset, suspendingRun)); !reply.Accepted() {
		t.Fatalf("clear on a state without the suspension: %+v", reply)
	}
	if reply, _ := f.pipe.Handle(context.Background(), clearRequest(testAsset, laterRun)); refusalOf(reply) != authz.RefuseSuspensionMismatch {
		t.Fatalf("request not matching the file: %+v", reply)
	}
}

// TestAssetClearAfterLaterSuspension: an identity mismatch replaces the
// suspension, so a clear naming the first invocation, file and request
// alike, lifts nothing.
func TestAssetClearAfterLaterSuspension(t *testing.T) {
	f := suspendedPipeline(t, &adminFile{b: clearFileFor(testAsset, suspendingRun)})
	if err := f.state.SuspendAsset(testAsset, adapter.RefusedIdentityMismatch, laterRun); err != nil {
		t.Fatal(err)
	}
	if reply, _ := f.pipe.Handle(context.Background(), clearRequest(testAsset, suspendingRun)); refusalOf(reply) != authz.RefuseSuspensionMismatch {
		t.Fatalf("clear of the replaced suspension: %+v", reply)
	}
	f.stillSuspended(t, laterRun)
}

// TestAssetAndCredentialClearsAreSeparate (A1 condition 3): clearing the
// asset leaves the credential suspended, and clearing the credential
// leaves the asset suspended.
func TestAssetAndCredentialClearsAreSeparate(t *testing.T) {
	f := suspendedPipeline(t, &adminFile{b: clearFileFor(testAsset, suspendingRun)})
	f.installCanary(t)
	if _, _, err := f.store.Suspend(pipeCred, 1, authz.SuspendOperator); err != nil {
		t.Fatal(err)
	}
	credClear := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialClearSusp, RequestID: "req-cred-clear",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, CredentialClearSusp: &authz.CredentialClearSuspBody{RefID: pipeCred, Version: 1}}
	if reply, _ := f.pipe.Handle(context.Background(), credClear); !reply.Accepted() {
		t.Fatalf("credential clear: %+v", reply)
	}
	f.stillSuspended(t, suspendingRun)

	if _, _, err := f.store.Suspend(pipeCred, 1, authz.SuspendOperator); err != nil {
		t.Fatal(err)
	}
	if reply, _ := f.pipe.Handle(context.Background(), clearRequest(testAsset, suspendingRun)); !reply.Accepted() {
		t.Fatalf("asset clear: %+v", reply)
	}
	if st := f.store.Status(pipeCred); st[0].State != authz.CredentialSuspended {
		t.Fatalf("the asset clear lifted the credential's suspension: %+v", st)
	}
}

// TestClearAssetSuspensionState: the state's own rule, without the
// pipeline.
func TestClearAssetSuspensionState(t *testing.T) {
	_, state, _ := newState(t)
	var r *authz.Refusal
	if err := state.ClearAssetSuspension(testAsset, suspendingRun); err != nil {
		t.Fatalf("clear of an asset not suspended: %v", err)
	}
	if err := state.SuspendAsset(testAsset, adapter.RefusedPasswordPromptAbsent, suspendingRun); err != nil {
		t.Fatal(err)
	}
	if err := state.ClearAssetSuspension(testAsset, laterRun); !errors.As(err, &r) || r.Code != authz.RefuseSuspensionMismatch {
		t.Fatalf("clear naming another run: %v", err)
	}
	if err := state.ClearAssetSuspension(testAsset, suspendingRun); err != nil {
		t.Fatal(err)
	}
	if err := state.CheckSuspended(testAsset); err != nil {
		t.Fatal(err)
	}
}

// TestHeldSuspensionNamed: a refusal because the collector holds the asset
// suspended names that suspension (C7 0.3), so a node that never recorded
// it, because the suspending run's reply was lost, can adopt it and clear
// it the normal way (A6 on #120). A clear naming another invocation is
// told which one is held. A request stamped before 0.3 gets the 0.2 reply.
func TestHeldSuspensionNamed(t *testing.T) {
	held := authz.HeldSuspension{Reason: asset.SuspendAuthFailed, Ref: suspendingRun, Code: string(adapter.FailedAuthRejected)}
	f := suspendedPipeline(t, &adminFile{b: clearFileFor(testAsset, laterRun)})
	f.installCanary(t)
	f.clock.t = f.clock.t.Add(time.Hour) // past the fresh-state floor
	check := func(name string, reply authz.CollectorReply, code authz.RefusalCode, want *authz.HeldSuspension) {
		t.Helper()
		got, err := reply.HeldSuspension()
		if refusalOf(reply) != code || err != nil || (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: %+v, held %+v, %v; want %s naming %+v", name, reply.Refusal, got, err, code, want)
		}
		if reply.CollectorSeq == 0 {
			t.Errorf("%s: no collector_seq", name)
		}
	}
	reply, _ := f.run(t, pipeRun("sel.id", ""))
	check("run", reply, authz.RefuseAssetSuspended, &held)
	reply, _ = f.pipe.Handle(context.Background(), clearRequest(testAsset, laterRun))
	check("clear naming another invocation", reply, authz.RefuseSuspensionMismatch, &held)

	old := pipeRun("sel.id", "")
	old.Contract = "otsec.authz/0.2"
	reply, _ = f.run(t, old)
	check("run stamped 0.2", reply, authz.RefuseAssetNotEnrolled, nil)
	oldClear := clearRequest(testAsset, laterRun)
	oldClear.Contract = "otsec.authz/0.2"
	reply, _ = f.pipe.Handle(context.Background(), oldClear)
	check("clear stamped 0.2", reply, authz.RefuseSuspensionMismatch, nil)
	if f.runner.count() != 0 {
		t.Fatal("a run to the suspended asset reached the runner")
	}
	f.stillSuspended(t, suspendingRun)
}
