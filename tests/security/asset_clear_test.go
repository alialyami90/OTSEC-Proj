//go:build !windows

package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/platform/store/protect"
)

// C7 0.2 asset.clear_suspension, the collector side (D2-15, A1 condition 4
// on #117). The ground truth is the rule, not the implementation: the
// collector lifts an asset suspension only when the node's request, the
// administrator's clear-suspension.json in a folder neither service can
// write, and the collector's own record of the suspending invocation all
// name the same asset and invocation. Every denial must leave the asset
// suspended, in memory and on disk, refuse with suspension_mismatch (or
// the principal or contract refusal), and number the reply, so the node's
// collector.request record accounts for it. Class simulated. Linux only:
// the folder check there is the mode, so the refused-folder cases guard
// the wiring, not the Windows DACL boundary, which protect's Windows tests
// and the elevated installer run cover (A3, A5 on #116, #119).

const (
	invX = "6f1c2e8a-0000-4000-8000-0000000000a1" // suspends the asset
	invY = "6f1c2e8a-0000-4000-8000-0000000000b2" // another invocation
	invW = "6f1c2e8a-0000-4000-8000-0000000000c3" // an earlier, cleared one
)

// adminDir is a folder laid out as config\admin is on Linux: 0550, with
// clear-suspension.json at 0440 when body is set.
type adminDir struct {
	t   *testing.T
	dir string
}

func newAdminDir(t *testing.T) *adminDir {
	t.Helper()
	d := &adminDir{t: t, dir: filepath.Join(t.TempDir(), "admin")}
	if err := os.Mkdir(d.dir, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(d.dir, 0o700) })
	return d
}

func (d *adminDir) path() string { return filepath.Join(d.dir, collector.ClearSuspensionFileName) }

// put writes the file as an administrator would, then restores the modes.
func (d *adminDir) put(body string, mode os.FileMode) {
	d.t.Helper()
	os.Chmod(d.dir, 0o700)
	defer os.Chmod(d.dir, 0o550)
	os.Remove(d.path())
	if err := os.WriteFile(d.path(), []byte(body), 0o600); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Chmod(d.path(), mode); err != nil {
		d.t.Fatal(err)
	}
}

func (d *adminDir) remove() {
	os.Chmod(d.dir, 0o700)
	os.Remove(d.path())
	os.Chmod(d.dir, 0o550)
}

// reader is the binary's wiring (cmd/otsec-collector clearFileReader):
// the folder check, then the file read, every time.
func (d *adminDir) reader() func() ([]byte, error) {
	readers := []string{"S-1-5-80-1"}
	return func() ([]byte, error) {
		if err := protect.CheckDirFor(d.dir, readers); err != nil {
			return nil, err
		}
		return protect.ReadFileFor(d.path(), collector.MaxClearSuspensionBytes, readers)
	}
}

func clearFileBody(assetID, ref string) string {
	return `{"schema":"` + collector.ClearSuspensionSchema + `","asset_id":"` + assetID + `","ref":"` + ref + `"}`
}

func clearRequest(r rig, assetID, ref string) *authz.CollectorRequest {
	return &authz.CollectorRequest{
		Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: "a6-clear",
		OnBehalfOf:     authz.Principal{Type: authz.PrincipalNode, ID: r.nodeID},
		PolicyVersion:  3,
		AssetClearSusp: &authz.AssetClearSuspBody{AssetID: assetID, Ref: ref},
	}
}

// clearRig is a pipeline with the admin folder wired and lockAsset
// suspended by invX.
func clearRig(t *testing.T) (rig, *adminDir, *dialRunner) {
	t.Helper()
	l := listen(t, "127.0.0.1")
	d := newAdminDir(t)
	runner := &dialRunner{}
	r, err := newRig(t, "127.0.0.1", l.port(), runner, func(c *collector.PipelineConfig) { c.ReadClearFile = d.reader() })
	if err != nil {
		t.Fatal(err)
	}
	if err := r.state.SuspendAsset(lockAsset, adapter.RefusedIdentityMismatch, invX); err != nil {
		t.Fatal(err)
	}
	return r, d, runner
}

// heldX is the suspension clearRig sets (C7 0.3 names it in refusals).
var heldX = authz.HeldSuspension{Reason: asset.SuspendIdentityMismatch, Ref: invX, Code: string(adapter.RefusedIdentityMismatch)}

// stillSuspended checks the asset is suspended by clearRig's invX in
// memory, on disk, and to a run request, which must not reach the runner.
func stillSuspended(t *testing.T, r rig, runner *dialRunner) {
	t.Helper()
	stillSuspendedBy(t, r, runner, heldX)
}

// stillSuspendedBy is stillSuspended for the suspension held.
func stillSuspendedBy(t *testing.T, r rig, runner *dialRunner, held authz.HeldSuspension) {
	t.Helper()
	if err := r.state.CheckSuspended(lockAsset); err == nil {
		t.Error("the asset is no longer suspended in memory")
	}
	again, err := collector.OpenState(r.statePath, nil)
	if err != nil {
		t.Fatalf("reopen the state: %v", err)
	}
	if err := again.CheckSuspended(lockAsset); err == nil {
		t.Error("the asset is no longer suspended on disk")
	}
	reply, work := r.pipe.Handle(context.Background(), lockRun(lockAsset, r.rev))
	if work != nil {
		work.Run(context.Background())
	}
	if reply.Accepted() || len(runner.dials) != 0 {
		t.Errorf("a run to the suspended asset was accepted (%+v) or dialled %v", reply.Refusal, runner.dials)
	} else if r := reply.Refusal; r == nil || r.Code != authz.RefuseAssetSuspended || !strings.Contains(r.Detail, "is suspended") ||
		r.Suspension == nil || *r.Suspension != held {
		// C7 0.3: the collector refuses asset_suspended and names the
		// suspension it holds, with its C2 code. Any other refusal is the
		// rig, not the suspension.
		t.Errorf("the run was refused for another reason: %+v", reply.Refusal)
	}
}

// refusedWith sends req and checks it is refused with code and numbered.
func refusedWith(t *testing.T, r rig, req *authz.CollectorRequest, code authz.RefusalCode) authz.CollectorReply {
	t.Helper()
	reply, work := r.pipe.Handle(context.Background(), req)
	if work != nil {
		t.Fatal("an asset clear returned work")
	}
	if reply.Accepted() || reply.Refusal == nil || reply.Refusal.Code != code {
		t.Fatalf("reply %+v, want refused %s", reply, code)
	}
	if reply.CollectorSeq == 0 {
		t.Error("the refusal has no collector_seq, so the node cannot account for it")
	}
	return reply
}

func TestAssetClearControl(t *testing.T) {
	r, d, runner := clearRig(t)
	d.put(clearFileBody(lockAsset, invX), 0o440)
	reply, _ := r.pipe.Handle(context.Background(), clearRequest(r, lockAsset, invX))
	if !reply.Accepted() {
		t.Fatalf("a matching clear was refused: %+v", reply.Refusal)
	}
	again, err := collector.OpenState(r.statePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.CheckSuspended(lockAsset); err != nil {
		t.Fatalf("not cleared on disk: %v", err)
	}
	if err := r.state.CheckSuspended(lockAsset); err != nil {
		t.Fatalf("not cleared in memory: %v", err)
	}
	// The run the denials keep refused now reaches the runner (A3 on #118).
	reply, work := r.pipe.Handle(context.Background(), lockRun(lockAsset, r.rev))
	if !reply.Accepted() || work == nil {
		t.Fatalf("a run after the clear was refused: %+v", reply.Refusal)
	}
	work.Run(context.Background())
	if len(runner.dials) != 1 {
		t.Fatalf("the runner dialled %v after the clear, want one dial", runner.dials)
	}
}

// A planted file with no request lifts nothing: the asset stays suspended
// and runs are still refused.
func TestAssetClearPlantedFileNoRequest(t *testing.T) {
	r, d, runner := clearRig(t)
	d.put(clearFileBody(lockAsset, invX), 0o440)
	stillSuspended(t, r, runner)
}

func TestAssetClearDeniedA6(t *testing.T) {
	cases := []struct {
		name string
		// file is the clear-suspension.json body; "" means no file.
		file string
		mode os.FileMode
		// setup changes the folder or the state before the request.
		setup    func(t *testing.T, r rig, d *adminDir)
		asset    string
		ref      string
		wantCode authz.RefusalCode
	}{
		{name: "a request with no file", ref: invX},
		{name: "a stale file for an earlier suspension, request for the current one", file: clearFileBody(lockAsset, invW), ref: invX},
		{name: "a stale file and a request for the earlier suspension", file: clearFileBody(lockAsset, invW), ref: invW},
		{name: "file and request name another invocation", file: clearFileBody(lockAsset, invY), ref: invY},
		{name: "file names the current invocation, request another", file: clearFileBody(lockAsset, invX), ref: invY},
		{name: "file names another invocation, request the current", file: clearFileBody(lockAsset, invY), ref: invX},
		{name: "file names another asset", file: clearFileBody("2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b14", invX), ref: invX},
		{name: "the ref in upper case", file: clearFileBody(lockAsset, strings.ToUpper(invX)), ref: invX},
		{name: "another schema", file: strings.Replace(clearFileBody(lockAsset, invX), "/0.1", "/0.2", 1), ref: invX},
		{name: "an extra field", file: strings.TrimSuffix(clearFileBody(lockAsset, invX), "}") + `,"by":"admin"}`, ref: invX},
		{name: "a duplicate ref", file: strings.TrimSuffix(clearFileBody(lockAsset, invY), "}") + `,"ref":"` + invX + `"}`, ref: invX},
		{name: "trailing data", file: clearFileBody(lockAsset, invX) + `{}`, ref: invX},
		{name: "a field in another case", file: strings.Replace(clearFileBody(lockAsset, invX), `"ref"`, `"REF"`, 1), ref: invX},
		{name: "an empty file", file: " ", ref: invX},
		{name: "a file over the bound", file: clearFileBody(lockAsset, invX) + strings.Repeat(" ", collector.MaxClearSuspensionBytes), ref: invX},
		// Refused folder or file: the collector or the node could write it.
		{name: "a writable file", file: clearFileBody(lockAsset, invX), mode: 0o640, ref: invX},
		{name: "a file others can read", file: clearFileBody(lockAsset, invX), mode: 0o444, ref: invX},
		{name: "a writable folder", file: clearFileBody(lockAsset, invX), ref: invX,
			setup: func(t *testing.T, r rig, d *adminDir) { os.Chmod(d.dir, 0o750) }},
		{name: "a folder others can enter", file: clearFileBody(lockAsset, invX), ref: invX,
			setup: func(t *testing.T, r rig, d *adminDir) { os.Chmod(d.dir, 0o551) }},
		{name: "the file is a link to a good file elsewhere", ref: invX,
			setup: func(t *testing.T, r rig, d *adminDir) {
				other := filepath.Join(t.TempDir(), "good.json")
				os.WriteFile(other, []byte(clearFileBody(lockAsset, invX)), 0o440)
				os.Chmod(d.dir, 0o700)
				os.Symlink(other, d.path())
				os.Chmod(d.dir, 0o550)
			}},
		{name: "the file has a second hard link", file: clearFileBody(lockAsset, invX), ref: invX,
			setup: func(t *testing.T, r rig, d *adminDir) {
				os.Chmod(d.dir, 0o700)
				os.Link(d.path(), filepath.Join(d.dir, "other.json"))
				os.Chmod(d.dir, 0o550)
			}},
		{name: "the folder is a link", file: clearFileBody(lockAsset, invX), ref: invX,
			setup: func(t *testing.T, r rig, d *adminDir) {
				os.Chmod(d.dir, 0o700)
				real := d.dir + ".real"
				os.Rename(d.dir, real)
				os.Symlink(real, d.dir)
				os.Chmod(real, 0o550)
				t.Cleanup(func() { os.Chmod(real, 0o700) })
			}},
		// Not enrolled: refused before the file, as its own code.
		{name: "an asset not enrolled", file: clearFileBody("2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b14", invX),
			asset: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b14", ref: invX, wantCode: authz.RefuseAssetNotEnrolled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, d, runner := clearRig(t)
			if c.file != "" {
				mode := c.mode
				if mode == 0 {
					mode = 0o440
				}
				d.put(c.file, mode)
			}
			if c.setup != nil {
				c.setup(t, r, d)
			}
			id := c.asset
			if id == "" {
				id = lockAsset
			}
			code := c.wantCode
			if code == "" {
				code = authz.RefuseSuspensionMismatch
			}
			reply := refusedWith(t, r, clearRequest(r, id, c.ref), code)
			if strings.Contains(reply.Refusal.Detail, `"schema"`) {
				t.Errorf("the refusal detail carries the file's content: %q", reply.Refusal.Detail)
			}
			stillSuspended(t, r, runner)
		})
	}
}

// Who may ask, and under which contract minor: refused before the file is
// read, with the asset still suspended.
func TestAssetClearPrincipalsA6(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*authz.CollectorRequest)
		code authz.RefusalCode
	}{
		{"a person", func(q *authz.CollectorRequest) {
			q.OnBehalfOf = authz.Principal{Type: authz.PrincipalHuman, ID: "admin-a"}
		}, authz.RefusePrincipal},
		{"a platform service", func(q *authz.CollectorRequest) {
			q.OnBehalfOf = authz.Principal{Type: authz.PrincipalSystem, ID: "otsec-node"}
		}, authz.RefusePrincipal},
		{"a schedule", func(q *authz.CollectorRequest) {
			q.OnBehalfOf = authz.Principal{Type: authz.PrincipalSchedule, ID: "sch-a6"}
		}, authz.RefusePrincipal},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, d, runner := clearRig(t)
			d.put(clearFileBody(lockAsset, invX), 0o440)
			q := clearRequest(r, lockAsset, invX)
			c.mod(q)
			if err := q.Validate(); err == nil {
				t.Error("C7 Validate accepted it")
			}
			refusedWith(t, r, q, c.code)
			stillSuspended(t, r, runner)
		})
	}
	// Stamped 0.1, the kind does not exist: C7 Validate refuses it, which
	// is what the collector's decoder applies before Handle.
	r, _, _ := clearRig(t)
	q := clearRequest(r, lockAsset, invX)
	q.Contract = "otsec.authz/0.1"
	if err := q.Validate(); err == nil {
		t.Error("an asset clear stamped otsec.authz/0.1 validated")
	}
}

// A matching clear of an asset that is not suspended is accepted and
// changes nothing; the same file and request then do not lift a later
// suspension by another invocation.
func TestAssetClearRetryThenLaterSuspension(t *testing.T) {
	r, d, runner := clearRig(t)
	d.put(clearFileBody(lockAsset, invX), 0o440)
	for i := 0; i < 2; i++ {
		if reply, _ := r.pipe.Handle(context.Background(), clearRequest(r, lockAsset, invX)); !reply.Accepted() {
			t.Fatalf("clear %d refused: %+v", i, reply.Refusal)
		}
	}
	if err := r.state.SuspendAsset(lockAsset, adapter.FailedAuthRejected, invY); err != nil {
		t.Fatal(err)
	}
	reply := refusedWith(t, r, clearRequest(r, lockAsset, invX), authz.RefuseSuspensionMismatch)
	later := authz.HeldSuspension{Reason: asset.SuspendAuthFailed, Ref: invY, Code: string(adapter.FailedAuthRejected)}
	if reply.Refusal.Suspension == nil || *reply.Refusal.Suspension != later {
		t.Errorf("the mismatch names %+v, want the later suspension %+v", reply.Refusal.Suspension, later)
	}
	stillSuspendedBy(t, r, runner, later)
}
