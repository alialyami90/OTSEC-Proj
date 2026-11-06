//go:build !windows

package security

// P4-H1 on the collector (#508, D4-62), D6's acceptance cases. The ground
// truth is the brief (docs/agent-handoffs.md, P4-H1), not the code: for an
// asset with any endpoint that is not simulated in the collector's own
// configuration, the unsigned clear-suspension.json lifts nothing, whatever
// the node believes about itself, and only an administrator's signed
// asset.clear_suspension does; a signed clear that is replayed, expired,
// signed by a key nobody pinned, or names another invocation is refused and
// changes nothing; a lab-only asset keeps the file. Built on this package's
// clearRig (the binary's folder check and read, at the real modes) and
// admin_repeat_test.go's administrator key, a test key (D2-5). The
// configuration loader refuses device-observed in this phase (D2-4), so the
// target is set after loading, as #508's own tests do. Class: simulated.
// Linux only, as asset_clear_test.go.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collector"
)

// offLabRig is clearRig with rptKey pinned, an alarm log, a count of the
// administrators' file reads, and the asset's endpoints changed by label
// after loading. It returns the install key ID a signed request names.
type offLabRig struct {
	rig
	dir     *adminDir
	runner  *dialRunner
	reads   *int
	alarms  *[]error
	install string
}

func newOffLabRig(t *testing.T, label func(a *asset.Asset)) *offLabRig {
	t.Helper()
	l := listen(t, "127.0.0.1")
	d := newAdminDir(t)
	o := &offLabRig{dir: d, runner: &dialRunner{}, reads: new(int), alarms: new([]error)}
	read := d.reader()
	r, err := newRig(t, "127.0.0.1", l.port(), o.runner, func(c *collector.PipelineConfig) {
		c.ReadClearFile = func() ([]byte, error) { *o.reads++; return read() }
		c.AdminKeys = []authz.AdminKey{rptKey(authz.KeyActive)}
		c.Alarm = func(err error) { *o.alarms = append(*o.alarms, err) }
		o.install = c.Creds.InstallKey().KeyID
		if label != nil {
			label(&c.Assets[0].Asset)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	o.rig = r
	if err := r.state.SuspendAsset(lockAsset, adapter.RefusedIdentityMismatch, invX); err != nil {
		t.Fatal(err)
	}
	return o
}

// firstOffLab and secondOffLab add a device-observed endpoint before or
// after the fixture's simulated one, so a check of one position alone is
// caught. (The fixture's simulator observations need their simulated
// endpoint, so it stays.)
func firstOffLab(a *asset.Asset) {
	a.Endpoints = append([]asset.Endpoint{deviceEndpoint(a)}, a.Endpoints...)
}

func secondOffLab(a *asset.Asset) {
	a.Endpoints = append(a.Endpoints, deviceEndpoint(a))
}

func deviceEndpoint(a *asset.Asset) asset.Endpoint {
	ep := a.Endpoints[0]
	ep.ID, ep.Target = ep.ID+"-device", asset.DeviceObserved
	return ep
}

// suspendedBy fails the test unless the asset is suspended by ref in memory
// and on disk. (A run to an asset with a device-observed endpoint is refused
// asset_not_enrolled first, by D2-4, so a run cannot show it here.)
func (o *offLabRig) suspendedBy(t *testing.T, ref string) {
	t.Helper()
	again, err := collector.OpenState(o.statePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for where, s := range map[string]*collector.State{"in memory": o.state, "on disk": again} {
		if err := s.CheckSuspended(lockAsset); err == nil || !strings.Contains(err.Error(), ref) {
			t.Fatalf("not suspended by %s %s: %v", ref, where, err)
		}
	}
}

// signedClear is the administrator's asset.clear_suspension of ref, issued
// at the rig's clock (newRig's 07:00) unless at is set.
func (o *offLabRig) signedClear(t *testing.T, ref string, at time.Time, priv ed25519.PrivateKey) *authz.CollectorRequest {
	t.Helper()
	if at.IsZero() {
		at = time.Date(2026, 10, 25, 7, 0, 0, 0, time.UTC)
	}
	p := authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: authz.KindAssetClearSusp, Principal: rptAdmin,
		AdminKeyID: rptKey(authz.KeyActive).KeyID, NodeID: o.nodeID, InstallKeyID: o.install,
		Nonce:    a6NewNonce(t),
		IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(10 * time.Minute).Format(time.RFC3339),
		AssetClearSusp: &authz.AssetClearSuspBody{AssetID: lockAsset, Ref: ref},
	}
	key := rptPriv
	if priv != nil {
		key, p.AdminKeyID = priv, authz.AdminKeyID(priv.Public().(ed25519.PublicKey))
	}
	env, err := authz.SignAdminRequest(key, p)
	if err != nil {
		t.Fatal(err)
	}
	return rptRequest(authz.KindAssetClearSusp, env, authz.ContractID, "d6-signed-clear")
}

func (o *offLabRig) handle(req *authz.CollectorRequest) authz.CollectorReply {
	reply, work := o.pipe.Handle(context.Background(), req)
	if work != nil {
		work.Run(context.Background())
	}
	return reply
}

// cleared fails the test unless the asset is clear in memory and on disk,
// and, on a lab-only asset, a run reaches the runner.
func (o *offLabRig) cleared(t *testing.T, lab bool) {
	t.Helper()
	again, err := collector.OpenState(o.statePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.CheckSuspended(lockAsset); err != nil {
		t.Fatalf("not cleared on disk: %v", err)
	}
	if err := o.state.CheckSuspended(lockAsset); err != nil {
		t.Fatalf("not cleared in memory: %v", err)
	}
	if !lab {
		return
	}
	if reply := o.handle(lockRun(lockAsset, o.rev)); !reply.Accepted() || len(o.runner.dials) != 1 {
		t.Fatalf("a run after the clear: %+v, dials %v", reply.Refusal, o.runner.dials)
	}
}

// The control: on the lab-only asset the node's clear in the clear, with
// the administrator's file, still lifts the suspension, so a refusal below
// is the off-lab rule and not the rig.
func TestP4H1LabOnlyFileStillClears(t *testing.T) {
	o := newOffLabRig(t, nil)
	o.dir.put(clearFileBody(lockAsset, invX), 0o440)
	if reply := o.handle(clearRequest(o.rig, lockAsset, invX)); !reply.Accepted() {
		t.Fatalf("the lab-only file clear was refused: %+v", reply.Refusal)
	}
	if *o.reads != 1 {
		t.Fatalf("the file was read %d times, want once", *o.reads)
	}
	o.cleared(t, true)
}

// Off-lab, the node's clear in the clear is refused before the file is
// read, as a C7 refusal the node accepts, whatever contract the node stamps
// and whatever the node believes about itself: the request bytes are the
// same from a node that thinks it is lab-only (the divergence case). The
// asset stays suspended in memory, on disk and to a run, and each refusal
// raises one alarm naming the asset.
func TestP4H1OffLabFileClearsNothing(t *testing.T) {
	for name, label := range map[string]func(*asset.Asset){"first endpoint": firstOffLab, "second endpoint": secondOffLab} {
		t.Run(name, func(t *testing.T) {
			o := newOffLabRig(t, label)
			o.dir.put(clearFileBody(lockAsset, invX), 0o440)
			for i, stamp := range []string{authz.ContractID, "otsec.authz/0.3"} {
				req := clearRequest(o.rig, lockAsset, invX)
				req.Contract = stamp
				want := authz.RefuseAdminUnverified
				if stamp == "otsec.authz/0.3" {
					want = authz.RefusePrincipal // admin_unverified is 0.4's
				}
				reply := refusedWith(t, o.rig, req, want)
				if err := reply.Validate(); err != nil {
					t.Fatalf("%s: a reply the node refuses: %v", stamp, err)
				}
				if stamp == authz.ContractID && reply.Refusal.Check != authz.AdminCheckEnvelope {
					t.Fatalf("%s: refusal %+v, want admin check envelope", stamp, reply.Refusal)
				}
				if len(*o.alarms) != i+1 || !strings.Contains((*o.alarms)[i].Error(), lockAsset) {
					t.Fatalf("%s: alarms %v, want one more naming the asset", stamp, *o.alarms)
				}
			}
			if *o.reads != 0 {
				t.Fatalf("the administrators' file was read %d times off-lab", *o.reads)
			}
			o.suspendedBy(t, invX)
		})
	}
}

// Off-lab, the administrator's signed clear is the way out, and it gets
// every admin check. Another invocation is refused and spends its nonce
// (sent again: replay); a signature by a key nobody pinned, under the pinned
// key's ID, is refused, and so is that key under its own ID; an expired
// request is refused. Each leaves the asset suspended.
// Then the right one lifts it with no file read, and its replay after a
// later suspension lifts nothing.
func TestP4H1OffLabSignedClear(t *testing.T) {
	o := newOffLabRig(t, secondOffLab)
	o.dir.put(clearFileBody(lockAsset, invX), 0o440)
	check := func(name string, reply authz.CollectorReply, want authz.AdminCheck) {
		t.Helper()
		if reply.Accepted() || reply.Refusal == nil || reply.Refusal.Code != authz.RefuseAdminUnverified || reply.Refusal.Check != want {
			t.Fatalf("%s: %+v, want admin_unverified %s", name, reply.Refusal, want)
		}
		o.suspendedBy(t, invX)
	}

	other := o.signedClear(t, invY, time.Time{}, nil)
	if reply := o.handle(other); reply.Accepted() || reply.Refusal == nil || reply.Refusal.Code != authz.RefuseSuspensionMismatch {
		t.Fatalf("another invocation: %+v", reply.Refusal)
	}
	o.suspendedBy(t, invX)
	check("another invocation, sent again", o.handle(other), authz.AdminCheckReplay)

	forged := o.signedClear(t, invX, time.Time{}, nil)
	forged.AdminSigned.Signature = ed25519.Sign(otherAdminKey(), authz.AdminSigningInput(authz.KindAssetClearSusp, forged.AdminSigned.Payload))
	check("signed by a key nobody pinned, under the pinned key's ID", o.handle(forged), authz.AdminCheckSignature)
	unpinned := o.signedClear(t, invX, time.Time{}, otherAdminKey())
	check("a key nobody pinned", o.handle(unpinned), authz.AdminCheckKey)

	expired := o.signedClear(t, invX, time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC), nil)
	check("expired", o.handle(expired), authz.AdminCheckWindow)

	ok := o.signedClear(t, invX, time.Time{}, nil)
	if reply := o.handle(ok); !reply.Accepted() || reply.Admin == nil || reply.Admin.Principal != rptAdmin {
		t.Fatalf("the signed clear: %+v %+v", reply.Refusal, reply.Admin)
	}
	if *o.reads != 0 {
		t.Fatalf("the administrators' file was read %d times", *o.reads)
	}
	o.cleared(t, false)

	if err := o.state.SuspendAsset(lockAsset, adapter.RefusedIdentityMismatch, invY); err != nil {
		t.Fatal(err)
	}
	// The same bytes again while their nonce is held get C7 0.5's repeat
	// answer, which names the first decision and acts on nothing.
	if reply := o.handle(ok); reply.Accepted() && reply.RepeatOf == 0 || !reply.Accepted() && (reply.Refusal == nil || reply.Refusal.Check != authz.AdminCheckReplay) {
		t.Fatalf("the accepted clear sent again after a later suspension: %+v, want a repeat or a replay refusal", reply)
	}
	o.suspendedBy(t, invY)
}

// otherAdminKey is a test key no collector pins (D2-5).
func otherAdminKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("otsec d6 p4h1 unpinned admin key"))
	return ed25519.NewKeyFromSeed(seed[:])
}
