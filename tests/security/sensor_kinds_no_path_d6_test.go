package security

// C7 0.11's two sensor kinds have no product path yet (brief P4-4-CC,
// deliverable 5; D4-103 ruling 2.3): no node relays node.sensor_enrol or
// node.sensor_revoke, and a verified request of either kind that reaches
// the collector's pipeline is refused. Both legs run against the collector's
// own Server and Pipeline on a 127.0.0.1 listener, reached through the
// node's own collector client; the node leg runs the node's scheduler over
// an admin_dir that holds a signed request file of each kind. Ground truth
// is the brief's text, not the code. Every key is a test key (D2-5), and no
// address but loopback is dialled. Evidence class: simulated.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

const d6KindsSensor = "5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70"

var d6SensorKinds = []authz.RequestKind{authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke}

func d6KindsPin(s string) string {
	sum := sha256.Sum256([]byte("d6 sensor kinds " + s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// d6SeenHandler is the collector's pipeline, with a record of the kind of
// every request that reached it and of how long the pipeline took to
// decide it (P4-D6-EOF1).
type d6SeenHandler struct {
	collector.Handler
	mu    sync.Mutex
	kinds []authz.RequestKind
	took  []string
}

func (h *d6SeenHandler) Handle(ctx context.Context, req *authz.CollectorRequest) (authz.CollectorReply, collector.Work) {
	h.mu.Lock()
	h.kinds = append(h.kinds, req.Kind)
	h.mu.Unlock()
	start := time.Now()
	reply, work := h.Handler.Handle(ctx, req)
	h.mu.Lock()
	h.took = append(h.took, fmt.Sprintf("%s in %s", req.Kind, time.Since(start).Round(time.Millisecond)))
	h.mu.Unlock()
	return reply, work
}

func (h *d6SeenHandler) seen(k authz.RequestKind) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Contains(h.kinds, k)
}

// decided lists each request the pipeline has decided, with the time it took.
func (h *d6SeenHandler) decided() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.took, ", ")
}

// d6TestLog writes the collector server's log to the test's own log, where
// the server says why it closed a connection without a reply (P4-D6-EOF1).
type d6TestLog struct{ t *testing.T }

func (l d6TestLog) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// d6KindsCollector is the repeat rig's collector, its administrator key
// allowed both sensor kinds and node.network_baseline_ack, served on a
// 127.0.0.1 listener, and the node's client for it.
func d6KindsCollector(t *testing.T) (*rptRig, *d6SeenHandler, *collectorclient.Client) {
	t.Helper()
	r := newRptRig(t)
	key := rptKey(authz.KeyActive)
	key.Kinds = append(slices.Clone(d6SensorKinds), authz.KindNodeNetworkBaselineAck)
	r.restart(t, key)
	h := &d6SeenHandler{Handler: r.pipe}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &collector.Server{Handler: h, Log: slog.New(slog.NewTextHandler(d6TestLog{t}, nil))}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()
	return r, h, collectorclient.NewWithDialer(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	})
}

// d6KindsPayload is what the administrator signs for kind: a valid body,
// bound to the rig's node and install key, ten minutes to live.
func d6KindsPayload(t *testing.T, r *rptRig, kind authz.RequestKind) authz.AdminRequest {
	t.Helper()
	now := r.clock.now()
	p := authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: kind, Principal: rptAdmin,
		AdminKeyID: rptKey(authz.KeyActive).KeyID, NodeID: string(r.asset.Asset.NodeID), InstallKeyID: r.creds.InstallKey().KeyID,
		Nonce: a6NewNonce(t), IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),
	}
	switch kind {
	case authz.KindNodeSensorEnrol:
		p.NodeSensorEnrol = &authz.NodeSensorEnrolBody{SensorID: d6KindsSensor, Generation: "1", SensorSPKI: d6KindsPin("sensor key"),
			SensorAddress: "192.0.2.10:8443", NodeSPKI: d6KindsPin("node link key"), NodeAddress: "192.0.2.1",
			NotAfter: "2027-10-26T00:00:00Z", Reason: authz.SensorEnrolNew}
	case authz.KindNodeSensorRevoke:
		p.NodeSensorRevoke = &authz.NodeSensorRevokeBody{SensorID: d6KindsSensor, Generation: "1",
			SensorSPKI: d6KindsPin("sensor key"), Reason: authz.SensorRevokeCompromised}
	case authz.KindNodeNetworkBaselineAck:
		p.NodeNetworkBaselineAck = &authz.NodeNetworkBaselineAckBody{SensorID: d6KindsSensor,
			DraftDigest: d6KindsPin("draft"), BaselineDigest: d6KindsPin("baseline")}
	default:
		return r.payload(t, kind)
	}
	return p
}

func d6KindsSigned(t *testing.T, r *rptRig, kind authz.RequestKind) *authz.AdminSigned {
	t.Helper()
	env, err := authz.SignAdminRequest(rptPriv, d6KindsPayload(t, r, kind))
	if err != nil {
		t.Fatalf("sign %s: %v", kind, err)
	}
	return env
}

// A verified request of each sensor kind that reaches the collector's
// pipeline is refused: numbered, with no administrator check failed, so
// the refusal is the pipeline's and not the signature's or the key's.
// Control: node.network_baseline_ack, signed by the same key and sent the
// same way, is accepted.
func TestD6SensorKindsRefusedByCollector(t *testing.T) {
	r, h, client := d6KindsCollector(t)
	ctx := context.Background()
	send := func(kind authz.RequestKind) authz.CollectorReply {
		t.Helper()
		resp, err := client.Do(ctx, rptRequest(kind, d6KindsSigned(t, r, kind), authz.ContractID, "d6-kinds-"+string(kind)))
		t.Logf("decided so far: %s", h.decided())
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		return resp.Reply
	}
	if reply := send(authz.KindNodeNetworkBaselineAck); !reply.Accepted() {
		t.Fatalf("control: node.network_baseline_ack: %+v", reply.Refusal)
	}
	for _, kind := range d6SensorKinds {
		reply := send(kind)
		if !h.seen(kind) {
			t.Errorf("%s did not reach the pipeline", kind)
		}
		if reply.Accepted() || reply.Refusal == nil || reply.Refusal.Check != "" || reply.CollectorSeq == 0 || reply.Admin != nil {
			t.Errorf("%s: %+v (refusal %+v), want refused by the pipeline after verification", kind, reply, reply.Refusal)
		}
	}
}

// No node relays a request file of either sensor kind: the collector never
// sees one, and the node's status shows each file as not relayed. Control:
// a file of a relayed kind (credential.revoke), signed by the same key in
// the same admin_dir, reaches the collector in the same relay.
func TestD6SensorKindsNotRelayedByNode(t *testing.T) {
	const asset = "6f1c2e8a-4b3d-4c5e-9f70-0a1b2c3d4e5f"
	r, h, client := d6KindsCollector(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", dir).AddSEL751(asset, "", 2323, 300)
	nc.AdminDir = nc.TLSDir
	if err := nc.WriteInstallKey("ik_d6_kinds"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateDir(nc.AdminDir, ""); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	files := map[string]authz.RequestKind{
		"admin-request-d6-enrol.json":   authz.KindNodeSensorEnrol,
		"admin-request-d6-revoke.json":  authz.KindNodeSensorRevoke,
		"admin-request-d6-control.json": authz.KindCredentialRevoke,
	}
	for name, kind := range files {
		b, err := json.Marshal(map[string]any{"schema": node.AdminRequestFileSchema, "kind": kind, "signed": d6KindsSigned(t, r, kind)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nc.AdminDir, name), b, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := nc.LockTLS(); errors.Is(err, nodeconfigtest.ErrNeedsElevation) {
		if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("OTSEC_REQUIRE_ELEVATED") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.UnlockTLS() })
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	st := node.NewStatus("", nil, time.Now)
	rt, err := node.Start(ctx, c, node.RuntimeOptions{Status: st})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	s, err := node.NewScheduler(ctx, rt, client)
	if err != nil {
		t.Fatal(err)
	}
	// Run relays admin_dir before anything else, then waits
	// RelayEverySeconds; the first relay is read from status, then Run ends.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	byFile := map[string]node.AdminRequestStatus{}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		clear(byFile)
		for _, a := range st.Snapshot("site-a-node1").AdminRequests {
			byFile[a.File] = a
		}
		if a := byFile["admin-request-d6-control.json"]; a.State == "accepted" || a.State == "refused" {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("control: the relayed file was not decided within 30 s: %+v", byFile)
		}
	}
	cancel()
	<-done

	if !h.seen(authz.KindCredentialRevoke) {
		t.Errorf("control: credential.revoke did not reach the collector")
	}
	for name, kind := range files {
		if kind == authz.KindCredentialRevoke {
			continue
		}
		if h.seen(kind) {
			t.Errorf("%s: the node relayed %s to the collector", name, kind)
		}
		if a := byFile[name]; a.State != "unread" || !strings.Contains(a.Detail, "is not relayed by this node") {
			t.Errorf("%s: status %+v, want unread as not relayed", name, a)
		}
	}
}
