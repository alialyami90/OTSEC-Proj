package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorwire"
)

// D2-10 lock 2 of 2: the collector's own loopback check (A3, #97). A run
// request for an asset whose endpoint is not a loopback IP literal is
// refused before any dial. Every case has an active, verified register and
// a runner that dials, so a broken lock reaches the runner and the
// listener, instead of stopping at a later check. Ground truth is the rule
// text of D2-10, not the implementation. Class simulated.

const lockFixtures = "../../modules/security/collector/testdata"

// counter is a TCP listener that counts the connections it accepts.
type counter struct {
	ln net.Listener
	n  atomic.Int64
}

func listen(t *testing.T, ip string) *counter {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	c := &counter{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.n.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *counter) port() int { return c.ln.Addr().(*net.TCPAddr).Port }

// hostIP is a non-loopback IPv4 address of this host, so a lock that fails
// would really connect somewhere.
func hostIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	t.Fatal("this host has no non-loopback IPv4 address; the lock 2 test needs one")
	return ""
}

// dialRunner dials the plan's endpoint through the plan's dialer, as the
// SEL-751 runner does, and records each attempt.
type dialRunner struct {
	mu    sync.Mutex
	dials []string
}

func (r *dialRunner) Run(ctx context.Context, plan collector.RunPlan) collector.RunReport {
	addr := net.JoinHostPort(plan.Endpoint.Host, strconv.Itoa(plan.Endpoint.Port))
	r.mu.Lock()
	r.dials = append(r.dials, addr)
	r.mu.Unlock()
	if c, err := plan.Dial(ctx, "tcp", addr); err == nil {
		c.Close()
	}
	return collector.RunReport{Outcome: collectorwire.RunOutcome{Wire: collectorwire.WireID,
		InvocationID: plan.Invocation.InvocationID, Audit: []json.RawMessage{}}, QUISent: true}
}

func readLockFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(lockFixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lockPipeline is a collector pipeline with the SEL-751 register active and
// the asset's one endpoint at host:port.
func lockPipeline(t *testing.T, host string, port int, runner collector.Runner) (*collector.Pipeline, uint64, error) {
	t.Helper()
	dir := t.TempDir()
	now := func() time.Time { return time.Date(2026, 10, 25, 7, 0, 0, 0, time.UTC) }
	statePath := filepath.Join(dir, "state.json")
	if err := collector.InitState(statePath); err != nil {
		t.Fatal(err)
	}
	st, err := collector.OpenState(statePath, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(readLockFixture(t, "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	credPath := filepath.Join(dir, "credentials.json")
	if err := collector.InitCredStore(credPath, string(a.NodeID), now); err != nil {
		t.Fatal(err)
	}
	creds, err := collector.OpenCredStore(credPath, collector.CredStoreConfig{NodeID: string(a.NodeID), Now: now, Generations: st})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	regs := collector.NewRegisters(st, []authz.TrustAnchor{{KeyID: "a6-release", PublicKey: pub, Status: authz.KeyActive}})
	payload := readLockFixture(t, "register-sel-751.json")
	env, err := json.Marshal(register.Envelope{Contract: register.ContractID, Algorithm: "ed25519", KeyID: "a6-release",
		Payload: payload, Signature: ed25519.Sign(priv, authz.RegisterSigningInput(payload))})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := regs.Activate(env)
	if err != nil {
		t.Fatalf("activate the register: %v", err)
	}
	p, err := asset.DecodeProfile(readLockFixture(t, "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.Endpoints[0].Host, a.Endpoints[0].Port = host, port
	pipe, err := collector.NewPipeline(collector.PipelineConfig{
		NodeID: string(a.NodeID), PolicyVersion: 3,
		Assets: []collector.Enrolled{{Asset: a, Profile: p}},
		State:  st, Creds: creds, Registers: regs, Runner: runner, Now: now,
	})
	return pipe, uint64(pkg.Revision), err
}

func lockRun(assetID string, rev uint64) *authz.CollectorRequest {
	return &authz.CollectorRequest{
		Contract: authz.ContractID, Kind: authz.KindRun, RequestID: "a6-lock2",
		OnBehalfOf:    authz.Principal{Type: authz.PrincipalSchedule, ID: "sch-a6-lock2"},
		PolicyVersion: 3,
		Run:           &authz.RunBody{AssetID: assetID, OperationID: "sel.id", Params: map[string]string{}, RegisterVersion: rev},
	}
}

const lockAsset = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"

// The control: on loopback the run is accepted and the runner's dial
// reaches the listener, so a refusal below is the lock and not the rig.
func TestD210CollectorLoopbackRuns(t *testing.T) {
	l := listen(t, "127.0.0.1")
	r := &dialRunner{}
	pipe, rev, err := lockPipeline(t, "127.0.0.1", l.port(), r)
	if err != nil {
		t.Fatal(err)
	}
	reply, work := pipe.Handle(context.Background(), lockRun(lockAsset, rev))
	if !reply.Accepted() || work == nil {
		t.Fatalf("loopback run refused: %+v", reply.Refusal)
	}
	work.Run(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for l.n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.n.Load() != 1 {
		t.Fatalf("listener saw %d connections, want 1 (dials %v)", l.n.Load(), r.dials)
	}
}

func TestD210CollectorRefusesNonLoopback(t *testing.T) {
	ip := hostIP(t)
	l := listen(t, ip)
	unspec := listen(t, "0.0.0.0") // reached by "0.0.0.0" and "::" if they were dialled
	for _, host := range []string{
		ip,                 // this host's own address: a real connection if the lock fails
		"0.0.0.0",          // unspecified: Linux dials it as the local host
		"::",               // the same in IPv6
		"::ffff:127.0.0.1", // IPv4-mapped loopback (refused form)
		"localhost",        // a name, never resolved
		"127.0.0.1%lo",     // zoned
		"10.0.0.5", "192.168.1.10", "2001:db8::1",
	} {
		t.Run(host, func(t *testing.T) {
			r := &dialRunner{}
			port := l.port()
			if host == "0.0.0.0" || host == "::" {
				port = unspec.port()
			}
			pipe, rev, err := lockPipeline(t, host, port, r)
			if err != nil {
				// C1 refuses a name or a zoned literal while loading, which is
				// before any dial too. Any other load error means the rig, not
				// lock 2, stopped the case.
				if (host == "localhost" || host == "127.0.0.1%lo") &&
					strings.Contains(err.Error(), strconv.Quote(host)) && strings.Contains(err.Error(), "not an IP address") {
					t.Logf("refused at NewPipeline: %v", err)
				} else {
					t.Errorf("NewPipeline refused for another reason: %v", err)
				}
				return
			}
			if host == "localhost" || host == "127.0.0.1%lo" {
				t.Fatalf("NewPipeline loaded an asset whose host is %q", host)
			}
			reply, work := pipe.Handle(context.Background(), lockRun(lockAsset, rev))
			if work != nil {
				// A broken lock dials; bound it so the failure is quick.
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				work.Run(ctx)
				cancel()
			}
			if reply.Accepted() {
				t.Errorf("accepted a run to %s", host)
			} else if reply.Refusal == nil || reply.Refusal.Code != authz.RefuseAssetNotEnrolled || !strings.Contains(reply.Refusal.Detail, "D2-10") {
				t.Errorf("refused for another reason: %+v", reply.Refusal)
			}
			if len(r.dials) != 0 {
				t.Errorf("the runner dialled %v", r.dials)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	if n := l.n.Load() + unspec.n.Load(); n != 0 {
		t.Errorf("listeners saw %d connections, want 0", n)
	}
}
