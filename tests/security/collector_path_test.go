package security

import (
	"context"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collector"
)

// C1 0.2 path rule in the collector (A3, #160; D2-16): only a direct path
// gets a session. Ground truth is the rule text in contracts/asset and
// D2-16, and a real listener: a refused run must not reach it. The
// adapter's own check (A2) is not on main, so here the collector is the
// only guard and the runner below dials whatever it is given.

func pathRig(t *testing.T, path asset.Path) (rig, *counter, *dialRunner, error) {
	t.Helper()
	l := listen(t, "127.0.0.1")
	runner := &dialRunner{}
	r, err := newRig(t, "127.0.0.1", l.port(), runner, func(c *collector.PipelineConfig) {
		c.Assets[0].Asset.Endpoints[0].Path = path
	})
	return r, l, runner, err
}

// runOnce sends one run and runs its work, bounded, if any was returned.
func runOnce(r rig) authz.CollectorReply {
	reply, work := r.pipe.Handle(context.Background(), lockRun(lockAsset, r.rev))
	if work != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		work.Run(ctx)
		cancel()
	}
	return reply
}

func TestC1PathDirectRuns(t *testing.T) {
	r, l, runner, err := pathRig(t, asset.Direct)
	if err != nil {
		t.Fatal(err)
	}
	if reply := runOnce(r); !reply.Accepted() {
		t.Fatalf("direct path refused: %+v", reply.Refusal)
	}
	deadline := time.Now().Add(5 * time.Second)
	for l.n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.n.Load() != 1 || len(runner.dials) != 1 {
		t.Fatalf("direct path: %d connections, dials %v", l.n.Load(), runner.dials)
	}
}

func TestC1PathNotDirectIsRefusedBeforeDial(t *testing.T) {
	for _, c := range []struct {
		name string
		path asset.Path
	}{
		{"port-server", asset.PortServer},
		{"no path (a 0.1 record)", ""},
		{"unknown path", "relay"},
		{"case variant", "Direct"},
		{"padded", " direct"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, l, runner, err := pathRig(t, c.path)
			if err != nil {
				// Refused while loading is also before any dial.
				t.Logf("refused at NewPipeline: %v", err)
				return
			}
			// Three runs: each is refused the same way, so the refusal is
			// not counted toward a suspension or a rate floor.
			for i := 0; i < 3; i++ {
				reply := runOnce(r)
				if reply.Accepted() {
					t.Fatalf("run %d accepted on path %q", i, c.path)
				}
				if reply.Refusal == nil || reply.Refusal.Code != authz.RefuseAssetNotEnrolled ||
					!strings.Contains(reply.Refusal.Detail, "D2-16") {
					t.Fatalf("run %d refused for another reason: %+v", i, reply.Refusal)
				}
			}
			time.Sleep(200 * time.Millisecond)
			if l.n.Load() != 0 || len(runner.dials) != 0 {
				t.Errorf("path %q: %d connections, dials %v", c.path, l.n.Load(), runner.dials)
			}
		})
	}
}
