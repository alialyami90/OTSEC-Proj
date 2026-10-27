package node

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

func TestZZRelayStartDiag(t *testing.T) {
	ms, _ := strconv.Atoi(os.Getenv("DIAG_MS"))
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-run.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	ctx, cancel := context.WithTimeout(bg, time.Duration(ms)*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	err := s.Run(ctx)
	t.Logf("Run returned %v after %v; sent %d runs %d", err, time.Since(t0), len(col.sent), col.runs)
	for _, a := range st.Snapshot("x").Alarms {
		t.Logf("alarm %s: %s", a.Code, a.Detail)
	}
}
