package node

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// closer records a sensor link's closes for a decision.
type closer struct {
	mu      sync.Mutex
	reasons []string
}

func (c *closer) CloseConn(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reasons = append(c.reasons, reason)
}

func (c *closer) closed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.reasons...)
}

// M-10's fold legs (C13 0.2 section 15; docs/phase4/D5-sensor-node.md
// section 1.3; the no-dial legs are P4-4-DE's, D5-p44int-split.md section
// 3): a record in the sensor fold made unparseable while two sensor
// connections are open closes both as state-unread, at each fold while it
// stands, and sensor-state-unread stands with cause fold-record, raised
// once, the
// fold's cursor held before the record; once the record reads, the state
// is read and the cursor passes it. A read that fails stands with cause
// fold-read, closes nothing, and is retried. The live connections' close
// is sensorlink's TestStateUnreadClosesConnections. Every page is read
// under the 1 s deadline. Controls (named mutants run against this test,
// results in #747's comment): M7, the fold's close removed, under which
// neither closes; M-U, a page read with no deadline.
func TestStateUnreadFoldRecord(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	injectSensorChain(t, r)
	db := r.Store(AuditStream)
	refuse := audit.ActionSensorLinkRefused
	t.Cleanup(func() { parseAuditRecord = audit.ParseRecord })
	parseAuditRecord = func(b []byte) (*audit.Record, error) {
		rec, err := audit.ParseRecord(b)
		if err == nil && rec.Action == refuse {
			return nil, fmt.Errorf("%w: the test makes %s unparseable", audit.ErrRecordRejected, refuse)
		}
		return rec, err
	}
	var readErr error
	var undeadlined int
	deadline := func(ctx context.Context) {
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > sensorFoldDeadline {
			undeadlined++
		}
	}
	newFold := func(links ...sensorCloser) (*sensorFold, *[]string) {
		var raised []string
		return &sensorFold{
			read: func(ctx context.Context, after c5.Seq, max int) ([]c5.Stored, error) {
				deadline(ctx)
				if readErr != nil {
					return nil, readErr
				}
				return db.Read(ctx, AuditStream, after, max)
			},
			last: func(ctx context.Context) (c5.Seq, error) {
				deadline(ctx)
				return db.LastCommitted(ctx, AuditStream)
			},
			links: links,
			raise: func(alarm, detail string) { raised = append(raised, alarm+": "+detail) },
		}, &raised
	}
	a, b := &closer{}, &closer{}
	f, raised := newFold(a, b)
	f.fold(bg)
	f.fold(bg)
	// Each fold while it stands closes them again: no connection is kept.
	for _, c := range []*closer{a, b} {
		if got := c.closed(); len(got) != 2 || got[0] != netobs.CloseStateUnread || got[1] != netobs.CloseStateUnread {
			t.Fatalf("closes %v", got)
		}
	}
	if f.unread != StateUnreadFoldRecord || len(*raised) != 1 || !strings.HasPrefix((*raised)[0], alarmSensorStateUnread+": cause fold-record") {
		t.Fatalf("unread %q, raised %v", f.unread, *raised)
	}
	held := f.through
	last, err := db.LastCommitted(bg, AuditStream)
	if err != nil || held >= last {
		t.Fatalf("the cursor at %d of %d: %v", held, last, err)
	}
	parseAuditRecord = audit.ParseRecord // the record reads
	f.fold(bg)
	if f.unread != "" || f.through != last {
		t.Fatalf("after the record reads: unread %q, through %d of %d", f.unread, f.through, last)
	}

	readErr = errors.New("test: the audit database is busy")
	g, graised := newFold(a, b)
	g.fold(bg)
	if g.unread != StateUnreadFoldRead || len(a.closed()) != 2 || len(*graised) != 1 || !strings.Contains((*graised)[0], "cause fold-read") {
		t.Fatalf("read error: unread %q, closes %v, raised %v", g.unread, a.closed(), *graised)
	}
	readErr = nil
	g.fold(bg)
	if g.unread != "" || g.through != last {
		t.Fatalf("retried: unread %q, through %d", g.unread, g.through)
	}
	if undeadlined != 0 {
		t.Fatalf("%d reads without the fold's 1 s deadline", undeadlined)
	}
}
