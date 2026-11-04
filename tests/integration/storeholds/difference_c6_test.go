package storeholds

// D4-42's last case, at the store's boundary: a large difference that is
// still within C9's MaxDifferenceBytes must be stored as a difference. The
// node's configuration records go through its ConfigDocuments under its own
// record cap, ConfigRecordBytes, so a difference at exactly the bound must
// pass both and read back byte for byte, and one byte more
// must be refused before anything is stored (the node then records the
// change with difference_too_large instead). Ground truth: D4-42's text and
// C9's constant, not the node's writer. Evidence class: simulated.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	nodepkg "otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/store"
)

// differenceOf is C9's golden difference with its first change's new value
// padded so that it encodes to exactly n bytes.
func differenceOf(t *testing.T, n int) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "config", "testdata", "valid", "difference-1-3.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := config.DecodeDifference(b)
	if err != nil {
		t.Fatal(err)
	}
	base := *d.Changes[0].To
	encode := func(pad int) []byte {
		v := base + strings.Repeat("A", pad)
		d.Changes[0].To = &v
		out, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := encode(n - len(encode(0)))
	if len(out) != n {
		t.Fatalf("built %d bytes, want %d", len(out), n)
	}
	return out
}

func TestC6DifferenceAtTheBoundIsStored(t *testing.T) {
	if config.MaxDifferenceBytes >= nodepkg.ConfigRecordBytes {
		t.Fatalf("MaxDifferenceBytes %d is not under the node's record cap %d", config.MaxDifferenceBytes, nodepkg.ConfigRecordBytes)
	}
	d := database(nodepkg.ConfigRecordBytes)
	env, err := store.NewEnv(store.Options{Dir: newDir(t), Node: node, Database: d, Documents: nodepkg.ConfigDocuments})
	if err != nil {
		t.Fatal(err)
	}
	ctx0, cancel0 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel0()
	r := c5.RunStartup(ctx0, env, c5.StartupPolicy{
		Streams:                d.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
	})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup %s: %v %v", r.Mode, r.Err, r.Steps)
	}
	db, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatal("not the SQLite store")
	}
	t.Cleanup(func() {
		db.Close()
		if r.Unlock != nil {
			r.Unlock()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
	if err != nil {
		t.Fatal(err)
	}

	// One byte over: refused, and nothing is stored.
	over := differenceOf(t, config.MaxDifferenceBytes+1)
	if _, err := l.AppendBatch(ctx, []c5.Record{{Stream: cfg, Class: c5.ClassConfiguration, Event: over}}); err == nil {
		t.Fatal("a difference one byte over MaxDifferenceBytes was stored")
	}
	if got, err := db.Read(ctx, cfg, 0, 10); err != nil || len(got) != 0 {
		t.Fatalf("after the refusal: %d records stored, %v", len(got), err)
	}

	// At the bound: stored as a difference and read back as written.
	at := differenceOf(t, config.MaxDifferenceBytes)
	if _, err := l.AppendBatch(ctx, []c5.Record{{Stream: cfg, Class: c5.ClassConfiguration, Event: at}}); err != nil {
		t.Fatalf("a difference of exactly MaxDifferenceBytes was refused: %v", err)
	}
	got, err := db.Read(ctx, cfg, 0, 10)
	if err != nil || len(got) != 1 || string(got[0].Event) != string(at) {
		t.Fatalf("read back %d records, %v", len(got), err)
	}
	if _, err := config.DecodeDifference(got[0].Event); err != nil {
		t.Fatalf("the stored difference does not decode: %v", err)
	}
}
