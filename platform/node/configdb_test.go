package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// C9 and C10 fixtures are the contracts' own.
func contractFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// configRead is a C9 snapshot of a fixture read and the capture that is its
// transcript.
func configRead(t *testing.T, n string) (doc []byte, capture c5.Capture) {
	t.Helper()
	var tr adapter.Transcript
	if err := json.Unmarshal(contractFile(t, "config/testdata/transcripts/read-"+n+".json"), &tr); err != nil {
		t.Fatal(err)
	}
	return contractFile(t, "config/testdata/valid/snapshot-read-"+n+".json"), c5.Capture{SHA256: tr.SHA256, Bytes: tr.Data}
}

func configNode(t *testing.T, mod func(*nodeconfigtest.Config)) (*Config, string) {
	t.Helper()
	return schedConfig(t, func(nc *nodeconfigtest.Config) {
		nc.Store.Quotas["configuration"] = 16 << 20
		if mod != nil {
			mod(nc)
		}
	})
}

// The configuration database is opted into by its quota. With the quota it
// holds the class alone, with a stream for each asset and the record cap, and
// no forwarding target consumes it; without, the layout is the one a node
// had before C5 0.4.
func TestConfigDatabaseIsOptedIntoByItsQuota(t *testing.T) {
	with, _ := configNode(t, func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", true)
	})
	l, err := with.Layout()
	if err != nil {
		t.Fatal(err)
	}
	var d *c5.Database
	for i := range l.Databases {
		if l.Databases[i].ID == ConfigDB {
			d = &l.Databases[i]
		}
	}
	if d == nil {
		t.Fatalf("no configuration database in %+v", l.Databases)
	}
	if len(d.Streams) != 1 || d.Streams[0].ID != ConfigStream(relayID) || d.Streams[0].Class != c5.ClassConfiguration {
		t.Fatalf("streams %+v", d.Streams)
	}
	if len(d.Classes) != 1 || d.Classes[0] != c5.ClassConfiguration || len(d.Quotas) != 1 ||
		d.Quotas[0].MaxRecordBytes != ConfigRecordBytes || d.Quotas[0].Bytes != 16<<20 {
		t.Fatalf("classes %v quotas %+v", d.Classes, d.Quotas)
	}
	cs, err := with.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Stream == ConfigStream(relayID) {
			t.Fatalf("a target consumes the configuration stream: %+v", c)
		}
	}

	without, _ := schedConfig(t, nil)
	l, err = without.Layout()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l.Databases {
		if d.ID == ConfigDB {
			t.Fatalf("a node without the quota has %+v", d)
		}
	}
}

// A configuration quota below the record cap cannot hold one snapshot: the
// node does not load.
func TestConfigQuotaBelowTheRecordCap(t *testing.T) {
	for n, ok := range map[int64]bool{ConfigRecordBytes - 1: false, ConfigRecordBytes: true} {
		nc, _ := listenConfig(t, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["configuration"] = n })
		_, err := ParseConfig(nc.Bytes())
		if ok != (err == nil) || (!ok && !strings.Contains(err.Error(), "store.quotas.configuration")) {
			t.Errorf("quota %d: %v", n, err)
		}
	}
}

// The database starts with the recovery reserve of its largest commit, which
// is one record at the cap (C5 0.5), and stores C9 and C10 documents byte
// for byte under the node's document check.
func TestConfigDatabaseStoresDocuments(t *testing.T) {
	c, dir := configNode(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	d := r.find(ConfigDB)
	if d == nil || r.Mode(ConfigDB) != c5.ModeCollecting {
		t.Fatalf("configuration database %+v in mode %s", d, r.Mode(ConfigDB))
	}
	if d.policy.LargestCommitRecords != 1 || d.policy.LargestCommitBytes != ConfigRecordBytes ||
		d.policy.RecoveryReserveBytes != c5.RecoveryReserveFor(store.WALBoundBytes, ConfigRecordBytes, 1) {
		t.Fatalf("policy: commit %d bytes, %d records, reserve %d", d.policy.LargestCommitBytes, d.policy.LargestCommitRecords, d.policy.RecoveryReserveBytes)
	}
	_, log, _ := r.view(d)
	stream := ConfigStream(relayID)

	snap, capture := configRead(t, "1")
	if _, err := log.Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: snap, Capture: &capture}); err != nil {
		t.Fatal(err)
	}
	diff := contractFile(t, "config/testdata/valid/difference-1-2.json")
	if _, err := log.Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: diff}); err != nil {
		t.Fatal(err)
	}
	base := contractFile(t, "baseline/testdata/valid/baseline-synthetic.json")
	if _, err := log.Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: base}); err != nil {
		t.Fatal(err)
	}
	got, err := r.Store(stream).Read(bg, stream, 0, 10)
	if err != nil || len(got) != 3 {
		t.Fatalf("read %d records: %v", len(got), err)
	}
	for i, want := range [][]byte{snap, diff, base} {
		if config.Digest(got[i].Event) != config.Digest(want) {
			t.Errorf("record %d is not stored byte for byte", i+1)
		}
	}
}

// The document check refuses what is not a C9 or C10 document, a snapshot
// beside a capture it was not read from, and a capture where there is none;
// a record over the cap, or two in one batch, never commits.
func TestConfigDatabaseRefusals(t *testing.T) {
	c, dir := configNode(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	_, log, _ := r.view(r.find(ConfigDB))
	stream := ConfigStream(relayID)
	rec := func(doc []byte, cp *c5.Capture) c5.Record {
		return c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: doc, Capture: cp}
	}
	snap1, cap1 := configRead(t, "1")
	_, cap2 := configRead(t, "2")
	diff := contractFile(t, "config/testdata/valid/difference-1-2.json")
	base := contractFile(t, "baseline/testdata/valid/baseline-synthetic.json")
	// The same length as the transcript the snapshot names and other bytes,
	// with the SHA-256 of the bytes it carries: only the digest comparison
	// tells it from the transcript (B3 on #299).
	flipped := append([]byte(nil), cap1.Bytes...)
	flipped[0] ^= 0xff
	flipSum := sha256.Sum256(flipped)
	sameLength := c5.Capture{SHA256: hex.EncodeToString(flipSum[:]), Bytes: flipped}
	for name, rc := range map[string]c5.Record{
		"a C4 event":                  rec([]byte(`{"schema":"otsec.event/0.2","kind":"syslog"}`), nil),
		"not JSON":                    rec([]byte("SHO 1"), nil),
		"a snapshot with no capture":  rec(snap1, nil),
		"a snapshot, another capture": rec(snap1, &cap2),
		"a snapshot, a capture of the same length, other bytes": rec(snap1, &sameLength),
		"a difference with a capture":                           rec(diff, &cap1),
		"a baseline with a capture":                             rec(base, &cap1),
		"a snapshot that is not one":                            rec([]byte(strings.Replace(string(snap1), `"asset_id"`, `"asset_idx"`, 1)), &cap1),
	} {
		if _, err := log.Append(bg, rc); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
	// Over the record cap: refused, and a later record still commits.
	big := make([]byte, ConfigRecordBytes+1)
	sum := sha256.Sum256(big)
	if _, err := log.Append(bg, rec(snap1, &c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: big})); err == nil || !errors.Is(err, &c5.Error{Code: c5.CodeRecordTooLarge}) {
		t.Errorf("a record over the cap: %v", err)
	}
	if _, err := log.AppendBatch(bg, []c5.Record{rec(diff, nil), rec(base, nil)}); err == nil {
		t.Error("two configuration records in one batch")
	}
	if n, err := r.Store(stream).LastCommitted(bg, stream); err != nil || n != 0 {
		t.Fatalf("after the refusals the stream is at seq %d (%v), want 0", n, err)
	}
	if _, err := log.Append(bg, rec(snap1, &cap1)); err != nil {
		t.Fatalf("a good snapshot after the refusals: %v", err)
	}
}
