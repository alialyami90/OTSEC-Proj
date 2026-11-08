package sensorlink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/node"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// Constructed fixtures, desk only: no sensor produced them and no device
// was contacted. Addresses are TEST-NET-1 (192.0.2.0/24).
const (
	testNode    node.ID = "site-a-node1"
	testSensor          = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
	testRun             = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"
	relay               = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13" // ssh direct at .20
	master              = "7c1e5a20-4d3b-4f6a-8b2c-9e0d1f2a3b4c" // syslog sender at .10
	obsStream           = c5.StreamID("network-observation/" + testSensor)
	alertStream         = c5.StreamID("network-alert/" + testSensor)
)

func ptr[T any](v T) *T { return &v }

func ep(id string, tr asset.Transport, host string, path asset.Path) asset.Endpoint {
	return asset.Endpoint{ID: id, Transport: tr, Host: host, Port: 22, Path: path, Target: asset.Simulated}
}

func testAssets() []asset.Asset {
	return []asset.Asset{
		{AssetID: relay, NodeID: testNode, Endpoints: []asset.Endpoint{ep("ssh", asset.SSH, "192.0.2.20", asset.Direct)}},
		{AssetID: master, NodeID: testNode, Endpoints: []asset.Endpoint{ep("syslog", asset.SyslogUDP, "192.0.2.10", "")}},
	}
}

func frameBytes(n, off, ln int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	for i := off; i < off+ln; i++ {
		b[i] = netobs.RedactionByte
	}
	return b
}

func hashOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func coverage() netobs.Coverage {
	return netobs.Coverage{
		SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
		Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
		PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded,
		VLANsSeen: []int{10}, UntaggedSeen: true, Decodes: []string{"dnp3", "modbus"}, Degraded: []string{},
		Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3, FlowIdleS: netobs.DefaultFlowIdleS},
		SinceUTC: "2026-11-07T08:00:00.000000Z",
	}
}

// firstSight is a first-sight DNP3 direct operate from src to dst, on the
// channel: two frames with their bytes, the second with a redaction.
func firstSight(seq int, src, dst, sa string) *netobs.Observation {
	f1, f2 := frameBytes(74, 0, 0), frameBytes(90, 60, 8)
	return &netobs.Observation{
		Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: testSensor, RunID: testRun, Seq: strconv.Itoa(seq),
		Kind: netobs.KindFunction, FirstSight: true,
		FirstUTC: "2026-11-07T10:00:00.000001Z", LastUTC: "2026-11-07T10:00:00.120001Z", ResolutionNS: 1000,
		L2:        netobs.L2{SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", VLAN: ptr(10), EtherType: "0x0800"},
		IP:        &netobs.IP{Src: src, Dst: dst, L4: "tcp", Sport: ptr(51234), Dport: ptr(20000)},
		Direction: netobs.DirectionClientServer, Protocol: "dnp3",
		Citation: netobs.Citation{CaptureID: "ring:" + testRun + ":3", FramesTotal: 2, Frames: []netobs.CitedFrame{
			{N: 17, CapturedLen: len(f1), WireLen: len(f1), SHA256: hashOf(f1)},
			{N: 19, CapturedLen: len(f2), WireLen: len(f2), SHA256: hashOf(f2),
				Redactions: []netobs.Redaction{{Offset: 60, Length: 8, Reason: netobs.ReasonCredential}}},
		}},
		Coverage: coverage(),
		Function: &netobs.Function{Code: 5, Objects: []string{"g12v1"}, SA: sa},
		Frames: []netobs.Frame{
			{N: 17, TS: "2026-11-07T10:00:00.000001Z", Data: base64.StdEncoding.EncodeToString(f1)},
			{N: 19, TS: "2026-11-07T10:00:00.120001Z", Data: base64.StdEncoding.EncodeToString(f2)},
		},
	}
}

// flow is a flow start from src to dst that is not a first sight.
func flow(seq int, src, dst string) *netobs.Observation {
	o := firstSight(seq, src, dst, "")
	o.Kind, o.Function, o.Frames, o.FirstSight = netobs.KindFlow, nil, nil, false
	o.Flow = &netobs.Flow{Phase: "start", Packets: 3, Bytes: 222}
	return o
}

func heartbeat(seq int, packets uint64) *netobs.Heartbeat {
	return &netobs.Heartbeat{Schema: netobs.Identifier, Type: netobs.TypeHeartbeat, SensorID: testSensor, RunID: testRun,
		Seq: strconv.Itoa(seq), AtUTC: "2026-11-07T10:00:10.000000Z", Coverage: coverage(),
		Counters: netobs.Counters{Packets: packets, Bytes: packets * 90}, InterfaceCheck: "ok"}
}

// stream frames records as the sensor writes them.
func stream(t *testing.T, recs ...any) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range recs {
		b, ok := r.([]byte)
		if !ok {
			var err error
			if b, err = json.Marshal(r); err != nil {
				t.Fatal(err)
			}
		}
		if err := netobs.WriteFrame(&buf, b); err != nil {
			t.Fatal(err)
		}
	}
	return &buf
}

// clock is the test's monotonic clock.
type clock struct{ now time.Duration }

func (c *clock) mono() time.Duration { return c.now }

func received() event.Received {
	return event.Received{UTC: "2026-11-07T10:00:01.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}
}

// netStore is a network database with the given observation quota, and a
// Log over it.
type netStore struct {
	db  *store.DB
	log *c5.Log
}

func openNet(t *testing.T, obsQuota int64) netStore {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	d := c5.Database{ID: "network", Writer: "detection",
		Streams: []c5.StreamSpec{{ID: obsStream, Class: c5.ClassNetworkObservation}, {ID: alertStream, Class: c5.ClassNetworkAlert}},
		Classes: []c5.StreamClass{c5.ClassNetworkAlert, c5.ClassNetworkObservation},
		Quotas: []c5.Quota{
			{Class: c5.ClassNetworkAlert, Bytes: 4 << 20, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes},
			{Class: c5.ClassNetworkObservation, Bytes: obsQuota, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes},
		}}
	env, err := store.NewEnv(store.Options{Dir: dir, Node: testNode, Database: d})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := c5.RunStartup(ctx, env, c5.StartupPolicy{Streams: d.Streams,
		RecoveryReserveBytes: 2 * store.WALBoundBytes, LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes: store.WALBoundBytes + c5.MinOpenHeadroom, PruneStepEvents: 50, CompactStepPages: 32, PruneTarget: 0.8})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup mode %s: %v", r.Mode, r.Err)
	}
	if r.Unlock != nil {
		t.Cleanup(r.Unlock)
	}
	db, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatalf("store is %T", r.Store)
	}
	t.Cleanup(func() { db.Close() })
	log, err := c5.NewLogFor(db, testNode, d, c5.GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond, MaxCommitRecords: 128}, map[c5.StreamID]c5.Seq{})
	if err != nil {
		t.Fatal(err)
	}
	return netStore{db: db, log: log}
}

// Append, AppendBatch and LastCommitted make a netStore the link's Appender.
func (s netStore) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	return s.log.Append(ctx, rec)
}

func (s netStore) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	return s.log.AppendBatch(ctx, recs)
}

func (s netStore) LastCommitted(ctx context.Context) (uint64, error) {
	return s.db.LastCommitted(ctx, obsStream)
}

func newLink(t *testing.T, s netStore, c *clock, obsQuota int64) *Link {
	t.Helper()
	l, err := New(Config{NodeID: testNode, SensorID: testSensor, EvidenceClass: asset.Simulated, OutageHours: 1,
		ObservationQuota: obsQuota, Stream: obsStream},
		Options{Assets: testAssets(), Store: s, Monotonic: c.mono, Received: received})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// stored reads every committed observation back.
func stored(t *testing.T, s netStore) []c5.Stored {
	t.Helper()
	got, err := s.db.Read(context.Background(), obsStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
