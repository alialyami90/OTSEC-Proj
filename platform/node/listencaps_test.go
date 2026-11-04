package node

import (
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// A listener's receiver splits its batches at the commit caps of the Log
// behind it: the node passes it the options it built that Log with, and the
// receiver reads them back (C5 0.4, 0.5; B1 on #281). Datagram and stream
// listeners alike.
func TestListenerReceiversGetTheSyslogLogsCommitCaps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group c5.GroupOptions
		bytes int64
		recs  int
	}{
		{"defaults", c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}, c5.DefaultMaxCommitBytes, SyslogBatchRecords},
		{"commit bytes set", c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond, MaxCommitBytes: 256 << 10}, 256 << 10, SyslogBatchRecords},
		{"both set", c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond, MaxCommitBytes: 128 << 10, MaxCommitRecords: 300}, 128 << 10, 300},
		{"events above the record cap", c5.GroupOptions{MaxEvents: 2000, MaxWait: 5 * time.Millisecond}, c5.DefaultMaxCommitBytes, 2000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
				nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0").AddListener("lab-tcp", "syslog-tcp", "127.0.0.1:0")
			})
			c := parse(t, nc)
			st := NewStatus(dir+"/status.json", func(string) {}, nil)
			r, err := Start(bg, c, RuntimeOptions{Status: st, Group: tc.group})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ls, err := NewListening(r)
			if err != nil {
				t.Fatal(err)
			}
			if len(ls.receivers) != 2 {
				t.Fatalf("%d receivers, want 2", len(ls.receivers))
			}
			// The caps the node's own Log for that stream was built with.
			g := groupFor(r.dbFor(ListenerStream("lab-udp")).spec, tc.group)
			if g.CommitBytes() != tc.bytes || g.CommitRecords() != tc.recs {
				t.Fatalf("the syslog Log has caps %d and %d, test expects %d and %d", g.CommitBytes(), g.CommitRecords(), tc.bytes, tc.recs)
			}
			for i, rc := range ls.receivers {
				bytes, recs := rc.CommitCaps()
				if bytes != tc.bytes || recs != tc.recs {
					t.Errorf("receiver %d: caps %d bytes and %d records, want %d and %d", i, bytes, recs, tc.bytes, tc.recs)
				}
			}
		})
	}
}
