package node

import (
	"fmt"
	"sort"
	"strings"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/baseline"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
)

// The node's databases. Evidence read from devices and the node's own
// health events share one database, so a capture that rides on a health
// event (an unaligned SER read, D1-12) is kept in the database of the record
// that refers to it. Received Syslog has its own database, so a Syslog storm
// cannot hold the evidence database's lock, and audit is alone, as C5
// requires.
const (
	EvidenceDB c5.DatabaseID = "evidence"
	SyslogDB   c5.DatabaseID = "syslog"
	AuditDB    c5.DatabaseID = "audit"
	// ConfigDB holds configuration snapshots, differences and baselines
	// (C9, C10; C5 0.4) and nothing else, so a full configuration store
	// cannot stop event collection and an event flood cannot stop
	// configuration reads. It exists when store.quotas names the
	// configuration class, and then has one stream for each asset.
	ConfigDB c5.DatabaseID = "configuration"

	HealthStream c5.StreamID = "platform/health"
	AuditStream  c5.StreamID = "audit"
)

// SERStream is the stream of an asset's SER records.
func SERStream(assetID string) c5.StreamID { return c5.StreamID("ser/" + assetID) }

// QuarantineStream is the stream of an asset's quarantined run outcomes:
// outcomes that failed the collector client's checks (A3, #82). It has no
// consumer, so no Syslog target forwards it, and a C5 stream with no
// consumer is never pruned (CodeNoConsumers): the quarantine stays on the
// node until an operator deals with it, bounded only by the class quota.
func QuarantineStream(assetID string) c5.StreamID { return c5.StreamID(c5.QuarantinePrefix + assetID) }

// ListenerStream is the stream of the messages a listener receives.
func ListenerStream(listenerID string) c5.StreamID { return c5.StreamID("syslog/" + listenerID) }

// UnknownStream is the stream of the messages a listener receives from
// senders that resolve to no asset (HR-11, C5 0.4). It is in the
// listener's database and has class syslog-unknown, whose quota is the
// absolute bound on what unknown senders hold at once. A stream keeps one
// class for life, so known and unknown messages cannot share one.
func UnknownStream(listenerID string) c5.StreamID {
	return c5.StreamID("syslog-unknown/" + listenerID)
}

// ConfigStream is the stream of an asset's configuration documents: its C9
// snapshots and differences, and its C10 baselines (C5 0.4).
func ConfigStream(assetID string) c5.StreamID { return c5.StreamID("config/" + assetID) }

// ConfigRecordBytes is the record cap of the configuration class: one
// document plus its capture, the transcript of one config.read. B2's
// estimate of a full SEL-751 read is 150 to 250 KB; the cap is B1's D4-9
// figure, 1.5 MiB, and the largest SER read in B2's measurement, about
// 1.95 MB for realistic rows, is an event database's matter, not this
// one's. A record over it is refused before it is queued and the read goes
// to quarantine, so no partial snapshot is ever stored (C9).
const ConfigRecordBytes int64 = 1536 << 10

// ConfigQuotaFloorRecords (D4-20 rule 5) is how many full-size records the
// configuration quota must hold for each asset whose configuration the node
// reads: the baseline, the two newest reads that showed no difference, one
// read in flight, and room for 12 held differences before the class stops.
const ConfigQuotaFloorRecords = 16

// ConfigReadOperation reports whether a register operation ID reads an
// asset's configuration: the second segment is "config" and the last starts
// with "read", as in sel.config.read_all (B2's C9 brief, register revision
// 5). A schedule entry with such an operation is configuration collection.
func ConfigReadOperation(op string) bool {
	parts := strings.Split(op, ".")
	return len(parts) >= 3 && parts[1] == "config" && strings.HasPrefix(parts[len(parts)-1], "read")
}

// ReadsConfiguration reports whether the scheduled collection reads an
// asset's configuration. It is the one predicate: the quota floor counts
// assets with it, and the writer that stores configuration records takes only
// the runs for which it holds, so the two cannot count differently (B1 and B6
// on #299).
func (s Collection) ReadsConfiguration() bool { return ConfigReadOperation(s.Operation) }

// ConfigAssets counts the assets whose configuration the schedule reads.
func (c *Config) ConfigAssets() int {
	seen := map[string]bool{}
	for _, s := range c.Schedule {
		if s.ReadsConfiguration() {
			seen[s.AssetID] = true
		}
	}
	return len(seen)
}

// Layout derives the node's C5 layout from the configuration: one SER
// stream per asset with a scheduled collection, one stream per listener,
// the health stream and the audit stream, each database with a quota for
// every class it holds. A class it needs without a quota in store.quotas is
// an error.
func (c *Config) Layout() (c5.Layout, error) {
	evidence := c5.Database{ID: EvidenceDB, Writer: "node"}
	seen := map[string]bool{}
	for _, s := range c.Schedule {
		if seen[s.AssetID] {
			continue
		}
		seen[s.AssetID] = true
		evidence.Streams = append(evidence.Streams,
			c5.StreamSpec{ID: SERStream(s.AssetID), Class: c5.ClassAdapterEvidence},
			c5.StreamSpec{ID: QuarantineStream(s.AssetID), Class: c5.ClassAdapterEvidence})
	}
	evidence.Streams = append(evidence.Streams, c5.StreamSpec{ID: HealthStream, Class: c5.ClassPlatform})

	// The configuration database is opted into by its quota: a node that
	// does not name the class keeps the layout it had before C5 0.4. Its
	// streams are one for each asset, because a C10 event baseline belongs
	// to an asset that sends Syslog or SER events whether or not any
	// configuration is read from it.
	configDB := c5.Database{ID: ConfigDB, Writer: "node"}
	floor := int64(c.ConfigAssets())*ConfigQuotaFloorRecords*ConfigRecordBytes + c.EventBaselineQuotaFloor()
	if _, ok := c.Store.Quotas[string(c5.ClassConfiguration)]; !ok && floor > 0 {
		// An absent quota is below the floor too (D4-20 rule 5): without it
		// there is no configuration database, and the first read would have
		// nowhere to go.
		return c5.Layout{}, fmt.Errorf("store.quotas.configuration is required: the schedule reads the configuration of %d assets and %d event baselines are set, which needs at least %d bytes (%d x the record cap for each configuration asset, D4-20, and %d x %d bytes and %d x %d bytes for the baselines and checkpoints of each other event-baseline asset)",
			c.ConfigAssets(), len(c.EventBaselines), floor, ConfigQuotaFloorRecords, EventBaselineQuotaRecords, baseline.MaxBytes, EventCheckpointRecords, ConfigRecordBytes)
	}
	if _, ok := c.Store.Quotas[string(c5.ClassConfiguration)]; ok {
		for _, a := range c.assets {
			configDB.Streams = append(configDB.Streams, c5.StreamSpec{ID: ConfigStream(a.AssetID), Class: c5.ClassConfiguration})
		}
	}

	syslogDB := c5.Database{ID: SyslogDB, Writer: "telemetry"}
	for _, l := range c.Listeners {
		class := c5.ClassSyslogStream
		if l.Transport == asset.SyslogUDP {
			class = c5.ClassSyslogDatagram
		}
		syslogDB.Streams = append(syslogDB.Streams,
			c5.StreamSpec{ID: ListenerStream(l.ID), Class: class},
			c5.StreamSpec{ID: UnknownStream(l.ID), Class: c5.ClassSyslogUnknown})
	}
	auditDB := c5.Database{ID: AuditDB, Writer: "security", Streams: []c5.StreamSpec{{ID: AuditStream, Class: c5.ClassAudit}}}

	var l c5.Layout
	for _, d := range []c5.Database{evidence, syslogDB, auditDB, configDB} {
		if len(d.Streams) == 0 {
			continue
		}
		classes := map[c5.StreamClass]bool{}
		for _, s := range d.Streams {
			classes[s.Class] = true
		}
		for class := range classes {
			bytes, ok := c.Store.Quotas[string(class)]
			if !ok {
				return c5.Layout{}, fmt.Errorf("store.quotas has no quota for class %s, which database %s holds", class, d.ID)
			}
			d.Classes = append(d.Classes, class)
			q := c5.Quota{Class: class, Bytes: bytes, WarnFraction: c.Store.WarnFraction}
			if class == c5.ClassConfiguration {
				if bytes < ConfigRecordBytes {
					return c5.Layout{}, fmt.Errorf("store.quotas.configuration (%d bytes) is below the record cap, %d bytes: it must hold at least one snapshot with its transcript", bytes, ConfigRecordBytes)
				}
				if n := int64(c.ConfigAssets()); n > 0 && bytes < n*ConfigQuotaFloorRecords*ConfigRecordBytes {
					return c5.Layout{}, fmt.Errorf("store.quotas.configuration (%d bytes) is below the floor for configuration collection: %d bytes, %d x the record cap for each of the %d assets the schedule reads (D4-20)",
						bytes, n*ConfigQuotaFloorRecords*ConfigRecordBytes, ConfigQuotaFloorRecords, n)
				}
				if bytes < floor {
					return c5.Layout{}, fmt.Errorf("store.quotas.configuration (%d bytes) is below the floor for event baselines and configuration: %d bytes (%d x %d bytes of baselines and %d x %d bytes of checkpoints for each event-baseline asset whose configuration is not read, and the D4-20 floor for each that is)",
						bytes, floor, EventBaselineQuotaRecords, baseline.MaxBytes, EventCheckpointRecords, ConfigRecordBytes)
				}
				q.MaxRecordBytes = ConfigRecordBytes
			}
			d.Quotas = append(d.Quotas, q)
		}
		sort.Slice(d.Classes, func(i, j int) bool { return d.Classes[i] < d.Classes[j] })
		sort.Slice(d.Quotas, func(i, j int) bool { return d.Quotas[i].Class < d.Quotas[j].Class })
		l.Databases = append(l.Databases, d)
	}
	if err := l.Validate(); err != nil {
		return c5.Layout{}, err
	}
	return l, nil
}

// Consumers returns every forwarding target's C5 consumers (C6-A5-2): each
// target consumes every event stream of the node, platform/health included,
// and the audit stream when its audit flag is set. No target consumes a
// quarantine stream, and none a configuration stream: its documents are C9
// and C10, not C4 events, so no Syslog target carries them, and a stream
// with no consumer is never pruned (only the class quota bounds it).
func (c *Config) Consumers() ([]c5.Consumer, error) {
	l, err := c.Layout()
	if err != nil {
		return nil, err
	}
	var events []c5.StreamID
	for s, class := range l.StreamClasses() {
		if class != c5.ClassAudit && class != c5.ClassConfiguration && !strings.HasPrefix(string(s), c5.QuarantinePrefix) {
			events = append(events, s)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i] < events[j] })
	var out []c5.Consumer
	for _, t := range c.targets {
		cs, err := syslog.Consumers(t, events, AuditStream)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		out = append(out, cs...)
	}
	return out, nil
}

func knownClass(s string) bool {
	_, err := c5.ActionFor(c5.StreamClass(s))
	return err == nil
}
