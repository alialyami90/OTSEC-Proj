package node

import (
	"fmt"
	"sort"
	"strings"

	"otsec.local/otsec/contracts/asset"
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
	for _, d := range []c5.Database{evidence, syslogDB, auditDB} {
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
			d.Quotas = append(d.Quotas, c5.Quota{Class: class, Bytes: bytes, WarnFraction: c.Store.WarnFraction})
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
// quarantine stream.
func (c *Config) Consumers() ([]c5.Consumer, error) {
	l, err := c.Layout()
	if err != nil {
		return nil, err
	}
	var events []c5.StreamID
	for s, class := range l.StreamClasses() {
		if class != c5.ClassAudit && !strings.HasPrefix(string(s), c5.QuarantinePrefix) {
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
