package node

import (
	"fmt"
	"sort"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/receive"
)

// Listener sizing (A3's condition D3-3 and HR-11, A6 on #150). A
// listener's unknown senders may store UnknownBytes per hour, refilled
// every hour, so over an upstream outage of T hours they can store
// UnknownBytes × (1 + T) in their class quota, which known devices share.
// The node sizes UnknownBytes so that every listener of a class together
// can take at most a quarter of that quota over the planned outage, and
// refuses a quota too small for that. Each node start refills the budget,
// so a node restarted R times in the outage can store UnknownBytes × R more
// from unknown senders. A received stream batch commits all
// or nothing, so the quota must also hold one whole batch beside the
// unknown share, or a large batch is held for good.
const (
	// DefaultSyslogOutageHours is the upstream outage the syslog classes
	// ride out when syslog_outage_hours is not set.
	DefaultSyslogOutageHours = 24
	MaxSyslogOutageHours     = 720
	// UnknownQuotaShare: unknown senders of a class's listeners together
	// may take at most 1/UnknownQuotaShare of its quota over the outage.
	UnknownQuotaShare = 4
	// MinUnknownBytes and MaxUnknownBytes bound a listener's hourly
	// unknown budget: A4's floor, and A4's default as the ceiling.
	MinUnknownBytes = 256 << 10
	MaxUnknownBytes = 1 << 20
	// ReceivedRecordFactor and ReceivedRecordOverhead bound the stored
	// event of any frame a listener accepts: at most ReceivedRecordBound
	// (factor × MaxMessage + overhead) bytes. It is a bound over the
	// listener's MaxMessage, not per frame: a small frame can store at far
	// more than factor × its own size, since a dialect's fields copy its
	// text (a 1024-byte RTAC frame of '<' stores as 19985 bytes, A6 on
	// #174). Measured on 8192-byte frames (simulated): 1.44× for random
	// bytes, 2.5× for ASCII text, 3.5× for quotes and 7.48× for control
	// characters or '<', which the JSON encoder escapes to six bytes in
	// the normalized message. The node's listeners use MaxMessage 8192,
	// where the worst frame measured stores at 61201 of 69632 bytes; at
	// receive's minimum of 2048 the margin is small, 19985 of 20480 in
	// A6's measurement (TestReceivedRecordBound pins both). A
	// configurable MaxMessage would need a larger overhead first.
	ReceivedRecordFactor   = 8
	ReceivedRecordOverhead = 4 << 10
)

// receiveDefaults are receive.Limits' defaults for a stream listener,
// which the node does not change except UnknownBytes.
const (
	streamMaxMessage = 8192
	streamQueue      = 64
)

// ReceivedRecordBound is the largest stored event of a frame a listener
// with this MaxMessage accepts.
func ReceivedRecordBound(maxMessage int64) int64 {
	return ReceivedRecordFactor*maxMessage + ReceivedRecordOverhead
}

// HeldBatchBytes is the largest stream batch a listener may hold for the
// store: Queue frames, each at its record bound.
const HeldBatchBytes = streamQueue * (ReceivedRecordFactor*streamMaxMessage + ReceivedRecordOverhead)

// listenerClass is the C5 class a listener's stream takes (Layout).
func listenerClass(t asset.Transport) c5.StreamClass {
	if t == asset.SyslogUDP {
		return c5.ClassSyslogDatagram
	}
	return c5.ClassSyslogStream
}

// outageHours is syslog_outage_hours, or its default.
func (c *Config) outageHours() int64 {
	if c.SyslogOutageHours == 0 {
		return DefaultSyslogOutageHours
	}
	return int64(c.SyslogOutageHours)
}

// ListenerSizing is what the node set for one listener's unknown senders.
type ListenerSizing struct {
	Class c5.StreamClass
	// UnknownBytes is the hourly budget of the listener's unknown senders
	// (receive.Limits.UnknownBytes).
	UnknownBytes int64
	// UnknownBound is what every listener of the class together may store
	// from unknown senders over the planned outage, at most a quarter of
	// the class quota.
	UnknownBound int64
	Quota        int64
	OutageHours  int64
}

// ListenerSizings sizes every listener's unknown budget from its class
// quota and the planned outage, or says why the quota is too small.
func (c *Config) ListenerSizings() (map[string]ListenerSizing, error) {
	byClass := map[c5.StreamClass][]string{}
	for _, l := range c.Listeners {
		cl := listenerClass(l.Transport)
		byClass[cl] = append(byClass[cl], l.ID)
	}
	classes := make([]string, 0, len(byClass))
	for cl := range byClass {
		classes = append(classes, string(cl))
	}
	sort.Strings(classes)
	t := c.outageHours()
	out := map[string]ListenerSizing{}
	for _, name := range classes {
		cl := c5.StreamClass(name)
		ids := byClass[cl]
		n := int64(len(ids))
		quota, ok := c.Store.Quotas[name]
		if !ok {
			return nil, fmt.Errorf("store.quotas has no quota for class %s, which listener %s uses", cl, ids[0])
		}
		per := min(quota/UnknownQuotaShare/(n*(1+t)), MaxUnknownBytes)
		if per < MinUnknownBytes {
			need := MinUnknownBytes * n * (1 + t) * UnknownQuotaShare
			return nil, fmt.Errorf("store.quotas.%s (%d bytes) is too small for %d listeners: unknown senders need at least %d bytes an hour each, and over a %d h outage (syslog_outage_hours) that is more than a quarter of the quota; the quota must be at least %d bytes (HR-11, D3-3)",
				cl, quota, n, MinUnknownBytes, t, need)
		}
		bound := per * n * (1 + t)
		if cl == c5.ClassSyslogStream && quota-bound < HeldBatchBytes {
			return nil, fmt.Errorf("store.quotas.%s (%d bytes) cannot hold one received stream batch (%d bytes) beside the unknown senders' share over the outage (%d bytes); a batch commits whole, so a larger one would be held for good (A6 on #150)",
				cl, quota, HeldBatchBytes, bound)
		}
		for _, id := range ids {
			out[id] = ListenerSizing{Class: cl, UnknownBytes: per, UnknownBound: bound, Quota: quota, OutageHours: t}
		}
	}
	return out, nil
}

// limits is listener id's receive.Limits: A4's defaults with the sized
// unknown budget, per hour as the sizing assumes.
func (sz ListenerSizing) limits() receive.Limits {
	return receive.Limits{UnknownBytes: sz.UnknownBytes, UnknownWindow: time.Hour}
}
