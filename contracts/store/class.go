package store

import (
	"fmt"
	"time"
)

// StreamClass groups streams by how they may behave when storage is full.
// Closed set.
type StreamClass string

const (
	// ClassAdapterEvidence: records the node reads from a device through an
	// adapter (SER, event reports, identification). The device keeps them
	// until its buffer wraps, so the node stops reading rather than drop.
	ClassAdapterEvidence StreamClass = "adapter-evidence"
	// ClassSyslogStream: Syslog received over TCP, TLS or RELP. The node
	// stops accepting (and, for RELP, stops acknowledging) rather than drop.
	ClassSyslogStream StreamClass = "syslog-stream"
	// ClassSyslogDatagram: Syslog received over UDP. The sender cannot be
	// slowed, so excess messages are dropped and counted.
	ClassSyslogDatagram StreamClass = "syslog-datagram"
	// ClassAudit: audit records (C8). Privileged operations fail closed when
	// they cannot be recorded.
	ClassAudit StreamClass = "audit"
	// ClassPlatform: platform health and alarm events. The node stops
	// accepting new ones and keeps the alarm in node status.
	ClassPlatform StreamClass = "platform"
)

// Classes lists every StreamClass.
var Classes = []StreamClass{ClassAdapterEvidence, ClassSyslogStream, ClassSyslogDatagram, ClassAudit, ClassPlatform}

// FullAction is what the store does for a class at its quota. Closed set.
type FullAction string

const (
	// StopCollecting: the collector stops reading from the device and raises
	// AlarmCollectionStopped with the stop time and the device-buffer
	// overwrite estimate.
	StopCollecting FullAction = "stop-collecting"
	// RefuseNew: the listener stops accepting new data; nothing already
	// received is acknowledged without a Receipt.
	RefuseNew FullAction = "refuse-new"
	// DropAndCount: new datagrams are dropped; the count is persisted and
	// forwarded (AlarmSyslogDropped).
	DropAndCount FullAction = "drop-and-count"
	// FailClosed: operations that need a record (privileged operations for
	// audit) are refused.
	FailClosed FullAction = "fail-closed"
)

// ActionFor is the fixed storage-full action for each class (ADR-0004 item
// 9). It is not configurable: a node never evicts unconfirmed records of any
// class to make room.
func ActionFor(c StreamClass) (FullAction, error) {
	switch c {
	case ClassAdapterEvidence:
		return StopCollecting, nil
	case ClassSyslogStream, ClassPlatform:
		return RefuseNew, nil
	case ClassSyslogDatagram:
		return DropAndCount, nil
	case ClassAudit:
		return FailClosed, nil
	}
	return "", errf(CodeInvalid, nil, "unknown stream class %q", c)
}

// Quota is the space one class may use in its database. Each class has its
// own quota, so a Syslog storm cannot use the space SER needs.
type Quota struct {
	Class StreamClass
	Bytes int64
	// WarnFraction of Bytes raises AlarmQuotaWarning, for example 0.8.
	WarnFraction float64
}

// Validate checks one quota.
func (q Quota) Validate() error {
	if _, err := ActionFor(q.Class); err != nil {
		return err
	}
	if q.Bytes <= 0 {
		return errf(CodeInvalid, nil, "quota for %s: bytes must be positive", q.Class)
	}
	if !(q.WarnFraction > 0 && q.WarnFraction < 1) {
		return errf(CodeInvalid, nil, "quota for %s: warn fraction %v not in (0,1)", q.Class, q.WarnFraction)
	}
	return nil
}

// AlarmCode is the closed list of alarms the store raises. They become C4
// platform events (TODO(C4): event kind mapping) and appear in node status.
type AlarmCode string

const (
	AlarmQuotaWarning          AlarmCode = "store-quota-warning"
	AlarmQuotaReached          AlarmCode = "store-quota-reached"
	AlarmCollectionStopped     AlarmCode = "collection-stopped"
	AlarmSyslogDropped         AlarmCode = "syslog-dropped"
	AlarmAuditFull             AlarmCode = "audit-store-full"
	AlarmRequiredStalled       AlarmCode = "required-consumer-stalled"
	AlarmCommitFailed          AlarmCode = "store-commit-failed"
	AlarmLockFailed            AlarmCode = "store-lock-failed"
	AlarmReserveReleaseFailed  AlarmCode = "reserve-release-failed"
	AlarmReserveMissing        AlarmCode = "reserve-missing"
	AlarmReserveRecreateFailed AlarmCode = "reserve-recreate-failed"
	AlarmOpenBlocked           AlarmCode = "store-open-blocked"
	AlarmOpenFailed            AlarmCode = "store-open-failed"
	AlarmSettingsInvalid       AlarmCode = "store-settings-invalid"
	AlarmIntegrityFailed       AlarmCode = "store-integrity-failed"
	AlarmPruneFailed           AlarmCode = "store-prune-failed"
	AlarmCompactFailed         AlarmCode = "store-compact-failed"
	AlarmDrainOnly             AlarmCode = "store-drain-only"
)

// Alarm is one storage alarm. Fields that do not apply to a code are zero.
type Alarm struct {
	Code   AlarmCode
	At     time.Time
	Class  StreamClass // quota and storage-full alarms
	Stream StreamID    // stream-specific alarms
	Step   Step        // startup alarms
	// StoppedAt and OverwriteAfter are set for AlarmCollectionStopped: when
	// reading stopped, and the estimated time after which the device buffer
	// overwrites records not yet read (zero: unknown).
	StoppedAt      time.Time
	OverwriteAfter time.Duration
	// Count is set for AlarmSyslogDropped.
	Count  int64
	Detail string
}

func (a Alarm) String() string { return fmt.Sprintf("%s %s", a.Code, a.Detail) }
