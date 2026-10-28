package store

import (
	"fmt"
	"strings"
	"time"

	"otsec.local/otsec/contracts/event"
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
	// ClassConfiguration (0.4): configuration snapshots and differences
	// (C9) and baselines (C10), each a typed document, not a C4 event. At
	// its quota configuration reads stop (StopCollecting). Its records may
	// be held (Holder), and its quota requires a MaxRecordBytes.
	ClassConfiguration StreamClass = "configuration"
	// ClassSyslogUnknown (0.4): Syslog from senders that resolve to no
	// asset, on every transport (HR-11). At its quota their messages are
	// dropped and counted, so a full class never refuses a connection that
	// also carries a known sender. The bound is the bytes stored at once,
	// which no clock step or restart refills.
	ClassSyslogUnknown StreamClass = "syslog-unknown"
)

// Classes lists every StreamClass.
var Classes = []StreamClass{ClassAdapterEvidence, ClassSyslogStream, ClassSyslogDatagram, ClassAudit, ClassPlatform, ClassConfiguration, ClassSyslogUnknown}

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

// FullAlarm is the alarm a class raises when its quota cannot hold the next
// record: audit-store-full for the audit class, syslog-unknown-full for the
// syslog-unknown class, and store-quota-reached for every other class. The
// runtime refusal and startup raise the same code, so one condition is one
// alarm to an operator and to the C6 views (B6 and B1 on #324).
func FullAlarm(c StreamClass) AlarmCode {
	switch c {
	case ClassAudit:
		return AlarmAuditFull
	case ClassSyslogUnknown:
		return AlarmSyslogUnknownFull
	}
	return AlarmQuotaReached
}

// ActionFor is the fixed storage-full action for each class (ADR-0004 item
// 9). It is not configurable: a node never evicts unconfirmed records of any
// class to make room.
func ActionFor(c StreamClass) (FullAction, error) {
	switch c {
	case ClassAdapterEvidence, ClassConfiguration:
		return StopCollecting, nil
	case ClassSyslogStream, ClassPlatform:
		return RefuseNew, nil
	case ClassSyslogDatagram, ClassSyslogUnknown:
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
	// MaxRecordBytes (0.4) caps one record of the class: its event plus
	// its capture. 0 means no cap of its own, so a record is bounded by
	// the Log's MaxCommitBytes instead. The configuration class requires
	// a cap. A record over it is refused with CodeRecordTooLarge before it
	// is queued.
	MaxRecordBytes int64
}

// MinRecordBytes is the smallest MaxRecordBytes or MaxCommitBytes (0.4).
// The recovery reserve rule (ReserveFor) is tested down to it.
const MinRecordBytes = 64 << 10

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
	switch {
	case q.MaxRecordBytes == 0 && q.Class == ClassConfiguration:
		return errf(CodeInvalid, nil, "quota for %s needs a record cap", q.Class)
	case q.MaxRecordBytes != 0 && (q.MaxRecordBytes < MinRecordBytes || q.MaxRecordBytes > q.Bytes):
		return errf(CodeInvalid, nil, "quota for %s: record cap %d not in [%d, %d]", q.Class, q.MaxRecordBytes, MinRecordBytes, q.Bytes)
	}
	return nil
}

// AlarmCode is the closed list of alarms the store raises. They become C4
// platform events on the node's platform/health stream, with the Health.Type
// HealthType gives, and appear in node status.
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
	AlarmOpenBlocked           AlarmCode = "store-open-blocked"   // blocked: not enough free space to open; recoverable
	AlarmInspectFailed         AlarmCode = "store-inspect-failed" // the store, its reserves or free space could not be read; failed
	AlarmOpenFailed            AlarmCode = "store-open-failed"
	AlarmSettingsInvalid       AlarmCode = "store-settings-invalid"
	AlarmIntegrityFailed       AlarmCode = "store-integrity-failed"
	AlarmPruneFailed           AlarmCode = "store-prune-failed"
	AlarmCompactFailed         AlarmCode = "store-compact-failed"
	AlarmDrainOnly             AlarmCode = "store-drain-only"
	// AlarmSyslogUnknownFull (0.4): the syslog-unknown class reached its
	// quota; unknown senders' messages are dropped and counted. Raised
	// once per fill and cleared below the class's WarnFraction. Detail
	// names the streams holding the most bytes.
	AlarmSyslogUnknownFull AlarmCode = "syslog-unknown-full"
	// AlarmHoldsReconciled (0.4): the node found a hold the C8 records do
	// not justify, or a missing one, and corrected it. Stream and Detail
	// name the record.
	AlarmHoldsReconciled AlarmCode = "store-holds-reconciled"
)

// HealthModeChanged is the C4 Health.Type of a ModeChange.
const HealthModeChanged = "store.mode-changed"

// HealthType is the C4 Health.Type the alarm is reported as (C4 review by
// A5, item 5). Two alarms use C4's existing types; every other is
// "store.<code>" without its "store-" prefix.
func (a AlarmCode) HealthType() string {
	switch a {
	case AlarmSyslogDropped:
		return event.HealthDropCounted
	case AlarmRequiredStalled:
		return event.HealthForwardUnreachable
	case AlarmAuditFull:
		return "store.audit-full"
	}
	return "store." + strings.TrimPrefix(string(a), "store-")
}

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
