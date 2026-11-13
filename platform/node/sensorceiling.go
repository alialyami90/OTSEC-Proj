package node

import (
	"context"
	"errors"
	"fmt"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
)

// The platform-class floor and ceiling, in bytes (docs/phase4/D5-sensor-
// node.md section 1.9 item 5; F-027's F1). The platform class holds the
// health stream, where collection writes each run's collection.* record
// and a held run's collection.missed (missed.go, schedule.go). Collection's
// need over the outage is reserved first, and the sensor's events are
// written only beneath it, so a sensor that fills the class never stops a
// run from being recorded.

// AlarmSensorPlatformFloor: store.quotas.platform is below collection's
// need plus the sensor's share (PlatformFloor), so the sensor is not
// started: no intake. The node starts and collects. It is raised once, as
// the quota and the schedule are read at start only.
const AlarmSensorPlatformFloor = "sensor-platform-floor"

// SensorHealthRecordBytes is the stored size each health record is
// reckoned at (section 1.10, unmeasured).
const SensorHealthRecordBytes = 4096

// SensorHealthEventsHour is the sensor's health events an hour (section
// 1.10: 12 drop counts, 4 + 4 coverage gaps, a pool of 24, and its
// database's mode change), and RetiredHealthEventsHour a retired sensor's.
// main has one sensor and no retired one.
const (
	SensorHealthEventsHour  = 45
	RetiredHealthEventsHour = 3
)

// errPastCeiling: a sensor health event was not written, because the
// platform class would hold quota less collection's need or more after it.
var errPastCeiling = errors.New("node: the platform class is at the sensor's ceiling, so the sensor's health event is held")

// PlatformFloor is collection's need over the outage, C, and the sensor's
// share, S, in bytes (section 1.9 item 5): C = R x 2 x 4,096 x H, where R
// is the schedule's runs an hour and H the sensor's outage_hours, and S =
// (45 x sensors + 3 x retired) x 4,096 x H. Each entry's part of C is
// rounded up, so C is never under its exact value. Both are 0 without the
// network_sensor section. C is a lower bound: it counts collection's run
// records only (section 1.14).
func (c *Config) PlatformFloor() (collection, sensor int64) {
	s := c.NetworkSensor
	if s == nil {
		return 0, 0
	}
	h := int64(s.OutageHours)
	for _, col := range c.Schedule {
		every := int64(col.EverySeconds)
		if every <= 0 {
			continue // refused at load
		}
		collection += (3600*2*SensorHealthRecordBytes*h + every - 1) / every
	}
	return collection, SensorHealthEventsHour * SensorHealthRecordBytes * h
}

// platformFloorShort reports whether the platform quota is below C + S,
// and the alarm's detail when it is.
func (c *Config) platformFloorShort() (bool, string) {
	col, sen := c.PlatformFloor()
	q := c.Store.Quotas[string(c5.ClassPlatform)]
	if q >= col+sen {
		return false, ""
	}
	return true, fmt.Sprintf("store.quotas.platform is %d bytes, below collection's need of %d bytes over %d outage hours plus the sensor's share of %d bytes (%d in all), so the sensor is not started; the node collects without it",
		q, col, c.NetworkSensor.OutageHours, sen, col+sen)
}

// ceilingFits reports whether a sensor event of size bytes may be written
// with used bytes in the platform class: only while the class holds less
// than quota less collection's need after it.
func ceilingFits(used, size, quota, collection int64) bool {
	return used+size < quota-collection
}

// sensorHealth commits a sensor health event to platform/health under the
// ceiling: errPastCeiling, counted in status as health_held, when it does
// not fit. Like healthSink, it appends nothing in a mode that accepts no
// events. Every health event the sensor's work writes comes here: its drop
// counts, its databases' store alarms and mode changes, and the forwarder's
// sensor session's reports (D6's N3 on #662).
func (r *Runtime) sensorHealth(ctx context.Context, he event.Health) (c5.Key, error) {
	db, log, mode := r.view(r.dbFor(HealthStream))
	if log == nil || db == nil {
		return c5.Key{}, errors.New("node: the health stream's database is not open")
	}
	if !mode.AcceptsEvents() {
		return c5.Key{}, fmt.Errorf("node: the health stream's database is in mode %s, which accepts no events", mode)
	}
	rec, err := r.healthEventRecord(HealthStream, he)
	if err != nil {
		return c5.Key{}, err
	}
	used, err := db.ClassBytes(ctx, c5.ClassPlatform)
	if err != nil {
		return c5.Key{}, err
	}
	col, _ := r.cfg.PlatformFloor()
	if !ceilingFits(used, rec.Bytes(), r.cfg.Store.Quotas[string(c5.ClassPlatform)], col) {
		r.sensorHeld.Add(1)
		return c5.Key{}, errPastCeiling
	}
	rc, err := log.Append(ctx, rec)
	if err != nil {
		return c5.Key{}, err
	}
	return rc.Key(), nil
}

// sensorHealthEvent is Runtime.health for a sensor health event: under the
// ceiling, and a failure other than the ceiling raises store-commit-failed.
func (r *Runtime) sensorHealthEvent(ctx context.Context, typ string, details map[string]string) {
	_, err := r.sensorHealth(ctx, event.Health{Type: typ, Details: details})
	if err == nil || errors.Is(err, errPastCeiling) {
		return
	}
	if d := r.dbFor(HealthStream); d != nil {
		if _, log, mode := r.view(d); log != nil && mode.AcceptsEvents() {
			r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: HealthStream, Detail: "health event " + typ + ": " + err.Error()})
		}
	}
}

// sensorHealthSink is the forwarder's sensor session's HealthSink: its
// forward.* reports about the sensor's streams go under the ceiling.
type sensorHealthSink struct{ rt *Runtime }

func (h sensorHealthSink) Emit(ctx context.Context, he event.Health) (c5.Key, error) {
	return h.rt.sensorHealth(ctx, he)
}
