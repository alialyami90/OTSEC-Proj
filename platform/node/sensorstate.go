package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// The sensor fold's read of the audit stream (docs/phase4/D5-sensor-node.md
// section 1.3, "Where the state lives"; C13 CH-11 and CH-45; M-10): pages
// of 64, each under a 1 s deadline, run by the sensor manager, never by the
// scheduler's fold. This build judges only whether each record can be read
// and parsed; what the records enrol, revoke or refuse is P4-4-DE's
// (enrolment), so it names no sensor action. Not wired (F-027's gate):
// nothing outside the tests makes a sensorFold.
const (
	sensorFoldPage     = 64
	sensorFoldDeadline = time.Second
)

// The causes of sensor-state-unread this fold raises (CH-45).
const (
	StateUnreadFoldRecord = "fold-record"
	StateUnreadFoldRead   = "fold-read"
)

// sensorCloser is a sensor link's close for a decision (sensorlink's
// Link.CloseConn).
type sensorCloser interface{ CloseConn(reason string) }

// sensorFold reads the audit stream from through for the sensor state.
type sensorFold struct {
	read    func(ctx context.Context, after c5.Seq, max int) ([]c5.Stored, error)
	last    func(ctx context.Context) (c5.Seq, error)
	links   []sensorCloser
	raise   func(alarm, detail string)
	through c5.Seq
	// unread is the cause standing, "" when the state was read.
	unread string
}

// fold reads every record after through. A record that cannot be parsed
// makes the state unknown: every open sensor connection closes as
// state-unread, the cursor stays before it, and sensor-state-unread stands
// with cause fold-record until a fold reads it (the record may be a
// revocation; fail closed). A read that fails keeps the cursor and the
// links, and stands with cause fold-read until a later fold reads through.
func (f *sensorFold) fold(ctx context.Context) {
	err := f.readThrough(ctx)
	bad := badRecord{}
	switch {
	case err == nil:
		f.unread = ""
	case errors.As(err, &bad):
		for _, l := range f.links {
			l.CloseConn(netobs.CloseStateUnread)
		}
		f.stand(StateUnreadFoldRecord, err)
	default:
		f.stand(StateUnreadFoldRead, err)
	}
}

func (f *sensorFold) stand(cause string, err error) {
	if f.unread != cause {
		f.unread = cause
		f.raise(alarmSensorStateUnread, fmt.Sprintf("cause %s: the sensor state cannot be read past audit seq %d: %v", cause, f.through, err))
	}
}

// alarmSensorStateUnread is sensorlink's AlarmStateUnread, named here so
// that the node's alarms list it.
const alarmSensorStateUnread = "sensor-state-unread"

func (f *sensorFold) readThrough(ctx context.Context) error {
	page := func(fn func(ctx context.Context) error) error {
		ctx, cancel := context.WithTimeout(ctx, sensorFoldDeadline)
		defer cancel()
		return fn(ctx)
	}
	var last c5.Seq
	if err := page(func(ctx context.Context) (err error) { last, err = f.last(ctx); return }); err != nil {
		return err
	}
	for f.through < last {
		var got []c5.Stored
		if err := page(func(ctx context.Context) (err error) { got, err = f.read(ctx, f.through, sensorFoldPage); return }); err != nil {
			return err
		}
		if len(got) == 0 {
			return fmt.Errorf("audit stream ends at %d, before its last committed seq %d", f.through, last)
		}
		for _, st := range got {
			if _, err := parseAuditRecord(st.Event); err != nil {
				return badRecord{st.Key.Seq, err}
			}
			f.through = st.Key.Seq
		}
	}
	return nil
}
