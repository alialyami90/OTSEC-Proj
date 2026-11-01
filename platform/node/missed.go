package node

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"
)

// missedRun is the slots of one schedule entry that ended with none of its
// SER rows and none of its collection.* records stored: the run was not
// sent (a hold, a suspension, an audit record that could not be written),
// or its outcome or its record was lost. The event-baseline feeder opens a
// gap only at a stored failure, so without a record the read after such a
// series would carry its backlog as if it had been read on time, and the
// learner would take it in full (V-S12, C1 on #365).
//
// One collection.missed is written for the series, once the health stream
// takes it, and never again for that series: a series ends at the entry's
// next stored run. While the record is not written, no run of the entry is
// sent (D4-37): a read then would store its rows ahead of the record, and
// its own collection.run would be refused as well. The held slots join the
// series. The series is in memory only, so a restart before it is written
// loses it; the feeder opens a gap across every node restart, which covers
// that (feeder slice 1c).
type missedRun struct {
	col     Collection
	firstAt time.Time
	alarm   string // the first slot's alarm
	request string // the first slot's request ID, empty if it sent none
	n       int    // slots missed when the record was written, or so far
	written bool
}

// noteMissed records how schedule entry i's run ended: a stored run ends the
// entry's series, any other run joins it.
func (s *Scheduler) noteMissed(i int, rep Report) {
	col := s.rt.cfg.Schedule[i]
	id := col.ID
	if rep.stored {
		delete(s.missed, id)
		return
	}
	m := s.missed[id]
	if m == nil {
		m = &missedRun{col: col, firstAt: s.now(), alarm: rep.Alarm, request: rep.RequestID}
		s.missed[id] = m
	}
	if !m.written {
		m.n++
	}
}

// writeMissed writes collection.missed for each series not yet written. A
// series the health stream does not take now is tried again at the next
// run, and its entry's runs are held until it is written (heldMissed).
func (s *Scheduler) writeMissed(ctx context.Context) {
	log := s.rt.Log(HealthStream)
	if log == nil {
		return
	}
	for _, id := range slices.Sorted(maps.Keys(s.missed)) {
		m := s.missed[id]
		if m.written {
			continue
		}
		col := m.col
		d := map[string]string{"asset_id": col.AssetID, "schedule": col.ID, "operation": col.Operation,
			"missed": strconv.Itoa(m.n), "first_at": m.firstAt.UTC().Format(time.RFC3339Nano), "alarm": m.alarm}
		if m.request != "" {
			d["request_id"] = m.request
		}
		rec, err := s.rt.healthRecord(HealthStream, HealthCollectionMissed, d)
		if err == nil {
			_, err = log.Append(ctx, rec)
		}
		if err != nil {
			s.raiseOnceKey("missed "+id, col.AssetID, AlarmEvidenceNotStored, fmt.Sprintf("%s of schedule entry %s not stored, so its runs are held: %v", HealthCollectionMissed, id, err))
			continue
		}
		s.clearQuietKey("missed " + id)
		m.written = true
	}
}

// heldMissed reports whether schedule entry id has a series not yet
// written, so its run is not sent (D4-37).
func (s *Scheduler) heldMissed(id string) bool {
	m := s.missed[id]
	return m != nil && !m.written
}
