package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// Status is the node's alarm channel outside the store (C5-A3-5). Every
// store alarm and mode reaches it, whether or not the database that raised
// it can store a health event, so a storage failure stays observable
// (principle 5). It keeps the current state in memory, rewrites a status
// file on every change, and hands each alarm to the OS log (the Windows
// Event Log under the SCM, stderr and so the journal on Linux).
type Status struct {
	path  string
	oslog func(string)
	now   func() time.Time

	mu     sync.Mutex
	modes  map[c5.DatabaseID]c5.Mode
	alarms []StatusAlarm
}

// StatusAlarm is one alarm as node status shows it: a store alarm, which
// names its database and has a C5 alarm code, or a collection alarm, which
// names its asset and has a code below.
type StatusAlarm struct {
	Database c5.DatabaseID `json:"database,omitempty"`
	Asset    string        `json:"asset_id,omitempty"`
	Code     string        `json:"code"`
	At       time.Time     `json:"at"`
	Class    string        `json:"class,omitempty"`
	Stream   string        `json:"stream,omitempty"`
	Step     string        `json:"step,omitempty"`
	Detail   string        `json:"detail,omitempty"`
}

// StatusFile is the content of the status file.
type StatusFile struct {
	Schema  string                    `json:"schema"`
	Node    string                    `json:"node_id"`
	Written time.Time                 `json:"written"`
	Modes   map[c5.DatabaseID]c5.Mode `json:"modes"`
	Alarms  []StatusAlarm             `json:"alarms"`
	// Collecting is true only when every database accepts events.
	Collecting bool `json:"collecting"`
}

// StatusSchema identifies the status file format.
const StatusSchema = "otsec.nodestatus/0.1"

// MaxStatusAlarms is how many recent alarms the status keeps.
const MaxStatusAlarms = 200

// NewStatus returns a Status that writes path (empty: no file) and logs
// through oslog (nil: no OS log).
func NewStatus(path string, oslog func(string), now func() time.Time) *Status {
	if now == nil {
		now = time.Now
	}
	return &Status{path: path, oslog: oslog, now: now, modes: map[c5.DatabaseID]c5.Mode{}}
}

// Alarm records one alarm of database db.
func (s *Status) Alarm(db c5.DatabaseID, a c5.Alarm) {
	if a.At.IsZero() {
		a.At = s.now()
	}
	sa := StatusAlarm{Database: db, Code: string(a.Code), At: a.At.UTC(), Class: string(a.Class), Stream: string(a.Stream), Step: string(a.Step), Detail: a.Detail}
	if s.oslog != nil {
		s.oslog(fmt.Sprintf("otsec store %s: %s %s", db, a.Code, a.Detail))
	}
	s.add(sa)
}

// Collection alarm codes. AlarmUnauthorizedLine is the safety case: by the
// node's own register, a session sent a line its run was not allowed to
// send, and collection from that asset stops until the node restarts.
const (
	AlarmUnauthorizedLine   = "collection-unauthorized-line"
	AlarmAuditUnavailable   = "collection-audit-unavailable"
	AlarmOutcomeUnknown     = "collection-outcome-unknown"
	AlarmCollectorRefused   = "collection-refused"
	AlarmNoDecision         = "collection-no-decision"
	AlarmResultRefused      = "collection-result-refused"
	AlarmEvidenceNotStored  = "collection-evidence-not-stored"
	AlarmCollectionDisabled = "collection-disabled"
	// AlarmQuarantineNotStored stops every credentialed run on the node:
	// the evidence of a failed run could not be kept.
	AlarmQuarantineNotStored = "collection-quarantine-not-stored"
	AlarmNoQuarantineRoom    = "collection-no-quarantine-room"
)

// Raise records a collection alarm for asset. detail goes to the OS log, so
// it never holds device text: a quarantine's reason stays with the
// quarantined evidence.
func (s *Status) Raise(asset, code, detail string) {
	if s.oslog != nil {
		s.oslog(fmt.Sprintf("otsec collection %s: %s %s", asset, code, detail))
	}
	s.add(StatusAlarm{Asset: asset, Code: code, At: s.now().UTC(), Detail: detail})
}

func (s *Status) add(sa StatusAlarm) {
	s.mu.Lock()
	s.alarms = append(s.alarms, sa)
	if len(s.alarms) > MaxStatusAlarms {
		s.alarms = s.alarms[len(s.alarms)-MaxStatusAlarms:]
	}
	s.mu.Unlock()
}

// SetMode records database db's mode.
func (s *Status) SetMode(db c5.DatabaseID, m c5.Mode) {
	if s.oslog != nil {
		s.oslog(fmt.Sprintf("otsec store %s: mode %s", db, m))
	}
	s.mu.Lock()
	s.modes[db] = m
	s.mu.Unlock()
}

// Snapshot returns the current status.
func (s *Status) Snapshot(node string) StatusFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := StatusFile{Schema: StatusSchema, Node: node, Written: s.now().UTC(), Modes: map[c5.DatabaseID]c5.Mode{}, Alarms: append([]StatusAlarm{}, s.alarms...)}
	f.Collecting = len(s.modes) > 0
	for db, m := range s.modes {
		f.Modes[db] = m
		if !m.AcceptsEvents() {
			f.Collecting = false
		}
	}
	sort.SliceStable(f.Alarms, func(i, j int) bool { return f.Alarms[i].At.Before(f.Alarms[j].At) })
	return f
}

// Write writes the snapshot to the status file: to a temporary file in the
// same directory, flushed, then renamed, so a reader never sees half a file.
func (s *Status) Write(node string) error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.Snapshot(node), "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".status-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
