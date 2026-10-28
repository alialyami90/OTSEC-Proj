package node

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"sync"
	"time"

	"otsec.local/otsec/contracts/asset"
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

	mu      sync.Mutex
	modes   map[c5.DatabaseID]c5.Mode
	alarms  []StatusAlarm
	targets map[string]TargetStatus
	// suspensions are the scheduler's current asset suspensions.
	suspensions map[string]asset.Suspension
	collClears  map[string]string
	quarantine  []QuarantineStatus
	collector   *CollectorStatus
	assets      map[string]AssetResult
	runsHeld    string
	listeners   map[string]ListenerStatus
	nodeKeys    []NodeKeyExpiry
	adminReqs   []AdminRequestStatus
	labTLS      bool
	labTLSRefs  []string
}

// StatusAlarm is one alarm as node status shows it: a store alarm, which
// names its database and has a C5 alarm code, or a collection alarm, which
// names its asset and has a code below.
type StatusAlarm struct {
	Database c5.DatabaseID `json:"database,omitempty"`
	Asset    string        `json:"asset_id,omitempty"`
	Target   string        `json:"target,omitempty"`
	Code     string        `json:"code"`
	At       time.Time     `json:"at"`
	Class    string        `json:"class,omitempty"`
	Stream   string        `json:"stream,omitempty"`
	Step     string        `json:"step,omitempty"`
	Detail   string        `json:"detail,omitempty"`
}

// StatusFile is the content of the status file.
type StatusFile struct {
	Schema  string    `json:"schema"`
	Node    string    `json:"node_id"`
	Written time.Time `json:"written"`
	// GoVersion is the Go toolchain the running node was built with
	// (runtime.Version), so an operator can check it against the latest
	// patch of a supported minor (D3-10). Empty in a file written by an
	// older node.
	GoVersion string                    `json:"go_version,omitempty"`
	Modes     map[c5.DatabaseID]c5.Mode `json:"modes"`
	Alarms    []StatusAlarm             `json:"alarms"`
	// Collecting is true only when every database accepts events.
	Collecting bool `json:"collecting"`
	// RunsHeld is the alarm code that stops every run on the node, level
	// 0 included, while it holds; empty when none does. The alarms list is
	// a history, so this is the one place that says whether such a hold is
	// still current (A3 on #147).
	RunsHeld string `json:"runs_held,omitempty"`
	// Targets is each forwarding target's state, from its forwarder.
	Targets map[string]TargetStatus `json:"targets,omitempty"`
	// Suspensions are the assets the node will not collect from until an
	// administrator clears them (suspend.go).
	Suspensions map[string]asset.Suspension `json:"suspensions,omitempty"`
	// CollectorClears are the clears the node has recorded that the
	// collector has not yet accepted, asset ID to the suspension's ref
	// (assetclear.go). The asset's runs are held until it does, and
	// clear-suspension.json must stay in place until then.
	CollectorClears map[string]string `json:"collector_clears,omitempty"`
	// Quarantine lists the recorded quarantine exports whose range still
	// holds records: not cleared, or cleared with removal not done
	// (quarantine.go).
	Quarantine []QuarantineStatus `json:"quarantine,omitempty"`
	// Collector is the collector's install keys as the audit stream gives
	// them (seqreset.go): the trusted key and, after a reinstall, the new
	// one beside it, for the administrator's fingerprint check.
	Collector *CollectorStatus `json:"collector,omitempty"`
	// Assets is each scheduled asset's last run that reached the collector
	// in this process (results.go).
	Assets map[string]AssetResult `json:"assets,omitempty"`
	// Listeners is each Syslog listener's state (listening.go).
	Listeners map[string]ListenerStatus `json:"listeners,omitempty"`
	// NodeKeys are the key register's active entries whose certificate
	// expires within NodeKeyWarning, or has expired (nodekeys.go).
	NodeKeys []NodeKeyExpiry `json:"node_keys_expiring,omitempty"`
	// AdminRequests is each admin-request file in admin_dir and the
	// collector's decision on it, if any (adminrelay.go).
	AdminRequests []AdminRequestStatus `json:"admin_requests,omitempty"`
	// LabTLSFiles is true when lab_tls_files is set, and LabTLSFileRefs
	// names the references whose private key is read from a file
	// (nodekeys.go, B3 on #176).
	LabTLSFiles    bool     `json:"lab_tls_files,omitempty"`
	LabTLSFileRefs []string `json:"lab_tls_file_refs,omitempty"`
}

// CollectorStatus is the collector's keys and numbering as node status
// shows them.
type CollectorStatus struct {
	TrustedKey   string `json:"trusted_key,omitempty"`
	OpenResetKey string `json:"open_reset_key,omitempty"`
	High         uint64 `json:"high"`
	Restored     bool   `json:"restored,omitempty"`
}

// TargetStatus is one forwarding target as node status shows it.
type TargetStatus struct {
	Class string `json:"class"`
	// LastConfirmed is when the target last confirmed a transaction in
	// this process; zero if never.
	LastConfirmed time.Time `json:"last_confirmed,omitzero"`
	Confirmed     uint64    `json:"confirmed"`
	// LastErr is why the last session ended. It is the forwarder's error
	// text, which never holds event content.
	LastErr string `json:"last_error,omitempty"`
	// Open is when the current session opened; zero while none is open.
	Open time.Time `json:"open,omitzero"`
	// Unreported counts forward.* health events the node's health stream
	// refused and the forwarder still holds to commit; ReportErr is the
	// last refusal (A4 #94).
	Unreported int                          `json:"unreported,omitempty"`
	ReportErr  string                       `json:"report_error,omitempty"`
	Streams    map[string]TargetStreamState `json:"streams"`
}

// TargetStreamState is one stream of a target: the saved cursor, the last
// position the target confirmed (ahead of the cursor while a report about
// the stream is owed, A4 #103), the stream's last committed seq, and why
// the stream is held, if it is.
type TargetStreamState struct {
	Cursor    uint64 `json:"cursor"`
	Confirmed uint64 `json:"confirmed"`
	Last      uint64 `json:"last"`
	Blocked   string `json:"blocked,omitempty"`
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
	// AlarmQuarantineNotStored stops every run on the node, level 0 included:
	// the evidence of a failed run could not be kept.
	AlarmQuarantineNotStored = "collection-quarantine-not-stored"
	AlarmNoQuarantineRoom    = "collection-no-quarantine-room"
	// AlarmQuarantineRoomLow: adapter-evidence holds WarnFraction of what
	// runs may use; runs stop at the quota less QuarantineRoom.
	AlarmQuarantineRoomLow = "collection-quarantine-room-low"
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

// RaiseTarget records a forwarding alarm for target.
func (s *Status) RaiseTarget(target, code, detail string) {
	if s.oslog != nil {
		s.oslog(fmt.Sprintf("otsec forward %s: %s %s", target, code, detail))
	}
	s.add(StatusAlarm{Target: target, Code: code, At: s.now().UTC(), Detail: detail})
}

// SetRunsHeld records the node-wide hold, or "" when there is none.
func (s *Status) SetRunsHeld(code string) {
	s.mu.Lock()
	s.runsHeld = code
	s.mu.Unlock()
}

// SetListeners records the Syslog listeners' state.
func (s *Status) SetListeners(m map[string]ListenerStatus) {
	s.mu.Lock()
	s.listeners = m
	s.mu.Unlock()
}

// SetAdminRequests records the admin-request files and their decisions.
func (s *Status) SetAdminRequests(r []AdminRequestStatus) {
	s.mu.Lock()
	s.adminReqs = slices.Clone(r)
	s.mu.Unlock()
}

// SetSuspensions records the node's current asset suspensions.
func (s *Status) SetSuspensions(m map[string]asset.Suspension) {
	s.mu.Lock()
	s.suspensions = m
	s.mu.Unlock()
}

// SetCollectorClears records the clears the collector has not yet
// accepted.
func (s *Status) SetCollectorClears(m map[string]string) {
	s.mu.Lock()
	s.collClears = m
	s.mu.Unlock()
}

// SetQuarantine records the quarantine exports still to clear or being
// cleared.
func (s *Status) SetQuarantine(q []QuarantineStatus) {
	s.mu.Lock()
	s.quarantine = q
	s.mu.Unlock()
}

// SetCollector records the collector's keys and numbering.
func (s *Status) SetCollector(c *CollectorStatus) {
	s.mu.Lock()
	s.collector = c
	s.mu.Unlock()
}

// SetNodeKeys records the node key register's expiring entries.
func (s *Status) SetNodeKeys(k []NodeKeyExpiry) {
	s.mu.Lock()
	s.nodeKeys = k
	s.mu.Unlock()
}

// SetLabTLSFiles records that lab_tls_files is set, and the references
// whose private key is read from a file.
func (s *Status) SetLabTLSFiles(refs []string) {
	s.mu.Lock()
	s.labTLS, s.labTLSRefs = true, slices.Clone(refs)
	s.mu.Unlock()
}

// SetAssetResults records each asset's last sent run.
func (s *Status) SetAssetResults(m map[string]AssetResult) {
	s.mu.Lock()
	s.assets = m
	s.mu.Unlock()
}

// SetTarget records target's state and reports whether it changed.
func (s *Status) SetTarget(name string, ts TargetStatus) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.targets == nil {
		s.targets = map[string]TargetStatus{}
	}
	prev, ok := s.targets[name]
	s.targets[name] = ts
	return !ok || !reflect.DeepEqual(prev, ts)
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
	f := StatusFile{Schema: StatusSchema, Node: node, Written: s.now().UTC(), GoVersion: runtime.Version(), Modes: map[c5.DatabaseID]c5.Mode{}, Alarms: append([]StatusAlarm{}, s.alarms...)}
	f.Collecting = len(s.modes) > 0
	f.RunsHeld = s.runsHeld
	for db, m := range s.modes {
		f.Modes[db] = m
		if !m.AcceptsEvents() {
			f.Collecting = false
		}
	}
	sort.SliceStable(f.Alarms, func(i, j int) bool { return f.Alarms[i].At.Before(f.Alarms[j].At) })
	if len(s.suspensions) > 0 {
		f.Suspensions = maps.Clone(s.suspensions)
	}
	if len(s.quarantine) > 0 {
		f.Quarantine = slices.Clone(s.quarantine)
	}
	if len(s.collClears) > 0 {
		f.CollectorClears = maps.Clone(s.collClears)
	}
	if s.collector != nil {
		c := *s.collector
		f.Collector = &c
	}
	if len(s.assets) > 0 {
		f.Assets = maps.Clone(s.assets)
	}
	if len(s.listeners) > 0 {
		f.Listeners = maps.Clone(s.listeners)
	}
	f.NodeKeys = slices.Clone(s.nodeKeys)
	f.LabTLSFiles, f.LabTLSFileRefs = s.labTLS, slices.Clone(s.labTLSRefs)
	if len(s.adminReqs) > 0 {
		f.AdminRequests = slices.Clone(s.adminReqs)
	}
	if len(s.targets) > 0 {
		f.Targets = map[string]TargetStatus{}
		for n, ts := range s.targets {
			f.Targets[n] = ts
		}
	}
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

// StatusFileName is the status file's name in the store directory, where
// only the node's account, SYSTEM and Administrators can read it.
const StatusFileName = "status.json"

// StatusPath is where the node writes its status file.
func StatusPath(c *Config) string { return filepath.Join(c.Store.Dir, StatusFileName) }

// ReadStatus reads a status file the node wrote.
func ReadStatus(path string) (StatusFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return StatusFile{}, err
	}
	var f StatusFile
	if err := json.Unmarshal(b, &f); err != nil {
		return StatusFile{}, fmt.Errorf("status file %s: %w", path, err)
	}
	if f.Schema != StatusSchema {
		return StatusFile{}, fmt.Errorf("status file %s is %q, want %q", path, f.Schema, StatusSchema)
	}
	return f, nil
}
