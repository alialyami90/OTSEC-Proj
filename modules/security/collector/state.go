package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// StateFormat identifies the durable state file. A file with another value
// is refused.
const StateFormat = "otsec.collector-state/0.1"

// ErrStateUnavailable means the durable collector state could not be read or
// written. Every run is then refused with collector_state_unavailable
// (C7-A5-3): a lost write could reopen the failed-auth floor or reuse a
// collector_seq number, so the collector does not guess.
var ErrStateUnavailable = errors.New("collector: durable state unavailable")

// State is the collector's durable state (A3 credential design, section 3;
// D1-20 as amended): the collector_seq counter; per asset the time of the
// last unconfirmed authentication, the TIDLE last read from it and the time
// of the last run that connected to it; per register family the
// anti-rollback floor (C3-A3-4); and the times of recent credential installs
// (the install budget).
//
// Every change is written to disk, flushed and renamed into place before the
// method returns, so a caller that has a nil error knows the change survives
// a crash. A failed write leaves the state broken: the in-memory copy no
// longer matches what the disk holds, so every later call fails with
// ErrStateUnavailable until the collector restarts and reads the file again.
//
// The file is created once, by InitState, when the collector is installed.
// OpenState never creates it: a missing file at run time is a lost state,
// not a first start, because creating a fresh one would reopen every floor
// and restart collector_seq at 1.
type State struct {
	path   string
	now    func() time.Time
	mu     sync.Mutex
	doc    stateDoc
	broken error
}

type stateDoc struct {
	Format       string                 `json:"format"`
	CollectorSeq uint64                 `json:"collector_seq"` // the last number handed out; 0 before the first
	Assets       map[string]assetState  `json:"assets"`
	Families     map[string]familyFloor `json:"families,omitempty"`
	Installs     []string               `json:"installs,omitempty"` // RFC 3339 UTC times of recent installs, oldest first
}

// familyFloor is authz.FamilyFloor as stored.
type familyFloor struct {
	Revision      uint64 `json:"revision"`
	PayloadSHA256 string `json:"payload_sha256"` // lowercase hex
}

type assetState struct {
	// UnconfirmedAuthUTC is when ACC was about to be sent and no "=>" has
	// confirmed the login since. Empty when none is pending.
	UnconfirmedAuthUTC string `json:"unconfirmed_auth_utc,omitempty"`
	// TIDLESeconds is the port TIDLE last read from the asset; 0 is unknown.
	TIDLESeconds int `json:"tidle_seconds,omitempty"`
	// LastRunUTC is when the last accepted run to the asset began, for the
	// profile's minimum interval.
	LastRunUTC string `json:"last_run_utc,omitempty"`
}

// MaxStateBytes bounds the state file. One asset entry is about 100 bytes,
// so this holds tens of thousands of assets, far beyond one node.
const MaxStateBytes = 4 << 20

// InitState creates the state file at path. It refuses to overwrite an
// existing file. The installer calls it once (A5, platform/winsvc); its
// directory must already carry the collector's protected DACL (W-4) or, on
// Linux, mode 0700.
func InitState(path string) error {
	b, err := json.Marshal(stateDoc{Format: StateFormat, Assets: map[string]assetState{}})
	if err != nil {
		return err
	}
	if err := createExclusive(path, b); err != nil {
		return fmt.Errorf("collector: create state: %w", err)
	}
	return nil
}

// createExclusive writes b to a new file at path, mode 0600, and flushes the
// file and its directory. It refuses an existing file, and removes what it
// created when a step fails.
func createExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// OpenState reads the state file. Any failure, including a missing file, is
// ErrStateUnavailable. now is the clock; nil means time.Now.
func OpenState(path string, now func() time.Time) (*State, error) {
	if now == nil {
		now = time.Now
	}
	b, err := readBounded(path, MaxStateBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateUnavailable, err)
	}
	var doc stateDoc
	if err := collectorwire.DecodeStrict(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrStateUnavailable, path, err)
	}
	if doc.Format != StateFormat || doc.Assets == nil {
		return nil, fmt.Errorf("%w: %s: format %q", ErrStateUnavailable, path, doc.Format)
	}
	if err := checkStateDoc(doc); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrStateUnavailable, path, err)
	}
	return &State{path: path, now: now, doc: doc}, nil
}

func checkStateDoc(doc stateDoc) error {
	for id, a := range doc.Assets {
		for _, ts := range []string{a.UnconfirmedAuthUTC, a.LastRunUTC} {
			if ts == "" {
				continue
			}
			if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
				return fmt.Errorf("asset %s: %v", id, err)
			}
		}
		if a.TIDLESeconds < 0 {
			return fmt.Errorf("asset %s: negative TIDLE", id)
		}
	}
	for fam, f := range doc.Families {
		if b, err := hex.DecodeString(f.PayloadSHA256); err != nil || len(b) != sha256.Size || f.PayloadSHA256 != strings.ToLower(f.PayloadSHA256) {
			return fmt.Errorf("family %s: payload_sha256 is not a lowercase SHA-256", fam)
		}
	}
	for _, ts := range doc.Installs {
		if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			return fmt.Errorf("installs: %v", err)
		}
	}
	return nil
}

// NextSeq hands out the next collector_seq number, written durably first. A
// number is never handed out twice, and a crash after NextSeq returns leaves
// at worst a number with no event, which audit.VerifyCollectorSeq shows as a
// gap: the safe direction.
func (s *State) NextSeq() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return 0, s.broken
	}
	next := s.doc
	next.CollectorSeq++
	if err := s.write(next); err != nil {
		return 0, err
	}
	return s.doc.CollectorSeq, nil
}

// LastSeq returns the last number handed out.
func (s *State) LastSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.CollectorSeq
}

// CheckFloor returns nil when a run on asset may authenticate, a refusal
// with rate_limited when the asset is inside its failed-auth floor, and
// ErrStateUnavailable when the state is broken. It runs before any
// connection (T-9).
func (s *State) CheckFloor(asset string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	a := s.doc.Assets[asset]
	if a.UnconfirmedAuthUTC == "" {
		return nil
	}
	t, _ := time.Parse(time.RFC3339Nano, a.UnconfirmedAuthUTC) // checked on open and on write
	floor := authz.FailureFloor(time.Duration(a.TIDLESeconds) * time.Second)
	if authz.InsideFailureFloor(t, s.now(), floor) {
		return &authz.Refusal{Code: authz.RefuseRateLimited, Detail: fmt.Sprintf("failed-auth floor of %s from %s", floor, a.UnconfirmedAuthUTC)}
	}
	return nil
}

// BeginAuth records, durably, that ACC is about to be sent to asset. The
// adapter sends ACC only after it returns nil (FloorGate.BeforeACC).
func (s *State) BeginAuth(asset string) error {
	return s.update(asset, func(a *assetState) {
		a.UnconfirmedAuthUTC = s.now().UTC().Format(time.RFC3339Nano)
	})
}

// ConfirmAuth clears the pending authentication of asset, durably. It is
// called only when "=>" follows ACC (FloorGate.Confirmed).
func (s *State) ConfirmAuth(asset string) error {
	return s.update(asset, func(a *assetState) { a.UnconfirmedAuthUTC = "" })
}

// SetTIDLE records the TIDLE read from asset. Only a value from 1 to 30
// minutes is kept; anything else is recorded as unknown, which gives the
// longest floor.
func (s *State) SetTIDLE(asset string, tidle time.Duration) error {
	return s.update(asset, func(a *assetState) {
		a.TIDLESeconds = 0
		if tidle >= time.Minute && tidle <= 30*time.Minute {
			a.TIDLESeconds = int(tidle / time.Second)
		}
	})
}

// CheckInterval refuses with rate_limited a run that starts sooner than min
// after the last accepted run to asset (the profile's min_interval_ms, C2
// Limits). A last run later than the clock counts as too recent.
func (s *State) CheckInterval(asset string, min time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	last := s.doc.Assets[asset].LastRunUTC
	if last == "" {
		return nil
	}
	t, _ := time.Parse(time.RFC3339Nano, last) // checked on open and on write
	if now := s.now(); t.After(now) || now.Sub(t) < min {
		return &authz.Refusal{Code: authz.RefuseRateLimited, Detail: fmt.Sprintf("minimum interval of %s since the run at %s", min, last)}
	}
	return nil
}

// BeginRun records, durably, that a run to asset starts now.
func (s *State) BeginRun(asset string) error {
	return s.update(asset, func(a *assetState) {
		a.LastRunUTC = s.now().UTC().Format(time.RFC3339Nano)
	})
}

// TakeInstall spends one install from the budget: at most limit installs in
// any window. It refuses with rate_limited when the budget is spent, and
// records the install durably otherwise. An install time later than the
// clock stays in the window. The budget keeps a node service that has been
// compromised from using installs to test guesses of stored secrets
// (docs/phase2/A3-collector.md, reuse rule).
func (s *State) TakeInstall(limit int, window time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	now := s.now()
	var kept []string
	for _, ts := range s.doc.Installs {
		t, _ := time.Parse(time.RFC3339Nano, ts) // checked on open and on write
		if t.After(now) || now.Sub(t) < window {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= limit {
		return &authz.Refusal{Code: authz.RefuseRateLimited, Detail: fmt.Sprintf("install budget of %d per %s is spent", limit, window)}
	}
	next := s.doc
	next.Installs = append(kept, now.UTC().Format(time.RFC3339Nano))
	return s.write(next)
}

// FamilyFloors returns the persisted anti-rollback floor of every register
// family, for authz.VerifyRegisterPackage.
func (s *State) FamilyFloors() map[string]authz.FamilyFloor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]authz.FamilyFloor, len(s.doc.Families))
	for fam, f := range s.doc.Families {
		var ff authz.FamilyFloor
		ff.Revision = f.Revision
		hex.Decode(ff.PayloadSHA256[:], []byte(f.PayloadSHA256)) // checked on open and on write
		out[fam] = ff
	}
	return out
}

// SetFamilyFloor persists a family's floor. The collector calls it after a
// package verifies and before it activates the package, and does not
// activate it if this fails (C7).
func (s *State) SetFamilyFloor(family string, f authz.FamilyFloor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	next := s.doc
	next.Families = make(map[string]familyFloor, len(s.doc.Families)+1)
	for k, v := range s.doc.Families {
		next.Families[k] = v
	}
	next.Families[family] = familyFloor{Revision: f.Revision, PayloadSHA256: hex.EncodeToString(f.PayloadSHA256[:])}
	return s.write(next)
}

func (s *State) update(asset string, f func(*assetState)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	next := s.doc
	next.Assets = make(map[string]assetState, len(s.doc.Assets)+1)
	for k, v := range s.doc.Assets {
		next.Assets[k] = v
	}
	a := next.Assets[asset]
	f(&a)
	if a == (assetState{}) {
		delete(next.Assets, asset)
	} else {
		next.Assets[asset] = a
	}
	return s.write(next)
}

// write replaces the file with next and, only on success, adopts it. Any
// failure breaks the state.
func (s *State) write(next stateDoc) error {
	err := checkStateDoc(next)
	var b []byte
	if err == nil {
		b, err = marshalState(next)
	}
	if err == nil && len(b) > MaxStateBytes {
		err = fmt.Errorf("state would be %d bytes, limit %d", len(b), MaxStateBytes)
	}
	if err == nil {
		err = replaceFile(s.path, b)
	}
	if err != nil {
		s.broken = fmt.Errorf("%w: write %s: %v", ErrStateUnavailable, s.path, err)
		return s.broken
	}
	s.doc = next
	return nil
}

// marshalState encodes the state; encoding/json sorts map keys, so the same
// state always gives the same bytes.
func marshalState(d stateDoc) ([]byte, error) { return json.Marshal(d) }

// replaceFile writes b to a temporary file beside path, flushes it, renames
// it over path and flushes the directory, so path holds either the old or
// the new bytes after a crash, never a mix.
func replaceFile(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := renameDurable(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, max)
	}
	b := make([]byte, st.Size())
	if _, err := f.ReadAt(b, 0); err != nil && st.Size() > 0 {
		return nil, err
	}
	return b, nil
}

// FloorGate binds the durable state to one asset for one run. It has the
// methods of the adapter's FloorGate (modules/ied/sel751, the seam agreed
// with A2).
type FloorGate struct {
	state *State
	asset string
	// Alarm receives a failure to clear the floor. Clearing failed is the
	// safe side (the floor stays set), but the state is now broken and the
	// operator needs to know. Nil drops it.
	Alarm func(error)

	confirmed atomic.Bool
}

// NewFloorGate returns the gate for one run on asset.
func NewFloorGate(s *State, asset string) *FloorGate {
	return &FloorGate{state: s, asset: asset}
}

// BeforeACC records the attempt durably. ACC is sent only after nil.
func (g *FloorGate) BeforeACC(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return g.state.BeginAuth(g.asset)
}

// Confirmed clears the floor after "=>" followed ACC.
func (g *FloorGate) Confirmed(ctx context.Context) {
	g.confirmed.Store(true)
	if err := g.state.ConfirmAuth(g.asset); err != nil && g.Alarm != nil {
		g.Alarm(err)
	}
}

// LoginConfirmed reports whether Confirmed was called in this run: the
// session reached Level 1, so the relay keeps that level until QUI or TIDLE.
func (g *FloorGate) LoginConfirmed() bool { return g.confirmed.Load() }
