package node

import "time"

// AssetStoreStatus is the item 3 ceiling as status shows it (C5 0.8
// section 5): the most the configuration class may hold after an identity
// record, latest read, finding or set is written, whether a write is being
// refused now, and how many writes it has refused, by series, since start.
type AssetStoreStatus struct {
	CeilingBytes int64             `json:"ceiling_bytes"`
	Full         bool              `json:"full,omitempty"`
	Refused      map[string]uint64 `json:"refused_writes,omitempty"`
}

// ApplicabilityStatus is R9's state as status shows it (the node note,
// section 6).
type ApplicabilityStatus struct {
	// SetInUse is the set the matcher runs under, nil when none is.
	SetInUse *AdvisorySetStatus `json:"set_in_use,omitempty"`
	// LastRefusal is the last set file the node turned away, by C11's
	// checks or for want of room.
	LastRefusal *AdvisoryRefusalStatus `json:"last_refusal,omitempty"`
	// StoredSets is how many sets the advisory stream holds.
	StoredSets int `json:"stored_sets"`
}

// AdvisorySetStatus is one installed set (R9.3: what a report names).
type AdvisorySetStatus struct {
	SetID         string    `json:"set_id"`
	Version       uint64    `json:"version"`
	IssuedAt      string    `json:"issued_at"`
	PayloadSHA256 string    `json:"payload_sha256"`
	KeyID         string    `json:"key_id"`
	InUseSince    time.Time `json:"in_use_since"`
}

// AdvisoryRefusalStatus is one refused set file. Code is a C11 refusal code,
// or AlarmAdvisorySetNoRoom's for a set the ceiling turned away.
type AdvisoryRefusalStatus struct {
	FileSHA256 string    `json:"file_sha256"`
	Code       string    `json:"code"`
	Detail     string    `json:"detail,omitempty"`
	SetID      string    `json:"set_id,omitempty"`
	Version    uint64    `json:"version,omitempty"`
	At         time.Time `json:"at"`
}

// SetAssetStore records the ceiling's state.
func (s *Status) SetAssetStore(a *AssetStoreStatus) {
	s.mu.Lock()
	s.assetStore = a
	s.mu.Unlock()
}

// SetApplicability records R9's state.
func (s *Status) SetApplicability(a *ApplicabilityStatus) {
	s.mu.Lock()
	s.applic = a
	s.mu.Unlock()
}
