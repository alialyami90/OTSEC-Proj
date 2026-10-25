package node

import (
	"fmt"
	"maps"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// AssetResult is an asset's last run that reached the collector, as node
// status shows it (D2-17): the code it ended with and how many runs in a
// row have failed. A failure that suspends nothing, such as C2 0.3's
// failed.identity_unreadable, is retried at every interval, and this is
// where its repetition shows. The counts are this process's; the health
// stream's collection.* events are the durable history.
type AssetResult struct {
	// Code is "ok", the outcome's C2 error code, or, for a run without an
	// outcome code, the collection alarm it raised.
	Code string `json:"code"`
	// Refusal is the collector's refusal code when it refused the run.
	Refusal string    `json:"refusal,omitempty"`
	At      time.Time `json:"at"`
	// Failures counts the runs in a row that did not end "ok".
	Failures int `json:"consecutive_failures"`
}

// AlarmRepeatedFailure is raised once when an asset's runs have failed
// RepeatedFailureAfter times in a row, and again only after a run succeeds
// and failures start over.
const AlarmRepeatedFailure = "collection-repeated-failure"

// RepeatedFailureAfter is how many failed runs in a row raise
// AlarmRepeatedFailure.
const RepeatedFailureAfter = 3

// resultCode is the code status shows for a sent run.
func (rep Report) resultCode() string {
	switch {
	case rep.Code != "":
		// A quarantined outcome's code was not verified: an unknown one
		// shows as failed.unknown, as suspend reads it.
		return string(rep.Code.Effective())
	case rep.Alarm != "":
		return rep.Alarm
	}
	return string(adapter.StatusOK)
}

// recordResult updates the asset's last result after a sent run.
func (s *Scheduler) recordResult(assetID string, rep Report) {
	code := rep.resultCode()
	s.mu.Lock()
	r := s.results[assetID]
	r.Code, r.Refusal, r.At = code, rep.Refusal, s.now().UTC()
	if code == string(adapter.StatusOK) {
		r.Failures = 0
	} else {
		r.Failures++
	}
	s.results[assetID] = r
	all := maps.Clone(s.results)
	s.mu.Unlock()
	s.rt.opt.Status.SetAssetResults(all)
	switch {
	case r.Failures == 0:
		s.clearQuietKey(assetID + " " + AlarmRepeatedFailure)
	case r.Failures >= RepeatedFailureAfter:
		s.raiseOnce(assetID, AlarmRepeatedFailure, fmt.Sprintf("%d runs in a row failed; the last ended %s", r.Failures, code))
	}
}
