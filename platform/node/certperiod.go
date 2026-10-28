package node

import (
	"crypto/tls"
	"fmt"
	"time"
)

// Certificate period alarms (HR-13, D4-11). They are node status alarms,
// not C6 or C8 names.
const (
	// AlarmListenerHeldBack: a syslog-tls listener's certificate is outside
	// its validity period at start. The listener is not bound, so no socket
	// is open and nothing is received on it, and the rest of the node runs.
	// The node re-checks the loaded certificate at each Publish and starts
	// the listener once the period is valid.
	AlarmListenerHeldBack = "syslog-listener-held-back"
	// AlarmTargetHeldBack: a relp-tls target's client certificate is
	// outside its validity period at start. The forwarder is not run, so no
	// connection is made and nothing is sent to the target, and its events
	// wait in the store. A required target that stays held back becomes
	// forward-unreachable like any other that confirms nothing.
	AlarmTargetHeldBack = "forward-target-held-back"
	// AlarmTargetCertExpiring: a target's client certificate expires within
	// CertWarning, or has expired while the forwarder runs. It is the
	// target counterpart of AlarmListenerCertExpiring.
	AlarmTargetCertExpiring = "forward-certificate-expiring"
)

// CertWarning is how long before a certificate's NotAfter the node warns
// about it: the same period for listeners and targets (D4-11 item 3).
const CertWarning = ListenerCertWarning

// CertAlarmRepeat is how often a certificate alarm is raised again while
// its condition lasts (D4-11 item 9). A link whose certificate has passed
// its end keeps running, so the alarm that names it is raised again, not
// only at the change: the status keeps the newest MaxStatusAlarms, and an
// alarm raised once could be pushed out of it by others.
const CertAlarmRepeat = time.Hour

// certWatch decides when a link's certificate alarm is raised: at the
// first check in a state and when the state changes, and, for a state in
// which the link is down or past its certificate's end, again every
// CertAlarmRepeat while it lasts. The 30-day "expiring" warning is raised
// once.
type certWatch struct {
	state  string
	raised time.Time
}

// certState is "expired", "expiring" or "" for a certificate that ends at
// notAfter.
func certState(notAfter, now time.Time) string {
	switch {
	case !now.Before(notAfter):
		return "expired"
	case notAfter.Sub(now) <= CertWarning:
		return "expiring"
	}
	return ""
}

// due reports whether the alarm for state is raised now, and records it.
func (w *certWatch) due(state string, now time.Time) bool {
	if state == "" {
		w.state, w.raised = "", time.Time{}
		return false
	}
	if state == w.state && (state == "expiring" || now.Sub(w.raised) < CertAlarmRepeat) {
		return false
	}
	w.state, w.raised = state, now
	return true
}

// heldState is why a certificate is outside its validity period at now:
// "not-yet-valid" or "expired".
func heldState(leafNotBefore, leafNotAfter, now time.Time) string {
	if now.Before(leafNotBefore) {
		return "not-yet-valid"
	}
	return "expired"
}

// periodDetail describes a certificate's validity period for an alarm.
func periodDetail(what string, notBefore, notAfter time.Time) string {
	return fmt.Sprintf("%s is valid from %s to %s", what, notBefore.UTC().Format(time.RFC3339), notAfter.UTC().Format(time.RFC3339))
}

// leafPeriod is the validity period of a loaded certificate.
func leafPeriod(c *tls.Certificate) (notBefore, notAfter time.Time, err error) {
	leaf, err := leafOf([]tls.Certificate{*c})
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return leaf.NotBefore, leaf.NotAfter, nil
}
