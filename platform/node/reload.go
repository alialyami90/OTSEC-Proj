package node

import (
	"context"
	"errors"
)

// errAuditNotOpen and errEvidenceNotOpen are the reads NewScheduler could
// not make because the database was not open: it failed at start, and C5
// 0.2 lets Tick open it later after a busy open (P3-A5).
var (
	errAuditNotOpen    = errors.New("audit database not open")
	errEvidenceNotOpen = errors.New("evidence database not open")
)

// reload does what NewScheduler could not do because a database was not
// open, once Tick has opened it (C5 0.2, P3-A5). Every run calls it first,
// so no run goes before it has succeeded:
//
//   - The suspensions are loaded as at start, from the checkpoint and the
//     audit stream. Only then does the node stop holding every run for
//     AlarmSuspensionsUnknown. A load that fails for another reason keeps
//     every run held, as it would at start, and is not tried again.
//   - An asset held as halted because its quarantine stream could not be
//     read is read again. It runs again only when the stream holds no
//     unauthorized-line quarantine.
func (s *Scheduler) reload(ctx context.Context) {
	s.mu.Lock()
	susp := s.reloadSusp
	var assets []string
	for a, unread := range s.haltUnread {
		if unread {
			assets = append(assets, a)
		}
	}
	s.mu.Unlock()
	if susp && s.rt.Store(AuditStream) != nil {
		err := s.loadSuspensions(ctx)
		s.mu.Lock()
		s.reloadSusp = false
		rebuilt := err == nil && s.node == AlarmSuspensionsUnknown
		if rebuilt {
			s.node = ""
		}
		s.mu.Unlock()
		switch {
		case rebuilt:
			s.rt.opt.Status.Raise("", AlarmSuspensionsRebuilt, "the audit database opened on a retry and the suspensions are rebuilt from it; runs are no longer held for asset-suspensions-unknown")
			s.settle(ctx)
		case err != nil:
			s.rt.opt.Status.Raise("", AlarmSuspensionsUnknown, "suspensions could not be rebuilt after the audit database opened; every run on this node stays stopped: "+err.Error())
		}
	}
	for _, a := range assets {
		halted, err := s.durableHalt(ctx, a)
		if errors.Is(err, errEvidenceNotOpen) {
			continue
		}
		s.mu.Lock()
		delete(s.haltUnread, a)
		if err == nil && !halted {
			delete(s.halted, a)
		}
		s.mu.Unlock()
		switch {
		case err != nil:
			s.rt.opt.Status.Raise(a, AlarmCollectionDisabled, "quarantine of "+a+" still unreadable after the evidence database opened; collection stays stopped: "+err.Error())
		case halted:
			s.rt.opt.Status.Raise(a, AlarmCollectionDisabled, "a quarantined run of this asset sent a line the register does not permit; collection stays stopped")
		}
	}
}
