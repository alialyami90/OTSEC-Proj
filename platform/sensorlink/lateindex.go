package sensorlink

import (
	"context"
	"slices"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The late index, part (e) of the hold (docs/phase4/D5-sensor-node.md
// section 1.6). A record can arrive after its session's result with no
// break: the engine may write a connection's record only at its end, and a
// break of at most backlog_tie_s keeps ties under the made_utc check.
//
//   - Only a session released with no flow tied, none left waiting and its
//     window not refused for skew enters it (Result).
//   - An entry ties one flow and is then spent, under Result's rules: the
//     5-tuple for a 0.9 result that connected, the first flow in the
//     window for a 0.8 result, a failed dial's window. A refusal spends it
//     too. A tied flow not ended joins the open table (part (d)).
//   - Each tie passes the skew gate as a waiting run's does
//     (laterRefusal): a cause that stands, the window's offsets at Dispatch
//     and at Result, and the capture floor.
//   - Past HoldLateHorizon after the session's end, on the node's wall
//     clock, a matching record commits untied, counted late_untied
//     (horizon). Past HoldLateEntries the oldest entry gives way, counted
//     late_untied (evicted); one evicted inside its horizon raises
//     sensor-late-index-short once a stretch.
//   - It is memory only, and starts empty at each start: an entry rebuilt
//     at a start was recorded before it, and would tie nothing (D5's choice
//     in section 1.6).
//
// The 0.2 intake only, as the skew gate is: off it, nothing enters.

// Test seams, each false in the node: lateIndexOff, a node with no late
// index; lateIndexAll, one that indexes every session released, tied or
// not; lateNotSpent, one whose entry ties every flow that matches it.
var lateIndexOff, lateIndexAll, lateNotSpent bool

// lateAdd puts e in the index, the oldest out past HoldLateEntries. The
// caller holds cmu.
func (l *Link) lateAdd(e lateEntry) {
	h := l.hold
	if !l.skewOn() || lateIndexOff {
		return
	}
	h.late = append(h.late, e)
	short := false
	for len(h.late) > HoldLateEntries {
		old := h.late[0]
		h.late = slices.Delete(h.late, 0, 1)
		h.stats.LateEvicted++
		if !h.now().After(old.s.EndedAt.Add(HoldLateHorizon)) {
			short = true
		}
	}
	switch {
	case short && !h.lateShort:
		h.lateShort = true
		l.lateShortDue.Store(true)
	case !short:
		h.lateShort = false // the stretch ends at an add that evicts nothing inside its horizon
	}
}

// lateFind is the newest entry a record of st's flow, on key k, matches,
// or -1.
func (l *Link) lateFind(k FlowKey, st *netobs.Observation) int {
	h, g := l.hold, l.hold.grace()
	start := l.toNode(flowStart(st)) // t_sensor + E
	for i := len(h.late) - 1; i >= 0; i-- {
		e := h.late[i]
		if e.run.Endpoint != k.Peer || e.run.L4 != k.L4 || !in(start, e.s.StartedAt.Add(-g), e.s.EndedAt.Add(g)) {
			continue
		}
		switch {
		case e.s.Connected && e.s.Local.IsValid():
			if k.Node != e.s.Local {
				continue // the 5-tuple of a 0.9 result
			}
		case !e.s.Connected:
			if k.L4 != "tcp" {
				continue // a failed dial's window
			}
		}
		return i
	}
	return -1
}

// lateTie ties st's record hr by the late index, or reports false so the
// caller commits it untied. The caller holds cmu.
func (l *Link) lateTie(ctx context.Context, st *netobs.Observation, hr HeldRecord, k FlowKey) bool {
	h := l.hold
	i := l.lateFind(k, st) // empty off the 0.2 path
	if i < 0 {
		return false
	}
	e := h.late[i]
	if !lateNotSpent {
		h.late = slices.Delete(h.late, i, i+1) // spent: it ties one flow, or refuses it
	}
	if h.now().After(e.s.EndedAt.Add(HoldLateHorizon)) {
		h.stats.LateHorizon++
		return false
	}
	if c := l.laterRefusal(e.stamps, flowStart(st)); c != "" {
		l.countRefusal(c)
		if l.marks(c) {
			if b, err := nodeBody(hr.Observation, "skewed", true); err == nil {
				hr.Observation = b
			}
		}
		l.commitOne(ctx, hr, nil, "")
		return true
	}
	tie := TieWindow
	if e.s.Connected && e.s.Local.IsValid() {
		tie = TieConnection
	}
	if !isEnd(st) {
		// The tied flow is not ended: it joins the open table, written
		// first, so its later records tie to the same session (part (d)).
		prev := slices.Clone(h.open)
		evicted := h.addOpen(OpenFlow{Key: k, InvocationID: e.s.InvocationID, Tie: tie, AssetID: e.run.AssetID,
			Expires:  h.now().Add(time.Duration(st.Coverage.Settings.FlowIdleS)*time.Second + h.grace()),
			FlowIdle: int64(st.Coverage.Settings.FlowIdleS), Off: h.off(), Live: true})
		if h.last != nil && h.save(ctx, *h.last) != nil {
			h.open = prev
			l.commitOne(ctx, hr, nil, "")
			return true
		}
		h.stats.OpenEvicted += evicted
	}
	h.stats.Tied++
	h.stats.LateTied++
	l.commitOne(ctx, hr, &netobs.PlatformSession{InvocationID: e.s.InvocationID, Tie: tie}, e.run.AssetID)
	return true
}
