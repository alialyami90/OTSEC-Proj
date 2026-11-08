package contract

// C13's bounds pinned by value (D6, D4-71). Each constant in
// contracts/netobs is checked against the value C13 states, so a change to a
// bound fails here until the contract text and this table change with it.
// Sources: docs/phase4/D4-c13-netobs.md §10 (the bounds table) and §7.1 (an
// alert's related list and explanation fields), and D1's values in D4-71
// for MaxBaselineBytes (§8 leaves it to code), period.overflow's saturation
// (§14 item 13) and the learner checkpoint's held starts (#561), and §8's
// detector checkpoint as #575 merged it: its windows (§7.3 item 3, §14
// item 16) and its own-session state, each part bounded, and the sum of
// their worst sizes strictly under the configuration record cap less its
// headroom with at least 10% to spare (§14 item 17, D1 in D4-72). Ground
// truth: GT-HAND, from the contract text and the rulings. Evidence class:
// desk.

import (
	"math"
	"testing"

	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/netobs"
)

func TestC13BoundsByValue(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
		source    string
	}{
		{"MaxChannelFrame", netobs.MaxChannelFrame, 64 << 10, "§10: 64 KiB"},
		{"MaxCitedFrames", netobs.MaxCitedFrames, 8, "§10"},
		{"MaxFrameBytes", netobs.MaxFrameBytes, 2048, "§10: 2,048"},
		{"MaxWireLen", netobs.MaxWireLen, 262144, "§10: 262,144 (256 KiB)"},
		{"MaxTextBytes", netobs.MaxTextBytes, 256, "§10: 256 original"},
		{"MaxTextEscaped", netobs.MaxTextEscaped, 1024, "§10: 1,024 escaped"},
		{"MaxCoverageBytes", netobs.MaxCoverageBytes, 2 << 10, "§10: 2 KiB"},
		{"MaxVLANs", netobs.MaxVLANs, 64, "§10, MaxCoverageBytes basis: 64 VLANs"},
		{"MaxInterfaces", netobs.MaxInterfaces, 8, "§10, MaxCoverageBytes basis: 8 interfaces"},
		{"MaxObjects", netobs.MaxObjects, 16, "§10"},
		{"MaxRedactions", netobs.MaxRedactions, 16, "§10: 16 per cited frame"},
		{"MaxAlertFlows", netobs.MaxAlertFlows, 4, "§10: alert citations, 4 flows"},
		{"MaxAlertFramesPerFlow", netobs.MaxAlertFramesPerFlow, 2, "§10: 2 frames each"},
		{"MaxRelated", netobs.MaxRelated, 32, "§7.1: related, ≤ 32"},
		{"ExplainMax", netobs.ExplainMax, 256, "§7.1: at most 256 bytes each"},
		{"DefaultCoalesceWindowS", netobs.DefaultCoalesceWindowS, 300, "§10: coalesce_window_s 300"},
		{"MinCoalesceWindowS", netobs.MinCoalesceWindowS, 60, "§10: bounded 60"},
		{"MaxCoalesceWindowS", netobs.MaxCoalesceWindowS, 3600, "§10: to 3600"},
		{"DefaultSAReplyTimeoutMS", netobs.DefaultSAReplyTimeoutMS, 5000, "§10: sa_reply_timeout_ms 5,000"},
		{"MinSAReplyTimeoutMS", netobs.MinSAReplyTimeoutMS, 1000, "§10: bounded 1,000"},
		{"MaxSAReplyTimeoutMS", netobs.MaxSAReplyTimeoutMS, 30000, "§10: to 30,000"},
		{"DefaultFlowIdleS", netobs.DefaultFlowIdleS, 60, "§10: flow_idle_s 60"},
		{"MinFlowIdleS", netobs.MinFlowIdleS, 10, "§10: bounded 10"},
		{"MaxFlowIdleS", netobs.MaxFlowIdleS, 600, "§10: to 600"},
		{"DefaultMaxPendingDNP3", netobs.DefaultMaxPendingDNP3, 4096, "§10: max_pending_dnp3 4,096"},
		{"MinMaxPendingDNP3", netobs.MinMaxPendingDNP3, 256, "§10: bounded 256"},
		{"MaxMaxPendingDNP3", netobs.MaxMaxPendingDNP3, 65536, "§10: to 65,536"},
		{"MaxBaselineBytes", netobs.MaxBaselineBytes, 512 << 10, "§8 with D1 in D4-71: 512 KiB"},
		{"MaxCaptureBytes", netobs.MaxCaptureBytes, 16536, "§7.1 with D4 on #564: 16,536"},
		{"MaxHeldStarts", netobs.MaxHeldStarts, 512, "D1 in D4-71: at most 512 starts"},
		{"MaxHeldStartBytes", netobs.MaxHeldStartBytes, 384, "D1 on #564 (#561): 384"},
		{"MaxLearnerCheckpointBytes", netobs.MaxLearnerCheckpointBytes, 721920, "D1 on #564 (#561): 705 KiB"},
		{"MaxDetectorWindows", netobs.MaxDetectorWindows, 96, "§7.3 item 3, §14 item 16: 96"},
		{"MaxDetectorWindowBytes", netobs.MaxDetectorWindowBytes, 12 << 10, "§8: 12 KiB"},
		{"MaxPendingSessions", netobs.MaxPendingSessions, 128, "§8, §14 item 17: 128"},
		{"MaxPendingSessionBytes", netobs.MaxPendingSessionBytes, 512, "§8: 512"},
		{"MaxTiedSessions", netobs.MaxTiedSessions, 256, "§8, §14 item 17: 256"},
		{"MaxTiedSessionBytes", netobs.MaxTiedSessionBytes, 128, "§8: 128"},
		{"MaxTakenSessions", netobs.MaxTakenSessions, 128, "§8 (D6's F1 on #575): 128"},
		{"MaxDetectorEndpoints", netobs.MaxDetectorEndpoints, 256, "§8: 256"},
		{"MaxDetectorEndpointBytes", netobs.MaxDetectorEndpointBytes, 192, "§8: 192"},
		{"MaxEndpointVLANs", netobs.MaxEndpointVLANs, 8, "§8: 8"},
		{"MaxDegradedIntervals", netobs.MaxDegradedIntervals, 64, "§8, §14 item 17: 64"},
		{"MaxDegradedIntervalBytes", netobs.MaxDegradedIntervalBytes, 128, "§8: 128"},
		{"MaxDetectorCheckpointBytes", netobs.MaxDetectorCheckpointBytes, 1354752, "§8, §14 item 17: 1,354,752"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, C13 %s says %d", c.name, c.got, c.source, c.want)
		}
	}
	// period.overflow saturates at 2^53 − 1, so every JSON reader holds it
	// exactly (§14 item 13, D4-71).
	if netobs.MaxOverflow != 1<<53-1 {
		t.Errorf("MaxOverflow = %d, C13 §14 item 13 says 2^53 − 1", uint64(netobs.MaxOverflow))
	}
	// The detector checkpoint fits one configuration record with room to
	// spare: under 1,507,328 bytes (the cap less its headroom) by at least
	// 10% of it (§14 item 17).
	const recordRoom = 1507328
	if got := config.RecordCap - config.RecordHeadroom; got != recordRoom {
		t.Errorf("the configuration record cap less its headroom is %d, C13 §14 item 17 says %d", got, recordRoom)
	}
	if b := netobs.MaxDetectorCheckpointBytes; b >= recordRoom || 10*(recordRoom-b) < recordRoom {
		t.Errorf("MaxDetectorCheckpointBytes %d leaves under 10%% of %d", b, recordRoom)
	}
	// MaxWireLen's basis (§10): far below the capture's 32-bit orig_len, so
	// a stored wire length can't wrap.
	if uint64(netobs.MaxWireLen) >= math.MaxUint32 {
		t.Errorf("MaxWireLen %d reaches the 32-bit orig_len", netobs.MaxWireLen)
	}
}
