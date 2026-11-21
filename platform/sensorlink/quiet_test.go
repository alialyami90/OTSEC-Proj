package sensorlink

import (
	"net/netip"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// N-18's node legs (C13 0.3 §12; W-7's case 4 as CH-57 amends it, D6's
// B6 on #673, and D6's variant), the intake's side, desk only: tied own
// runs, each followed by a quiet spell on every capture interface longer
// than flow_idle_s + g + one SensorTickInterval and more, the node's
// TickHold run after it, then one frame on another flow, after which the
// sensor writes the ends it held (idle for UDP, fin for TCP) and then that
// frame's flow start. The ends are read before any later flow start, so
// no open entry has expired (CH-57): each ties to its session, and
// OpenExpired does not rise. Mutants (the PR's body): the open table's
// expiry on the node's wall clock alone, as before CH-57; for D6's
// variant, expiry on any later record. The detector's half (no
// unjudged ... :incomplete) is C13 0.3's detector, INT-D4b's: on main,
// own-session-outside-record judges flow starts only, so an untied end
// raises nothing there.

// quietRun is one own run of the spell: its port, its endpoint's port and
// transport.
type quietRun struct {
	sport, dport int
	l4           string
}

// quietFlow is the record of run q's flow: its start, or its end (idle for
// UDP, fin for TCP), captured at at.
func quietFlow(q quietRun, at time.Time, end bool) *netobs.Observation {
	o := ownFlow02(0, q.sport, at, end)
	o.IP.L4, o.IP.Dport = q.l4, ptr(q.dport)
	if q.l4 == "udp" {
		o.Direction = netobs.DirectionNone
		if end {
			o.Flow.End, o.Flow.SynOnly = "idle", nil
		}
	}
	return o
}

// TestQuietSpellOwnRunsNoAlert: two tied own runs, one SNMPv3 over UDP and
// one Telnet closed by FIN, and D6's variant with an earlier-due third flow
// before one spell.
func TestQuietSpellOwnRunsNoAlert(t *testing.T) {
	for name, third := range map[string]bool{"two runs": false, "D6's variant, an earlier-due third flow": true} {
		t.Run(name, func(t *testing.T) {
			r, s, _ := t13(t, 30*time.Second, nil, nil)
			runs := []quietRun{{40011, 161, "udp"}, {40012, 23, "tcp"}}
			if third {
				runs = append([]quietRun{{40013, 23, "tcp"}}, runs...) // dispatched first: due first
			}
			for i, q := range runs {
				req := "req-" + itoa(i+1)
				ep := netip.AddrPortFrom(endpoint.Addr(), uint16(q.dport))
				if err := r.l.Dispatch(bg, HoldRun{RequestID: req, AssetID: relay, Endpoint: ep, L4: q.l4}); err != nil {
					t.Fatal(err)
				}
				from := r.now()
				s.write(quietFlow(q, s.now(), false))
				s.pass(time.Second)
				if _, err := r.l.Result(bg, req, Session{InvocationID: inv(i + 1), StartedAt: from, EndedAt: r.now(), Connected: true,
					Local: netip.AddrPortFrom(netip.MustParseAddr(nodeAddr), uint16(q.sport)), ConnectedAt: from}); err != nil {
					t.Fatal(err)
				}
				s.pass(5 * time.Second)
			}
			s.pass(time.Duration(netobs.DefaultFlowIdleS)*time.Second + 30*time.Second + 10*time.Second + 2*time.Minute)
			r.l.TickHold(bg)
			for _, q := range runs {
				s.write(quietFlow(q, s.now(), true))
			}
			s.write(obs02(0)) // the frame on another flow, after the ends
			for i, q := range runs {
				os := r.fromPort(q.sport)
				if len(os) != 2 {
					t.Fatalf("run %d: %d records stored, want its start and its end", i+1, len(os))
				}
				for _, o := range os {
					if ps := o.Node.PlatformSession; ps == nil || ps.InvocationID != inv(i+1) || ps.Tie != TieConnection {
						t.Fatalf("run %d: a record not tied to its session: %+v", i+1, o.Node)
					}
				}
			}
			if st := r.l.Stats().Hold; st.OpenExpired != 0 || st.Open != 0 {
				t.Fatalf("hold %+v: want no entry expired and none left open", st)
			}
		})
	}
}
