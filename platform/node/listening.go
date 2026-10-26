package node

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/receive"
)

// AlarmListenerStopped: a Syslog listener stopped serving while the node
// runs. Nothing more is received on it until the node restarts.
const AlarmListenerStopped = "syslog-listener-stopped"

// Listening runs the node's Syslog listeners (P3-A4): one receive.Receiver
// per configured listener, committing to the listener's stream in the
// syslog database through a view that looks the open database up on every
// call, as the forwarders do, because Tick can replace a database's handle
// when it resumes one.
type Listening struct {
	rt        *Runtime
	receivers []*receive.Receiver
	bound     map[string]net.Addr
}

// NewListening checks every listener of the runtime's configuration and
// binds nothing. A syslog-tls listener's references are resolved first
// (Config.ListenerTLS), so a missing or bad file stops the node; nothing
// falls back to plaintext. The sender table comes from the C1 assets'
// inbound endpoints (receive.SendersFor).
func NewListening(rt *Runtime) (*Listening, error) {
	ls := &Listening{rt: rt, bound: map[string]net.Addr{}}
	for _, l := range rt.cfg.Listeners {
		ap, err := netip.ParseAddrPort(l.Address)
		if err != nil {
			return nil, fmt.Errorf("listener %s: address %q: %w", l.ID, l.Address, err)
		}
		senders, err := receive.SendersFor(rt.cfg.assets, l.Transport, int(ap.Port()))
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		stream := ListenerStream(l.ID)
		cfg := receive.Config{
			Node: rt.cfg.NodeID, ID: l.ID, Stream: stream,
			Transport: l.Transport, Address: l.Address, Target: l.Target,
			Plaintext: l.LabPlaintext,
			Senders:   senders,
			Log:       liveLog{rt, stream},
			Health:    healthSink{rt},
			Received:  rt.received,
		}
		if l.Transport == asset.SyslogTLS {
			if cfg.TLS, err = rt.cfg.ListenerTLS(l); err != nil {
				return nil, err
			}
		}
		r, err := receive.New(cfg)
		if err != nil {
			return nil, err
		}
		ls.receivers = append(ls.receivers, r)
	}
	return ls, nil
}

// Listen binds every listener. If one cannot bind, those already bound are
// closed and the node stops: a listener the configuration names is never
// silently absent.
func (ls *Listening) Listen() error {
	for i, r := range ls.receivers {
		a, err := r.Listen()
		if err != nil {
			ls.close(ls.receivers[:i])
			return err
		}
		ls.bound[r.Status().ID] = a
	}
	return nil
}

// Addr is the address listener id is bound to, or nil before Listen.
func (ls *Listening) Addr(id string) net.Addr { return ls.bound[id] }

// close releases bound listeners that will not serve.
func (ls *Listening) close(rs []*receive.Receiver) {
	for _, r := range rs {
		r.Close()
	}
}

// Run serves every listener until ctx ends, and returns once each has
// committed what it read or its grace period has passed. A listener that
// stops on its own raises AlarmListenerStopped; the others keep serving.
func (ls *Listening) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, r := range ls.receivers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.Serve(ctx)
			if ctx.Err() == nil {
				detail := "the listener stopped serving; nothing more is received on it until the node restarts"
				if err != nil {
					detail += ": " + err.Error()
				}
				ls.rt.opt.Status.RaiseTarget("listener "+r.Status().ID, AlarmListenerStopped, detail)
			}
		}()
	}
	wg.Wait()
}

// Publish records every listener's state in status.
func (ls *Listening) Publish() {
	if len(ls.receivers) == 0 {
		return
	}
	m := make(map[string]ListenerStatus, len(ls.receivers))
	for _, r := range ls.receivers {
		m[r.Status().ID] = listenerStatus(r.Status())
	}
	ls.rt.opt.Status.SetListeners(m)
}

// ListenerStatus is one Syslog listener as node status shows it
// (receive.Status). LastErr is the listener's error text, which never holds
// message content.
type ListenerStatus struct {
	Transport          asset.Transport  `json:"transport"`
	Address            string           `json:"address"`
	Open               bool             `json:"open"`
	Connections        int              `json:"connections"`
	UnknownConnections int              `json:"unknown_connections,omitempty"`
	Received           int64            `json:"received"`
	Stored             int64            `json:"stored"`
	LastMessage        time.Time        `json:"last_message,omitzero"`
	Dropped            map[string]int64 `json:"dropped,omitempty"`
	Refused            map[string]int64 `json:"refused,omitempty"`
	Truncated          int64            `json:"truncated,omitempty"`
	Misframed          int64            `json:"misframed,omitempty"`
	Discarded          int64            `json:"discarded_bytes,omitempty"`
	UnknownSenders     int              `json:"unknown_senders,omitempty"`
	UnknownOverflow    bool             `json:"unknown_overflow,omitempty"`
	Held               bool             `json:"held,omitempty"`
	LastErr            string           `json:"last_error,omitempty"`
}

func listenerStatus(s receive.Status) ListenerStatus {
	nonZero := func(m map[string]int64) map[string]int64 {
		out := map[string]int64{}
		for k, v := range m {
			if v != 0 {
				out[k] = v
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return ListenerStatus{
		Transport: s.Transport, Address: s.Address, Open: s.Open,
		Connections: s.Connections, UnknownConnections: s.UnknownConnections,
		Received: s.Received, Stored: s.Stored, LastMessage: s.LastMessage,
		Dropped: nonZero(s.Dropped), Refused: nonZero(s.Refused),
		Truncated: s.Truncated, Misframed: s.Misframed, Discarded: s.Discarded,
		UnknownSenders: s.UnknownSenders, UnknownOverflow: s.UnknownOverflow,
		Held: s.Held, LastErr: s.LastErr,
	}
}

// SortedListeners returns m's listener IDs in order.
func SortedListeners(m map[string]ListenerStatus) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// liveLog appends a listener's batches to its stream through the Log of
// the database open now. While that database is not open, or is in a mode
// that accepts no events, it refuses the batch and nothing is written, so
// the listener holds a stream batch (refuse-new) or drops and counts a
// datagram batch (drop-and-count), as its C5 class says.
type liveLog struct {
	rt     *Runtime
	stream c5.StreamID
}

func (l liveLog) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	_, log, mode := l.rt.view(l.rt.dbFor(l.stream))
	if log == nil {
		return nil, fmt.Errorf("node: the database of %s is not open", l.stream)
	}
	if !mode.AcceptsEvents() {
		return nil, fmt.Errorf("node: the database of %s is in mode %s, which accepts no events", l.stream, mode)
	}
	return log.AppendBatch(ctx, recs)
}
