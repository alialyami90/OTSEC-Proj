package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/receive"
)

// AlarmListenerStopped: a Syslog listener stopped serving while the node
// runs. Nothing more is received on it until the node restarts.
const AlarmListenerStopped = "syslog-listener-stopped"

// AlarmListenerCertExpiring: a syslog-tls listener's certificate expires
// within ListenerCertWarning, or has expired. The listener keeps presenting
// it until the node restarts with a new one, and senders that check it
// refuse it once it has expired (A4 on #154).
const AlarmListenerCertExpiring = "syslog-listener-certificate-expiring"

// ListenerCertWarning is how long before a listener certificate's NotAfter
// AlarmListenerCertExpiring is raised.
const ListenerCertWarning = 30 * 24 * time.Hour

// AlarmTargetSmallForListeners: the node has listeners and a target's
// max_message_octets is below RecommendedTargetOctets, so a received
// message whose text does not fit is forwarded with its hash and length
// only (C6, forward.text-omitted). Raised at every start.
const AlarmTargetSmallForListeners = "target-small-for-listeners"

// RecommendedTargetOctets fits a forwarded event holding a received
// message of streamMaxMessage bytes: its text and the subject and value a
// dialect takes from it (RTAC: up to renderedFieldMax bytes each), escaped
// or carried as base64, take at most twice their length, and the rest of
// the header and structured data less than 2048 octets (A4 on #169: an
// 8147-byte RTAC frame renders at 21161 octets).
const RecommendedTargetOctets = 2*(streamMaxMessage+2*renderedFieldMax) + 2048

// renderedFieldMax is the longest subj or val C6 renders from a received
// message's dialect fields.
const renderedFieldMax = 1024

// Listening runs the node's Syslog listeners (P3-A4): one receive.Receiver
// per configured listener, committing to the listener's stream in the
// syslog database through a view that looks the open database up on every
// call, as the forwarders do, because Tick can replace a database's handle
// when it resumes one.
type Listening struct {
	rt        *Runtime
	receivers []*receive.Receiver
	bound     map[string]net.Addr
	plaintext map[string]bool
	sizing    map[string]ListenerSizing
	// unknown counts the record bytes stored from unknown senders since
	// start, per listener (liveLog); spent is what they stored in the
	// window before start, as counted from the stream (unknownSpent), or
	// the whole budget when it could not be counted.
	unknown map[string]*atomic.Int64
	spent   map[string]int64
	// notAfter is a syslog-tls listener's certificate expiry; watch decides
	// when its alarm ("expiring" or "expired") is raised.
	notAfter map[string]time.Time
	watch    map[string]*certWatch

	// held are the syslog-tls listeners whose certificate was outside its
	// validity period at start (HR-13, D4-11). They have no receiver: no
	// socket is bound and nothing is read until Publish finds the period
	// valid. mu guards receivers, held and the Run state below, because
	// Publish can add a receiver while Run is serving.
	mu        sync.Mutex
	held      []*heldListener
	runCtx    context.Context
	wg        sync.WaitGroup
	runStop   bool
	heldAtRun bool
}

// heldListener is a syslog-tls listener not started because its certificate
// is outside its validity period. cfg lacks only the TLS configuration; the
// certificate is the one loaded at start and is never read again.
type heldListener struct {
	l     Listener
	cfg   receive.Config
	creds *listenerCreds
	state string
	watch certWatch
	// failed is the start error already raised, so a listener that cannot
	// bind raises it once.
	failed string
}

// NewListening checks every listener of the runtime's configuration and
// binds nothing. A syslog-tls listener's references are resolved first
// (Config.ListenerTLS), so a missing or bad file stops the node; nothing
// falls back to plaintext. A certificate outside its validity period is the
// one fault that does not stop the node (HR-13, D4-11): that listener is
// held back with AlarmListenerHeldBack, binds nothing and reads nothing, and
// Publish starts it once the period is valid. The sender table comes from the C1 assets'
// inbound endpoints (receive.SendersFor), and each listener's unknown
// budget from its class quota (Config.ListenerSizings), less what unknown
// senders stored on its stream in the window before this start, so a
// restart does not refill it (D3-3). If that cannot be counted, the
// budget starts empty and AlarmUnknownSpentUncounted is raised.
func NewListening(rt *Runtime) (*Listening, error) {
	ls := &Listening{rt: rt, bound: map[string]net.Addr{}, plaintext: map[string]bool{},
		unknown: map[string]*atomic.Int64{}, spent: map[string]int64{}, notAfter: map[string]time.Time{}, watch: map[string]*certWatch{}}
	if len(rt.cfg.Listeners) == 0 {
		return ls, nil
	}
	sizing, err := rt.cfg.ListenerSizings()
	if err != nil {
		return nil, err
	}
	ls.sizing = sizing
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
		unknown := new(atomic.Int64)
		cfg := receive.Config{
			Node: rt.cfg.NodeID, ID: l.ID, Stream: stream,
			Transport: l.Transport, Address: l.Address, Target: l.Target,
			Plaintext: l.Plaintext,
			Senders:   senders,
			Log:       liveLog{rt, stream, unknown},
			Health:    healthSink{rt},
			Received:  rt.received,
			Limits:    sizing[l.ID].limits(),
		}
		// The receiver splits a batch at the caps of the Log behind it, which
		// are the ones the node built that Log with (C5 0.4, 0.5).
		if d := rt.dbFor(stream); d != nil {
			g := groupFor(d.spec, rt.opt.Group)
			cfg.MaxCommitBytes, cfg.MaxCommitRecords = g.CommitBytes(), g.CommitRecords()
		}
		spent, err := unknownSpent(context.Background(), rt.Store(stream), stream, cfg.Limits.UnknownWindow, rt.opt.Now())
		if err != nil {
			// receive starts a budget empty at UnknownBytes.
			spent = cfg.Limits.UnknownBytes
			rt.opt.Status.Raise("", AlarmUnknownSpentUncounted, fmt.Sprintf(
				"listener %s: what unknown senders stored in the last %s could not be counted (%v), so their budget starts empty and their messages are dropped until it refills at %d bytes an hour. Known senders are not affected",
				l.ID, cfg.Limits.UnknownWindow, err, cfg.Limits.UnknownBytes))
		}
		cfg.UnknownSpent = spent
		var held *heldListener
		if l.Transport == asset.SyslogTLS {
			creds, err := rt.cfg.loadListener(l)
			if err != nil {
				return nil, err
			}
			if _, ls.notAfter[l.ID], err = leafPeriod(creds.cert); err != nil {
				return nil, fmt.Errorf("listener %s: credential: %w", l.ID, err)
			}
			switch cfg.TLS, err = serverTLS(l, creds); {
			case err == nil:
			case errors.Is(err, receive.ErrCertificatePeriod):
				held = &heldListener{l: l, cfg: cfg, creds: creds}
			default:
				return nil, err
			}
		}
		if held != nil {
			ls.held = append(ls.held, held)
			ls.plaintext[l.ID] = l.Plaintext
			ls.unknown[l.ID] = unknown
			ls.spent[l.ID] = spent
			ls.heldAtRun = true
			ls.alarmHeld(held, rt.opt.Now())
			continue
		}
		r, err := receive.New(cfg)
		if err != nil {
			return nil, err
		}
		ls.receivers = append(ls.receivers, r)
		ls.plaintext[l.ID] = l.Plaintext
		ls.unknown[l.ID] = unknown
		ls.spent[l.ID] = spent
	}
	return ls, nil
}

// leafOf is the listener certificate of a server TLS configuration.
func leafOf(certs []tls.Certificate) (*x509.Certificate, error) {
	if len(certs) == 0 || len(certs[0].Certificate) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	if certs[0].Leaf != nil {
		return certs[0].Leaf, nil
	}
	return x509.ParseCertificate(certs[0].Certificate[0])
}

// Listen binds every listener. If one cannot bind, those already bound are
// closed and the node stops: a listener the configuration names is never
// silently absent. Once all are bound, each plaintext listener is recorded
// as node.posture_change, at every start (D3-5).
func (ls *Listening) Listen() error {
	for i, r := range ls.receivers {
		a, err := r.Listen()
		if err != nil {
			ls.close(ls.receivers[:i])
			return err
		}
		ls.bound[r.Status().ID] = a
	}
	for _, r := range ls.receivers {
		if s := r.Status(); ls.plaintext[s.ID] {
			ls.rt.audit(context.Background(), audit.ActionNodePostureChange, audit.OutcomeInfo, ReasonPlaintextListener,
				fmt.Sprintf("listener %s receives %s on %s in plaintext: no sender authentication or integrity (D3-5)", s.ID, s.Transport, ls.bound[s.ID]))
		}
	}
	ls.checkTargets()
	return nil
}

// checkTargets raises AlarmTargetSmallForListeners for each target too
// small to carry a received message's text whole. It is a warning: such a
// message is still forwarded, with its hash and length (C6).
func (ls *Listening) checkTargets() {
	if len(ls.receivers) == 0 {
		return
	}
	for _, t := range ls.rt.cfg.targets {
		if t.MaxMessageOctets < RecommendedTargetOctets {
			ls.rt.opt.Status.RaiseTarget(t.Name, AlarmTargetSmallForListeners,
				fmt.Sprintf("max_message_octets is %d; a received message whose text does not fit is forwarded with its hash and length only (forward.text-omitted). %d octets carries any received message of up to %d bytes whole",
					t.MaxMessageOctets, RecommendedTargetOctets, streamMaxMessage))
		}
	}
}

// checkExpiry raises AlarmListenerCertExpiring when a listener's
// certificate comes within CertWarning of expiry, again when it has expired,
// and then every CertAlarmRepeat while the listener runs: a running
// listener is never stopped at expiry (D4-11 items 4 and 9).
func (ls *Listening) checkExpiry(id string, now time.Time) {
	na, ok := ls.notAfter[id]
	if !ok {
		return
	}
	state := certState(na, now)
	w := ls.watch[id]
	if w == nil {
		w = &certWatch{}
		ls.watch[id] = w
	}
	if !w.due(state, now) {
		return
	}
	var detail string
	if state == "expired" {
		detail = fmt.Sprintf("the listener certificate expired at %s; the listener keeps running, and senders that check it refuse it. Replace %s.crt and .key and restart the node", na.UTC().Format(time.RFC3339), ls.credRef(id))
	} else {
		detail = fmt.Sprintf("the listener certificate expires at %s; replace %s.crt and .key and restart the node before then", na.UTC().Format(time.RFC3339), ls.credRef(id))
	}
	ls.rt.opt.Status.RaiseTarget("listener "+id, AlarmListenerCertExpiring, detail)
}

// alarmHeld raises AlarmListenerHeldBack for h when its state changes and
// every CertAlarmRepeat while it lasts.
func (ls *Listening) alarmHeld(h *heldListener, now time.Time) {
	nb, na, _ := leafPeriod(h.creds.cert)
	h.state = heldState(nb, na, time.Now())
	if !h.watch.due(h.state, now) {
		return
	}
	ls.rt.opt.Status.RaiseTarget("listener "+h.l.ID, AlarmListenerHeldBack, fmt.Sprintf(
		"the listener certificate is %s: %s. The listener is not bound and receives nothing; the rest of the node runs. It starts when the period is valid; to replace the certificate, replace %s.crt and .key and restart the node",
		h.state, periodDetail("it", nb, na), h.l.TLS.CredentialRef))
}

// release judges each held listener's loaded certificate again, by the same
// clock as at start (D4-11 item 11), and starts the listener once the
// period is valid: it binds, then serves if Run is serving. A listener that
// cannot bind stays held and raises AlarmListenerStopped once for that
// error. It is called from Publish.
func (ls *Listening) release(now time.Time) {
	ls.mu.Lock()
	held := slices.Clone(ls.held)
	ls.mu.Unlock()
	for _, h := range held {
		tlsCfg, err := serverTLS(h.l, h.creds)
		if errors.Is(err, receive.ErrCertificatePeriod) {
			ls.alarmHeld(h, now)
			continue
		}
		if err != nil {
			continue
		}
		cfg := h.cfg
		cfg.TLS = tlsCfg
		// The check that Run has not ended, the bind and the hand-over to
		// Run are one step under mu: a listener that binds after Run
		// returned would never be served or closed (B6 on #290).
		ls.mu.Lock()
		if ls.runStop {
			ls.mu.Unlock()
			return
		}
		r, err := receive.New(cfg)
		var a net.Addr
		if err == nil {
			if a, err = r.Listen(); err != nil {
				r.Close()
			}
		}
		if err != nil {
			ls.mu.Unlock()
			if h.failed != err.Error() {
				h.failed = err.Error()
				ls.rt.opt.Status.RaiseTarget("listener "+h.l.ID, AlarmListenerStopped, "the listener's certificate period is valid, but it could not start: "+err.Error()+"; it stays held back and is tried again")
			}
			continue
		}
		ls.held = slices.DeleteFunc(ls.held, func(x *heldListener) bool { return x == h })
		ls.receivers = append(ls.receivers, r)
		ls.bound[h.l.ID] = a
		if ls.runCtx != nil {
			ls.serve(r)
		}
		ls.mu.Unlock()
	}
}

// credRef is listener id's credential reference.
func (ls *Listening) credRef(id string) string {
	for _, l := range ls.rt.cfg.Listeners {
		if l.ID == id && l.TLS != nil {
			return l.TLS.CredentialRef
		}
	}
	return "the credential"
}

// ReasonPlaintextListener is the reason_code of the node.posture_change
// record a plaintext listener gets at start.
const ReasonPlaintextListener = "plaintext_listener"

// Addr is the address listener id is bound to, or nil before Listen.
func (ls *Listening) Addr(id string) net.Addr {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.bound[id]
}

// close releases bound listeners that will not serve.
func (ls *Listening) close(rs []*receive.Receiver) {
	for _, r := range rs {
		r.Close()
	}
}

// Run serves every listener until ctx ends, and returns once each has
// committed what it read or its grace period has passed. A listener that
// stops on its own raises AlarmListenerStopped; the others keep serving.
// While a listener is held back (certificate period, D4-11) Run keeps
// waiting for ctx, because Publish can still start it.
func (ls *Listening) Run(ctx context.Context) {
	ls.mu.Lock()
	ls.runCtx = ctx
	for _, r := range ls.receivers {
		ls.serve(r)
	}
	waitForCtx := ls.heldAtRun
	ls.mu.Unlock()
	if waitForCtx {
		<-ctx.Done()
	}
	ls.mu.Lock()
	ls.runStop = true
	ls.mu.Unlock()
	ls.wg.Wait()
}

// serve starts r's Serve in a goroutine counted by ls.wg. mu is held.
func (ls *Listening) serve(r *receive.Receiver) {
	ctx := ls.runCtx
	ls.wg.Add(1)
	go func() {
		defer ls.wg.Done()
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

// Publish records every listener's state in status, and raises
// AlarmListenerCertExpiring when a certificate is near or past expiry.
// It is called from one goroutine at a time.
func (ls *Listening) Publish() {
	now := ls.rt.opt.Now()
	ls.release(now)
	ls.mu.Lock()
	receivers := slices.Clone(ls.receivers)
	held := slices.Clone(ls.held)
	ls.mu.Unlock()
	if len(receivers) == 0 && len(held) == 0 {
		return
	}
	m := make(map[string]ListenerStatus, len(receivers)+len(held))
	for _, h := range held {
		id := h.l.ID
		sz := ls.sizing[id]
		m[id] = ListenerStatus{Transport: h.l.Transport, Address: h.l.Address, HeldBack: h.state,
			Unknown: &UnknownShare{HourlyBytes: sz.UnknownBytes, BoundBytes: sz.UnknownBound,
				QuotaBytes: sz.Quota, OutageHours: sz.OutageHours, SpentAtStart: ls.spent[id]},
			CertNotAfter: ls.notAfter[id].UTC()}
	}
	for _, r := range receivers {
		id := r.Status().ID
		s := listenerStatus(r.Status())
		s.Plaintext = ls.plaintext[id]
		sz := ls.sizing[id]
		s.Unknown = &UnknownShare{
			HourlyBytes: sz.UnknownBytes, BoundBytes: sz.UnknownBound,
			QuotaBytes: sz.Quota, OutageHours: sz.OutageHours,
			StoredBytes: ls.unknown[id].Load(), SpentAtStart: ls.spent[id],
		}
		if na, ok := ls.notAfter[id]; ok {
			s.CertNotAfter = na.UTC()
			ls.checkExpiry(id, now)
		}
		m[id] = s
	}
	ls.rt.opt.Status.SetListeners(m)
}

// ListenerStatus is one Syslog listener as node status shows it
// (receive.Status). LastErr is the listener's error text, which never holds
// message content.
type ListenerStatus struct {
	Transport asset.Transport `json:"transport"`
	Address   string          `json:"address"`
	// Plaintext: the listener is syslog-tcp or syslog-udp, with no sender
	// authentication or integrity (D3-5).
	Plaintext          bool             `json:"plaintext,omitempty"`
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
	// Unknown is the unknown senders' storage: their budget and bound
	// (ListenerSizings) and what they stored since start (HR-11, D3-3).
	Unknown *UnknownShare `json:"unknown,omitempty"`
	// CertNotAfter is a syslog-tls listener's certificate expiry.
	CertNotAfter time.Time `json:"certificate_not_after,omitzero"`
	// HeldBack is "expired" or "not-yet-valid" while the listener's
	// certificate is outside its validity period: nothing is bound and
	// nothing is received (HR-13, D4-11). Empty otherwise.
	HeldBack string `json:"held_back,omitempty"`
}

// UnknownShare is a listener's unknown-sender storage. BoundBytes is what
// the unknown senders of every listener of its class together may store
// over OutageHours, at most a quarter of QuotaBytes, the class quota.
type UnknownShare struct {
	HourlyBytes int64 `json:"hourly_bytes"`
	BoundBytes  int64 `json:"bound_bytes"`
	QuotaBytes  int64 `json:"quota_bytes"`
	OutageHours int64 `json:"outage_hours"`
	StoredBytes int64 `json:"stored_bytes"`
	// SpentAtStart is what the budget started spent by: what unknown
	// senders stored in the hour before start, or HourlyBytes when that
	// could not be counted (AlarmUnknownSpentUncounted).
	SpentAtStart int64 `json:"spent_at_start_bytes"`
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
	// unknown counts the event bytes stored from unknown senders: records
	// that carry asset-unresolved, which receive's unknown budget counts.
	unknown *atomic.Int64
}

func (l liveLog) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	_, log, mode := l.rt.view(l.rt.dbFor(l.stream))
	if log == nil {
		return nil, fmt.Errorf("node: the database of %s is not open", l.stream)
	}
	if !mode.AcceptsEvents() {
		return nil, fmt.Errorf("node: the database of %s is in mode %s, which accepts no events", l.stream, mode)
	}
	rs, err := log.AppendBatch(ctx, recs)
	if err == nil && l.unknown != nil {
		var n int64
		for _, rec := range recs {
			if unresolved(rec.Event) {
				n += int64(len(rec.Event))
			}
		}
		l.unknown.Add(n)
	}
	return rs, err
}

// unresolved reports whether a C4 event carries asset-unresolved.
func unresolved(ev []byte) bool {
	var e struct {
		Flags []string `json:"flags"`
	}
	if json.Unmarshal(ev, &e) != nil {
		return false
	}
	return slices.Contains(e.Flags, "asset-unresolved")
}
