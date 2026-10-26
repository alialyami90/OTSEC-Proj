// Command otsec is the node binary (P2-A5).
//
//	otsec node   -config <file>   run the node: store, scheduler, status
//	otsec assets -config <file>   list the configured assets
//	otsec events -config <file> [-stream <id>] [-after <seq>] [-limit <n>] [-json]
//	otsec health -config <file>   show node status, database modes and alarms
//	otsec install -config <file> [-collector-exe <path> -collector-config <file>]   Windows, elevated
//	otsec uninstall                                                                 Windows, elevated
//
// assets, events and health are read-only: they open the store read-only
// beside a running node (store.OpenReadOnly) and never write to it, to the
// configuration or to any device. They are the minimum interface the slice
// needs; an HTML view comes only after the slice passes end to end, through
// the impeccable skill (P2-A5).
//
// No subcommand causes device I/O on its own: only the node's scheduler
// asks the collector for a run, under a schedule principal (AP-15).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/store"
	"otsec.local/otsec/platform/winsvc"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  otsec node   -config <file>
  otsec assets -config <file>
  otsec events -config <file> [-stream <id>] [-after <seq>] [-limit <n>] [-json]
  otsec health -config <file>
  otsec install -config <file> [-collector-exe <path> -collector-config <file>]
  otsec uninstall
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("otsec "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "node configuration file (otsec.nodeconfig/0.1)")
	stream := fs.String("stream", "", "events: the stream to read; empty lists the streams")
	after := fs.Uint64("after", 0, "events: read events with seq above this")
	limit := fs.Int("limit", 50, "events: at most this many events")
	asJSON := fs.Bool("json", false, "events: print the stored C4 events as JSON lines")
	collectorExe := fs.String("collector-exe", "", "install: the collector binary; empty installs the node service only")
	collectorConfig := fs.String("collector-config", "", "install: the collector's configuration, required with -collector-exe")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if args[0] == "uninstall" && *configPath == "" && fs.NArg() == 0 {
		return report(stderr, winsvc.Uninstall())
	}
	if *configPath == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cfg, err := node.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch args[0] {
	case "node":
		err = runNode(ctx, cfg, stderr)
	case "install":
		exe, xerr := os.Executable()
		if xerr != nil {
			return report(stderr, xerr)
		}
		err = winsvc.Install(winsvc.InstallOptions{NodeExe: exe, CollectorExe: *collectorExe, Config: *configPath, CollectorConfig: *collectorConfig})
	case "assets":
		err = assets(cfg, stdout)
	case "events":
		err = events(ctx, cfg, stdout, c5.StreamID(*stream), c5.Seq(*after), *limit, *asJSON)
	case "health":
		err = health(ctx, cfg, stdout)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	return report(stderr, err)
}

func report(stderr io.Writer, err error) int {
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// runNode runs the node: under the Windows SCM when the SCM started the
// process, otherwise in the foreground until SIGINT or SIGTERM.
func runNode(ctx context.Context, cfg *node.Config, stderr io.Writer) error {
	if ok, err := winsvc.IsService(); err != nil {
		return err
	} else if ok {
		return winsvc.Run(func(ctx context.Context, oslog func(string)) error { return node.Run(ctx, cfg, oslog) })
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return node.Run(ctx, cfg, func(s string) { fmt.Fprintln(stderr, s) })
}

func assets(cfg *node.Config, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ASSET\tFAMILY\tFIRMWARE_ID\tSERIAL\tENDPOINT\tTARGET\tSECURITY\tBINDING")
	for _, a := range cfg.AssetRecords() {
		attr := map[string]string{}
		for _, at := range a.Attributes {
			attr[at.Name] = at.Value + " (" + string(at.Confidence) + ")"
		}
		eps := a.Endpoints
		if len(eps) == 0 {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t-\t-\t-\t%s\n", a.AssetID, orDash(attr["product_family"]), orDash(attr["firmware_id"]), orDash(attr["serial_number"]), a.IdentityBinding.Method)
		}
		for _, ep := range eps {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s %s:%d\t%s\t%s\t%s\n", a.AssetID, orDash(attr["product_family"]), orDash(attr["firmware_id"]),
				orDash(attr["serial_number"]), ep.Transport, ep.Host, ep.Port, ep.Target, ep.DownstreamSecurity.Level, a.IdentityBinding.Method)
		}
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// hidden reports whether events refuses to print a stream: the audit
// stream is the security auditor's, and a quarantine is evidence for the
// security role (open: a read API with roles).
func hidden(s c5.StreamID) bool {
	return s == node.AuditStream || strings.HasPrefix(string(s), "quarantine/")
}

// readers opens every database of the layout read-only.
func readers(ctx context.Context, cfg *node.Config) (map[c5.StreamID]*store.DB, func(), error) {
	l, err := cfg.Layout()
	if err != nil {
		return nil, nil, err
	}
	out := map[c5.StreamID]*store.DB{}
	var open []*store.DB
	closeAll := func() {
		for _, d := range open {
			d.Close()
		}
	}
	for _, d := range l.Databases {
		db, err := store.OpenReadOnly(ctx, cfg.Store.Dir, cfg.NodeID, d.ID)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		open = append(open, db)
		for _, s := range d.Streams {
			out[s.ID] = db
		}
	}
	return out, closeAll, nil
}

func events(ctx context.Context, cfg *node.Config, w io.Writer, stream c5.StreamID, after c5.Seq, limit int, asJSON bool) error {
	dbs, closeAll, err := readers(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeAll()
	if stream == "" {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "STREAM\tLAST_SEQ")
		for _, s := range sortedStreams(dbs) {
			n, err := dbs[s].LastCommitted(ctx, s)
			if err != nil {
				return err
			}
			note := ""
			if hidden(s) {
				note = "\t(not shown by otsec events)"
			}
			fmt.Fprintf(tw, "%s\t%d%s\n", s, n, note)
		}
		return tw.Flush()
	}
	if hidden(stream) {
		return fmt.Errorf("stream %s is not shown by otsec events: audit records and quarantined evidence are for the security roles", stream)
	}
	db, ok := dbs[stream]
	if !ok {
		return fmt.Errorf("stream %s is not in this node's layout", stream)
	}
	if limit < 1 || limit > store.MaxRead {
		return fmt.Errorf("-limit %d, want 1 to %d", limit, store.MaxRead)
	}
	got, err := db.Read(ctx, stream, after, limit)
	if err != nil {
		return err
	}
	if asJSON {
		for _, st := range got {
			fmt.Fprintf(w, "%s\n", st.Event)
		}
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tRECEIVED_UTC\tKIND\tDEVICE_TIME\tSUMMARY\tFLAGS")
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil {
			fmt.Fprintf(tw, "%d\t-\t-\t-\tundecodable: %v\t-\n", st.Key.Seq, err)
			continue
		}
		dt := "-"
		if e.DeviceTime != nil {
			dt = e.DeviceTime.Native
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", st.Key.Seq, e.Received.UTC, e.Kind, dt, summary(e), orDash(strings.Join(e.Flags, ",")))
	}
	return tw.Flush()
}

// summary is one line about an event. Device text is printed as the
// normalizer extracted it, with control characters escaped.
func summary(e *event.Event) string {
	switch {
	case e.Health != nil:
		keys := make([]string, 0, len(e.Health.Details))
		for k := range e.Health.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := []string{e.Health.Type}
		for _, k := range keys {
			parts = append(parts, k+"="+e.Health.Details[k])
		}
		return safe(strings.Join(parts, " "))
	case e.Normalized != nil:
		return safe(e.Normalized.Subject + " " + e.Normalized.Value)
	case e.Native != nil:
		return fmt.Sprintf("native record, %d bytes, not parsed", e.Native.RecordLength)
	}
	return "-"
}

func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func sortedStreams[V any](m map[c5.StreamID]V) []c5.StreamID {
	out := make([]c5.StreamID, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func health(ctx context.Context, cfg *node.Config, w io.Writer) error {
	st, err := node.ReadStatus(node.StatusPath(cfg))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no status file at %s: the node has not started", node.StatusPath(cfg))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "node %s, status written %s\n", st.Node, st.Written.Format(time.RFC3339))
	fmt.Fprintf(w, "collecting: %v\n", st.Collecting)
	if st.RunsHeld != "" {
		fmt.Fprintf(w, "RUNS HELD: %s; every run on this node is stopped while this line shows\n", safe(st.RunsHeld))
	}
	for _, db := range sortedDBs(st.Modes) {
		fmt.Fprintf(w, "database %s: %s\n", db, st.Modes[db])
	}
	if dbs, closeAll, err := readers(ctx, cfg); err != nil {
		fmt.Fprintf(w, "store not readable: %v\n", err)
	} else {
		for _, s := range sortedStreams(dbs) {
			if strings.HasPrefix(string(s), "quarantine/") {
				if n, err := dbs[s].LastCommitted(ctx, s); err == nil && n > 0 {
					fmt.Fprintf(w, "QUARANTINE %s: %d records held for the security role\n", s, n)
				}
			}
		}
		closeAll()
	}
	suspended := make([]string, 0, len(st.Suspensions))
	for a := range st.Suspensions {
		suspended = append(suspended, a)
	}
	sort.Strings(suspended)
	for _, a := range suspended {
		sp := st.Suspensions[a]
		fmt.Fprintf(w, "SUSPENDED %s: %s since %s; cleared only by an administrator naming ref %s\n", safe(a), safe(string(sp.Reason)), safe(sp.Since), safe(sp.Ref))
	}
	clearing := make([]string, 0, len(st.CollectorClears))
	for a := range st.CollectorClears {
		clearing = append(clearing, a)
	}
	sort.Strings(clearing)
	for _, a := range clearing {
		fmt.Fprintf(w, "COLLECTOR STILL SUSPENDED %s: the node cleared ref %s, the collector has not accepted the clear yet; runs stay held, and %s stays in place until this line is gone\n", safe(a), safe(st.CollectorClears[a]), node.ClearSuspensionFileName)
	}
	if c := st.Collector; c != nil {
		fmt.Fprintf(w, "collector install key: trusted %s, collector_seq high %d\n", safe(keyOrNone(c.TrustedKey)), c.High)
		if c.OpenResetKey != "" {
			fmt.Fprintf(w, "COLLECTOR RESET: new install key %s beside trusted %s; nothing is sent until an administrator confirms its fingerprint and acknowledges it\n", safe(c.OpenResetKey), safe(keyOrNone(c.TrustedKey)))
		}
		if c.Restored {
			fmt.Fprintln(w, "COLLECTOR RESTORED: collector_seq went back under the trusted key; nothing is sent, and this is not acknowledged")
		}
	}
	assets := make([]string, 0, len(st.Assets))
	for a := range st.Assets {
		assets = append(assets, a)
	}
	sort.Strings(assets)
	for _, a := range assets {
		r := st.Assets[a]
		line := fmt.Sprintf("asset %s: last run %s", safe(a), safe(r.Code))
		if r.Detail != "" {
			line += " (" + safe(r.Detail) + ")"
		}
		line += " at " + r.At.Format(time.RFC3339)
		if r.Refusal != "" {
			line += " (collector refused: " + safe(r.Refusal) + ")"
		}
		if r.Failures > 0 {
			line = "FAILING " + line + fmt.Sprintf("; %d failed in a row since the node started", r.Failures)
		}
		fmt.Fprintln(w, line)
	}
	names := make([]string, 0, len(st.Targets))
	for n := range st.Targets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ts := st.Targets[n]
		confirmed := "never in this process"
		if !ts.LastConfirmed.IsZero() {
			confirmed = ts.LastConfirmed.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "target %s (%s): %d confirmed, last %s\n", safe(n), ts.Class, ts.Confirmed, confirmed)
		if ts.Open.IsZero() {
			fmt.Fprintln(w, "  no session open")
		} else {
			fmt.Fprintf(w, "  session open since %s\n", ts.Open.Format(time.RFC3339))
		}
		if ts.LastErr != "" {
			fmt.Fprintf(w, "  last session ended: %s\n", safe(ts.LastErr))
		}
		if ts.Unreported > 0 || ts.ReportErr != "" {
			fmt.Fprintf(w, "  forward health events not yet recorded: %d", ts.Unreported)
			if ts.ReportErr != "" {
				fmt.Fprintf(w, " (last refusal: %s)", safe(ts.ReportErr))
			}
			fmt.Fprintln(w)
		}
		streams := make([]string, 0, len(ts.Streams))
		for s := range ts.Streams {
			streams = append(streams, s)
		}
		sort.Strings(streams)
		for _, s := range streams {
			ss := ts.Streams[s]
			line := fmt.Sprintf("  %s: confirmed %d of %d, cursor %d", safe(s), ss.Confirmed, ss.Last, ss.Cursor)
			if ss.Blocked != "" {
				line += ", HELD: " + safe(ss.Blocked)
			}
			fmt.Fprintln(w, line)
		}
	}
	for _, id := range node.SortedListeners(st.Listeners) {
		ls := st.Listeners[id]
		state := "open"
		if !ls.Open {
			state = "NOT OPEN"
		}
		last := "never in this process"
		if !ls.LastMessage.IsZero() {
			last = ls.LastMessage.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "listener %s (%s %s): %s, %d received, %d stored, last message %s\n", safe(id), ls.Transport, safe(ls.Address), state, ls.Received, ls.Stored, last)
		if ls.Plaintext {
			fmt.Fprintln(w, "  PLAINTEXT: no sender authentication or integrity; any host on the path can send or alter messages (D3-5)")
		}
		if ls.Held {
			fmt.Fprintln(w, "  HELD: the store is not taking this listener's messages; senders are not read meanwhile")
		}
		if len(ls.Dropped) > 0 {
			fmt.Fprintf(w, "  DROPPED: %s\n", counts(ls.Dropped))
		}
		if len(ls.Refused) > 0 {
			fmt.Fprintf(w, "  connections refused: %s\n", counts(ls.Refused))
		}
		if ls.Truncated > 0 || ls.Misframed > 0 || ls.Discarded > 0 {
			fmt.Fprintf(w, "  stored truncated %d, misframed %d; %d bytes past the size limit not stored\n", ls.Truncated, ls.Misframed, ls.Discarded)
		}
		if ls.UnknownSenders > 0 {
			more := ""
			if ls.UnknownOverflow {
				more = " and more not tracked"
			}
			fmt.Fprintf(w, "  UNKNOWN SENDERS: %d%s; their messages are kept with no asset\n", ls.UnknownSenders, more)
		}
		if ls.LastErr != "" {
			fmt.Fprintf(w, "  last error: %s\n", safe(ls.LastErr))
		}
	}
	if len(st.Alarms) == 0 {
		fmt.Fprintln(w, "alarms: none")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AT\tSOURCE\tCODE\tDETAIL")
	for _, a := range st.Alarms {
		src := string(a.Database)
		if a.Asset != "" {
			src = "asset " + a.Asset
		}
		if a.Target != "" {
			src = "target " + safe(a.Target)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.At.Format(time.RFC3339), src, a.Code, safe(a.Detail))
	}
	return tw.Flush()
}

// counts renders reason counts in reason order: "rate-limit 3, store 1".
func counts(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", safe(k), m[k])
	}
	return strings.Join(parts, ", ")
}

func sortedDBs(m map[c5.DatabaseID]c5.Mode) []c5.DatabaseID {
	out := make([]c5.DatabaseID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func keyOrNone(k string) string {
	if k == "" {
		return "(none)"
	}
	return k
}
