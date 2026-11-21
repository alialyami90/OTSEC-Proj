package sensorlink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// sensorrun.json (docs/phase4/D5-sensor-node.md sections 1.1, 1.3, 1.4,
// 1.8 and 1.9 item 5): what changes at the sensor's will and is not in a
// sensor database's cursor. This build keeps sensor-transmitted's standing
// state and latest raise, the held pool events (as counts and facts, never
// as event bytes), and the run and capture totals the held capture loss
// counts up to, and the copy of W and R (2e-1; 2e-3 adds the held gap). SL-30's
// dial counts and proofs, the re-arm's spent set, the run's second copy,
// the poison record and the cap's record times are P4-4-DE's.
//
// The write number (section 1.1): each write carries write_no, one above
// the last, and after the rename the node saves it in the cursor of every
// open sensor database. At a start a file below the highest number in a
// cursor is behind, one missing while a cursor holds a number above 0 is
// lost, and both read as unreadable; a sensor whose database cannot be
// compared (no cursor, or unread) reads as lost for its values. Each reads
// sensor-state-unread, cause run-file, and raises sensor-transmitted.

// RunFileSchema is the file's schema, the node's own.
const RunFileSchema = "otsec.node-sensorrun/0.1"

type runFileDoc struct {
	Schema  string                    `json:"schema"`
	WriteNo uint64                    `json:"write_no"`
	Sensors map[string]*runFileSensor `json:"sensors"`
}

type runFileSensor struct {
	Transmitted *transmitState `json:"transmitted,omitempty"`
	Held        []HeldEvent    `json:"held,omitempty"`
	Capture     *captureState  `json:"capture,omitempty"`
	// Copy is the earliest of W, R and the held gap's start (section 1.9
	// item 5; watch.go), the bound of a start whose cursor holds no W
	// (gapstart.go).
	Copy string `json:"w_r_copy,omitempty"`
}

type transmitState struct {
	Standing bool   `json:"standing"`
	RaisedAt string `json:"raised_at"`
}

type captureState struct {
	RunID string `json:"run_id"`
	// Key is the run's sensor.counters key (its position generation),
	// "" when not known.
	Key    string            `json:"key,omitempty"`
	Totals map[string]uint64 `json:"totals"`
}

// runFileFault is a test seam, nil in the node: it fails a write before its
// rename, as a kill or a full disk would.
var runFileFault func() error

// RunFile is the node's sensorrun.json.
type RunFile struct {
	path string
	// wmu makes one writer at a time, from the number taken to its
	// rename, so an older snapshot never lands after a newer one (D6's
	// B2 on #747).
	wmu     sync.Mutex
	mu      sync.Mutex
	doc     runFileDoc
	readErr error // the file at open: unreadable
	missing bool
	healths []*Health
	links   []*Link
}

// OpenRunFile reads sensorrun.json at path. A file that cannot be read or
// parsed is kept as unreadable for Start; nothing fails here.
func OpenRunFile(path string) *RunFile {
	f := &RunFile{path: path, doc: runFileDoc{Schema: RunFileSchema, Sensors: map[string]*runFileSensor{}}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f.missing = true
	case err != nil:
		f.readErr = err
	default:
		var d runFileDoc
		if err := json.Unmarshal(b, &d); err != nil || d.Schema != RunFileSchema || d.Sensors == nil {
			f.readErr = fmt.Errorf("sensorlink: sensorrun.json is not %s: %v", RunFileSchema, err)
		} else {
			f.doc = d
		}
	}
	return f
}

func (f *RunFile) add(h *Health) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healths = append(f.healths, h)
}

func (f *RunFile) addLink(l *Link) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links = append(f.links, l)
}

func (f *RunFile) put(sensor string, e runFileSensor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doc.Sensors[sensor] = &e
}

// write writes the file whole under the next write number (temporary
// file, flush, rename), then saves the number in the cursor of every
// sensor database the file knows. Only the file's own write can fail it:
// a cursor whose save fails is behind the file, which reads as current,
// and its next write of the position carries the number.
func (f *RunFile) write(ctx context.Context) error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.mu.Lock()
	n := f.doc.WriteNo + 1
	d := f.doc
	d.WriteNo = n
	b, err := json.Marshal(&d)
	links := append([]*Link(nil), f.links...)
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeSynced(f.path, b); err != nil {
		return err
	}
	f.mu.Lock()
	f.doc.WriteNo = max(f.doc.WriteNo, n)
	f.mu.Unlock()
	for _, l := range links {
		_ = l.saveWriteNo(ctx, n)
	}
	return nil
}

func writeSynced(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sensorrun-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runFileFault != nil {
		if err := runFileFault(); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}

// Start applies the file at the node's start, before any connection, to
// each sensor's link (each made with this file's Health): it judges the
// file against the links' cursors, gives each Health what stands, raises
// what does not, and writes the file once under a number above every
// cursor's. A cursor that cannot be read makes its sensor not comparable.
func (f *RunFile) Start(ctx context.Context, links ...*Link) error {
	type db struct {
		l   *Link
		cur *Cursor
		ok  bool // a cursor read, with its write number
	}
	var dbs []db
	var top uint64
	for _, l := range links {
		c, err := l.readCursor(ctx)
		d := db{l: l, cur: c, ok: err == nil && c != nil}
		if d.ok {
			top = max(top, c.WriteNo)
		}
		dbs = append(dbs, d)
	}
	f.mu.Lock()
	cause := ""
	switch {
	case f.readErr != nil:
		cause = "unreadable"
	case f.missing && top > 0:
		cause = "lost"
	case !f.missing && f.doc.WriteNo < top:
		cause = "behind"
	}
	doc := f.doc
	if cause != "" && cause != "behind" {
		doc.Sensors = map[string]*runFileSensor{}
	}
	f.doc.WriteNo = max(f.doc.WriteNo, top)
	f.doc.Sensors = map[string]*runFileSensor{}
	f.mu.Unlock()
	var errs []error
	for _, d := range dbs {
		h := d.l.opt.Health
		if h == nil {
			continue
		}
		c := cause
		if c == "" && !d.ok {
			c = "not-comparable" // its database lost, absent, unread or without a cursor
		}
		e := doc.Sensors[d.l.cfg.SensorID]
		next := h.start(e, c == "", c == "" || c == "behind", c, d.cur)
		if next != nil {
			errs = append(errs, d.l.saveStart(ctx, next))
		}
		// Any gap held for the floor first, then the node-start gap
		// (CH-45, "At a start"; gapstart.go).
		h.mu.Lock()
		copyAt := h.copyFile
		h.mu.Unlock()
		d.l.nodeStart(ctx, copyAt)
		h.mu.Lock()
		_ = h.pool.Write(ctx, h.cfg.Monotonic(), h.emit) // what the start counted, at the start's time
		f.put(d.l.cfg.SensorID, h.entry())
		h.mu.Unlock()
	}
	if err := f.write(ctx); err != nil {
		errs = append(errs, err)
	} else {
		for _, d := range dbs {
			if h := d.l.opt.Health; h != nil {
				h.mu.Lock()
				h.fileAt, h.fileWritten, h.dirty = h.cfg.Monotonic(), true, false
				h.fileRun, h.fileTotals = h.run, h.totals
				h.mu.Unlock()
			}
		}
	}
	return errors.Join(errs...)
}
