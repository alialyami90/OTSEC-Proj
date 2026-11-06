package node

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	c5 "otsec.local/otsec/contracts/store"
)

// AlarmAssetStoreFull is raised when an item 3 write is refused at the
// ceiling (C5 0.8 section 5, C1 on #444): storing it would leave the
// configuration class above the quota less the configuration module's own
// floor terms. One name covers the asset module and R9. It is raised once
// per crossing: a refusal raises it, and a later refusal raises it again
// only after the crossing has ended (C6 on #444). The crossing ends at the
// next item 3 write that fits, or once the class holds little enough that
// the smallest write it refused would fit, whatever freed the room (D4-54).
// The matcher pauses while it holds. Configuration reads, baselines and
// checkpoints are unaffected. Level 1.
const AlarmAssetStoreFull = "asset-store-full"

// HealthAssetStoreFull is AlarmAssetStoreFull's event on platform/health.
const HealthAssetStoreFull = "asset.store-full"

// ceilingError is an item 3 write refused at the ceiling.
type ceilingError struct {
	series     string
	need, free int64
	ceiling    int64
	classBytes int64
}

func (e *ceilingError) Error() string {
	return fmt.Sprintf("the item 3 ceiling refuses a %s record of %d bytes: the configuration class holds %d bytes and the ceiling is %d bytes, so %d bytes are free for item 3",
		e.series, e.need, e.classBytes, e.ceiling, e.free)
}

// item3Store is the ceiling's state. Only the scheduler's goroutine uses it.
type item3Store struct {
	full bool
	// need is the smallest write refused in this crossing.
	need    int64
	refused map[string]uint64
}

// item3Streams says where each item 3 series may be written (C5 0.8
// section 1). The contract cannot see the stream, so the node's one writer,
// storeItem3, holds each series to its own stream.
func item3StreamOK(stream c5.StreamID, series string) bool {
	switch series {
	case c5.SeriesAdvisorySet:
		return stream == AdvisoryStream
	case c5.SeriesIdentity, c5.SeriesIdentityRead, c5.SeriesFinding:
		return strings.HasPrefix(string(stream), "config/")
	}
	return false
}

// storeItem3 is the one writer of the item 3 series. It takes the series
// from the document itself (ConfigDocuments), refuses a series on a stream
// that is not its own, and refuses a write that would leave the
// configuration class above the ceiling (a *ceilingError), counting it by
// series in status. Otherwise it commits the record and returns its seq.
// Calls come from the scheduler's goroutine only, so no other item 3
// write can fall between the check and the commit.
func (s *Scheduler) storeItem3(ctx context.Context, stream c5.StreamID, doc []byte, capture *c5.Capture) (c5.Seq, error) {
	info, err := ConfigDocuments(doc, capture)
	if err != nil {
		return 0, err
	}
	if !item3StreamOK(stream, info.Series) {
		return 0, fmt.Errorf("a %s record does not belong on stream %s", info.Series, stream)
	}
	db := s.rt.Store(stream)
	if db == nil {
		return 0, errors.New("configuration database not open")
	}
	used, err := db.ClassBytes(ctx, c5.ClassConfiguration)
	if err != nil {
		return 0, err
	}
	s.endCrossing(used)
	need := int64(len(doc))
	if capture != nil {
		// An upper bound: a capture already stored is not counted again.
		need += int64(len(capture.Bytes))
	}
	if ceiling := s.rt.cfg.Item3Ceiling(); used+need > ceiling {
		e := &ceilingError{series: info.Series, need: need, free: max(ceiling-used, 0), ceiling: ceiling, classBytes: used}
		s.item3.refused[info.Series]++
		if s.item3.full {
			s.item3.need = min(s.item3.need, need)
		} else {
			s.item3.full, s.item3.need = true, need
			s.rt.opt.Status.Raise("", AlarmAssetStoreFull, e.Error()+"; identity records, findings and sets are not stored until room returns, and configuration monitoring continues to the full quota")
			s.rt.health(ctx, HealthAssetStoreFull, map[string]string{"series": info.Series, "bytes_needed": strconv.FormatInt(need, 10),
				"bytes_free": strconv.FormatInt(e.free, 10), "ceiling_bytes": strconv.FormatInt(ceiling, 10)})
		}
		s.publishAssetStore()
		return 0, e
	}
	seq, err := s.storeConfig(ctx, stream, doc, capture)
	if err != nil {
		return 0, err
	}
	if s.item3.full {
		s.item3.full = false
		s.publishAssetStore()
	}
	return seq, nil
}

// endCrossing ends the crossing when the configuration class, holding used
// bytes, has room under the ceiling for the smallest write refused in it,
// whatever freed the room (D4-54).
func (s *Scheduler) endCrossing(used int64) {
	if s.item3.full && used+s.item3.need <= s.rt.cfg.Item3Ceiling() {
		s.item3.full = false
		s.publishAssetStore()
	}
}

// item3Paused reports whether the matcher is paused: a crossing holds, and
// the class still has no room for the smallest write it refused. An error
// reading the class counts as paused.
func (s *Scheduler) item3Paused(ctx context.Context) bool {
	if !s.item3.full {
		return false
	}
	db, _, _ := s.rt.view(s.rt.find(ConfigDB))
	if db == nil {
		return true
	}
	used, err := db.ClassBytes(ctx, c5.ClassConfiguration)
	if err != nil {
		return true
	}
	s.endCrossing(used)
	return s.item3.full
}

// publishAssetStore puts the ceiling's state in status, with asset on.
func (s *Scheduler) publishAssetStore() {
	if !s.rt.cfg.AssetOn() {
		return
	}
	refused := map[string]uint64{}
	for k, v := range s.item3.refused {
		refused[k] = v
	}
	s.rt.opt.Status.SetAssetStore(&AssetStoreStatus{CeilingBytes: s.rt.cfg.Item3Ceiling(), Full: s.item3.full, Refused: refused})
	s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
}
