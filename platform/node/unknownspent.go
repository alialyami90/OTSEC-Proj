package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// AlarmUnknownSpentUncounted: at start, the node could not count what
// unknown senders stored on a listener's stream in the window before the
// start, so that listener's unknown budget starts empty (fail closed):
// unknown senders' messages are dropped as unknown-budget until it refills
// at its hourly rate. Known senders are not affected.
const AlarmUnknownSpentUncounted = "syslog-unknown-budget-uncounted"

// unknownSpent is receive.Config.UnknownSpent for stream (A3's conditions
// on D3-3): the sum of len(event) over the stream's committed records that
// carry asset-unresolved and whose received time is inside the window
// before now. A record received after now counts as inside, so a clock set
// back cannot hand out a fresh budget, and so does one whose received time
// does not parse. The whole stream is read, not only the records committed
// in the window: under a clock set back, commit order is not time order.
//
// The store keeps an event with its seq written in, so each record counts
// a few bytes more than the receiver spent on it; that errs toward an
// emptier budget. If the stream cannot be read, unknownSpent returns the
// error and the caller starts the budget empty.
func unknownSpent(ctx context.Context, db *store.DB, stream c5.StreamID, window time.Duration, now time.Time) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("the database of %s is not open", stream)
	}
	from := now.Add(-window)
	var spent int64
	var after c5.Seq
	for {
		got, err := db.Read(ctx, stream, after, store.MaxRead)
		if err != nil {
			return 0, err
		}
		for _, s := range got {
			after = s.Key.Seq
			// Most records name an asset: skip them without decoding.
			if !bytes.Contains(s.Event, []byte("asset-unresolved")) {
				continue
			}
			var e struct {
				Flags    []string `json:"flags"`
				Received struct {
					UTC string `json:"utc"`
				} `json:"received"`
			}
			if err := json.Unmarshal(s.Event, &e); err != nil {
				return 0, fmt.Errorf("%s seq %d: %w", stream, s.Key.Seq, err)
			}
			if !slices.Contains(e.Flags, "asset-unresolved") {
				continue
			}
			if at, err := time.Parse(time.RFC3339Nano, e.Received.UTC); err == nil && !at.After(from) {
				continue
			}
			spent += int64(len(s.Event))
		}
		if len(got) < store.MaxRead {
			return spent, nil
		}
	}
}
