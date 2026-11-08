package sensorlink

import (
	"math/bits"
	"time"
)

// budget is the unresolved budget (docs/phase4/D5-c5-0.9.md section 4): a
// byte bucket of at most B = Q/4, where Q is the observation quota, that
// refills at B/H bytes a second, H being the planned outage. It runs on the
// node's monotonic clock, so a wall-clock step neither refills nor empties
// it, and it starts empty at every start. The refill is exact: the part of
// a byte not yet earned is carried, so n seconds always give n*B/H bytes
// rounded down, however the time is split.
type budget struct {
	cap   uint64 // B
	hNS   uint64 // H in nanoseconds
	level uint64
	rem   uint64 // numerator carried, < hNS
	last  time.Duration
}

func newBudget(quota int64, outageHours int, now time.Duration) *budget {
	return &budget{cap: uint64(quota / 4), hNS: uint64(outageHours) * uint64(time.Hour), last: now}
}

func (b *budget) refill(now time.Duration) {
	if now <= b.last {
		return
	}
	e := uint64(now - b.last)
	b.last = now
	if e >= b.hNS {
		b.level, b.rem = b.cap, 0
		return
	}
	// (e*B + rem) / H, with e < H and rem < H, so the high word stays
	// below H and Div64 can't overflow.
	hi, lo := bits.Mul64(e, b.cap)
	lo, carry := bits.Add64(lo, b.rem, 0)
	hi += carry
	q, r := bits.Div64(hi, lo, b.hNS)
	b.level += q
	b.rem = r
	if b.level >= b.cap {
		b.level, b.rem = b.cap, 0
	}
}

// take takes n bytes if the bucket holds them.
func (b *budget) take(n int64, now time.Duration) bool {
	b.refill(now)
	if n < 0 || uint64(n) > b.level {
		return false
	}
	b.level -= uint64(n)
	return true
}

// giveBack returns n bytes the store refused after take took them.
func (b *budget) giveBack(n int64) {
	b.level = min(b.level+uint64(n), b.cap)
}
