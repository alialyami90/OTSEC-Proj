package receive

import (
	"net/netip"
	"sync"
	"time"
)

// limiter is a token bucket per sender address, plus one bucket that all
// unknown senders share. A known sender spends only its own tokens, so no
// flood from other addresses, spoofed or not, can take its share. An
// unknown sender spends its own and the shared bucket's, so one unknown
// sender is held to the per-source rate and all of them together to the
// shared rate.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second, per source
	burst   float64
	max     int // most sources tracked
	sources map[netip.Addr]*bucket
	unknown bucket
	uRate   float64
	uBurst  float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(l Limits) *limiter {
	return &limiter{
		rate: l.Rate, burst: float64(l.Burst), max: l.MaxSources,
		sources: map[netip.Addr]*bucket{},
		uRate:   l.UnknownRate, uBurst: float64(l.UnknownBurst),
		unknown: bucket{tokens: float64(l.UnknownBurst)},
	}
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	if !b.last.IsZero() && now.After(b.last) {
		b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	b.last = now
}

// wait reports how long until b holds one token.
func (b *bucket) wait(rate float64) time.Duration {
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

// source returns addr's bucket, creating it full. When the table is full it
// forgets a sender whose bucket has refilled (it would start full anyway),
// or else any one; forgetting a busy sender lets it burst once more.
func (l *limiter) source(addr netip.Addr, now time.Time) *bucket {
	b := l.sources[addr]
	if b != nil {
		return b
	}
	if len(l.sources) >= l.max {
		var victim netip.Addr
		found := false
		for a, x := range l.sources {
			x.refill(now, l.rate, l.burst)
			if !found || x.tokens >= l.burst {
				victim, found = a, true
				if x.tokens >= l.burst {
					break
				}
			}
		}
		delete(l.sources, victim)
	}
	b = &bucket{tokens: l.burst, last: now}
	l.sources[addr] = b
	return b
}

// allow takes one token for a datagram from addr and reports whether there
// was one. A datagram that finds none is dropped and counted.
func (l *limiter) allow(addr netip.Addr, known bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.source(addr, now)
	b.refill(now, l.rate, l.burst)
	if b.tokens < 1 {
		return false
	}
	if !known {
		l.unknown.refill(now, l.uRate, l.uBurst)
		if l.unknown.tokens < 1 {
			return false
		}
		l.unknown.tokens--
	}
	b.tokens--
	return true
}

// reserve takes one token for a stream frame from addr and returns how long
// the reader must wait before reading on. A stream is slowed, never
// dropped: the wait holds the connection, and TCP flow control holds the
// sender.
func (l *limiter) reserve(addr netip.Addr, known bool, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.source(addr, now)
	b.refill(now, l.rate, l.burst)
	d := b.wait(l.rate)
	b.tokens--
	if !known {
		l.unknown.refill(now, l.uRate, l.uBurst)
		d = max(d, l.unknown.wait(l.uRate))
		l.unknown.tokens--
	}
	return d
}
