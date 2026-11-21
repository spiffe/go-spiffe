package witwpt

import (
	"context"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// minSweepSize is the floor on how many entries accumulate before the memory
// cache reclaims expired ones, so a small cache does not sweep on every insert.
const minSweepSize = 128

// maxSweepInterval bounds how long expired records survive after a burst, when
// writes are too few to reach the size threshold.
const maxSweepInterval = time.Minute

// ReplayCache records seen proofs so one cannot be presented twice within its
// lifetime (wpt-01 §2). Records are keyed on the SPIFFE ID and the WPT's jti.
type ReplayCache interface {
	// CheckAndRecord atomically records the proof identified by id and jti. It
	// returns ErrReplayed if the pair is already recorded, and any other error
	// if it cannot check or record it; both reject the proof. The record must be
	// kept until exp, an absolute time on the verifier's clock.
	CheckAndRecord(ctx context.Context, id spiffeid.ID, jti string, exp time.Time) error
}

// NewMemoryReplayCache returns an in-process ReplayCache that reclaims expired
// records on write, so it needs no Close. Replicated deployments need a shared
// ReplayCache (e.g. Redis SET NX EX) to catch replays across replicas.
func NewMemoryReplayCache() ReplayCache {
	return newMemoryReplayCache()
}

func newMemoryReplayCache() *memoryReplayCache {
	return &memoryReplayCache{
		entries:   make(map[replayKey]time.Time),
		nextSweep: minSweepSize,
		lastSweep: time.Now(),
	}
}

type replayKey struct {
	id  string
	jti string
}

type memoryReplayCache struct {
	mu        sync.Mutex
	entries   map[replayKey]time.Time
	nextSweep int
	lastSweep time.Time
}

func (c *memoryReplayCache) CheckAndRecord(
	_ context.Context, id spiffeid.ID, jti string, exp time.Time,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if len(c.entries) >= c.nextSweep || now.Sub(c.lastSweep) >= maxSweepInterval {
		c.sweep(now)
		// Amortized O(1) per insert, holding steady state near twice the live set.
		c.nextSweep = 2*len(c.entries) + minSweepSize
		c.lastSweep = now
	}

	key := replayKey{id: id.String(), jti: jti}
	if previous, ok := c.entries[key]; ok && previous.After(now) {
		return ErrReplayed
	}

	c.entries[key] = exp
	return nil
}

// sweep drops every record whose exp has passed. The caller must hold the mutex.
func (c *memoryReplayCache) sweep(now time.Time) {
	for key, exp := range c.entries {
		if !exp.After(now) {
			delete(c.entries, key)
		}
	}
}
