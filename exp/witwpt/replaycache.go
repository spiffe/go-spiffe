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

// ReplayCache remembers which proofs have been seen, so a captured proof cannot
// be presented twice within its lifetime. wpt-01 §2 RECOMMENDS this check.
//
// It is the WPT's jti that is recorded; a WIT-SVID's own jti MUST NOT be used
// for replay protection (SPIFFE WIT-SVID.md §3.3).
type ReplayCache interface {
	// CheckAndRecord records the proof identified by id and jti, returning an
	// error if that pair has already been recorded. exp is when the record may
	// be dropped. Implementations MUST make the check and the record atomic.
	CheckAndRecord(ctx context.Context, id spiffeid.ID, jti string, exp time.Time) error
}

// NewMemoryReplayCache returns a ReplayCache holding records in memory for the
// life of the process, reclaiming expired records during writes so it owns no
// goroutine and needs no Close.
//
// It covers a single process only. A deployment running several replicas needs a
// shared store to reject a proof replayed to a different replica; implement
// ReplayCache over one (a Redis SET NX EX maps onto CheckAndRecord) and pass it
// to WithReplayCache.
func NewMemoryReplayCache() ReplayCache {
	return newMemoryReplayCache()
}

func newMemoryReplayCache() *memoryReplayCache {
	return &memoryReplayCache{
		entries:   make(map[replayKey]time.Time),
		nextSweep: minSweepSize,
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
}

func (c *memoryReplayCache) CheckAndRecord(
	_ context.Context, id spiffeid.ID, jti string, exp time.Time,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if len(c.entries) >= c.nextSweep {
		c.sweep(now)
		// Amortized O(1) per insert, holding steady state near twice the live set.
		c.nextSweep = 2*len(c.entries) + minSweepSize
	}

	key := replayKey{id: id.String(), jti: jti}
	if previous, ok := c.entries[key]; ok && previous.After(now) {
		// Unprefixed, since Verify wraps it as StageReplay with the package prefix.
		return errReplayed
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
