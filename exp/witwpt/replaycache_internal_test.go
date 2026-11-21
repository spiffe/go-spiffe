package witwpt

// White-box, because the memory cache's bounded footprint is a design claim
// about its internals: entries are reclaimed on write rather than by a sweeper
// goroutine, which is what keeps NewMemoryReplayCache lifecycle-free. Nothing
// observable from outside the package would show the map shrinking.

import (
	"strconv"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryReplayCacheReclaimsOnWrite(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/client")
	cache := newMemoryReplayCache()
	past := time.Now().Add(-time.Second)

	// Insert well past the initial sweep threshold, all already expired.
	for i := range 4 * minSweepSize {
		jti := "expired-" + strconv.Itoa(i)
		require.NoError(t, cache.CheckAndRecord(t.Context(), id, jti, past))
	}

	cache.mu.Lock()
	got := len(cache.entries)
	cache.mu.Unlock()

	assert.LessOrEqual(t, got, 2*minSweepSize,
		"expired entries must be reclaimed rather than accumulating")
}

func TestMemoryReplayCacheKeepsLiveEntriesWhileSweeping(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/client")
	cache := newMemoryReplayCache()
	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Minute)

	// One live entry, then enough expired ones to trigger sweeps.
	require.NoError(t, cache.CheckAndRecord(t.Context(), id, "live", future))
	for i := range 4 * minSweepSize {
		require.NoError(t, cache.CheckAndRecord(t.Context(), id, "expired-"+strconv.Itoa(i), past))
	}

	// A sweep must not have dropped the still-valid record.
	err := cache.CheckAndRecord(t.Context(), id, "live", future)
	require.EqualError(t, err, "proof token has already been used")
}
