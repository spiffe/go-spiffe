package witwpt_test

import (
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	replayClient = spiffeid.RequireFromString("spiffe://example.org/client")
	replayOther  = spiffeid.RequireFromString("spiffe://example.org/other")
)

func TestMemoryReplayCache(t *testing.T) {
	future := time.Now().Add(time.Minute)

	t.Run("first use is recorded and accepted", func(t *testing.T) {
		cache := witwpt.NewMemoryReplayCache()
		require.NoError(t, cache.CheckAndRecord(t.Context(), replayClient, "jti-1", future))
	})

	t.Run("second use of the same jti is rejected", func(t *testing.T) {
		cache := witwpt.NewMemoryReplayCache()
		require.NoError(t, cache.CheckAndRecord(t.Context(), replayClient, "jti-1", future))

		err := cache.CheckAndRecord(t.Context(), replayClient, "jti-1", future)
		require.EqualError(t, err, "proof token has already been used")
	})

	t.Run("the same jti from a different identity is accepted", func(t *testing.T) {
		// Keying on identity as well as jti means a workload minting a constant
		// jti cannot consume shared key space and start rejecting other
		// workloads' legitimate proofs.
		cache := witwpt.NewMemoryReplayCache()
		require.NoError(t, cache.CheckAndRecord(t.Context(), replayClient, "jti-1", future))
		require.NoError(t, cache.CheckAndRecord(t.Context(), replayOther, "jti-1", future))
	})

	t.Run("an expired record no longer binds", func(t *testing.T) {
		// exp tells the store when the record stops mattering, so no retention
		// policy has to be configured.
		cache := witwpt.NewMemoryReplayCache()
		past := time.Now().Add(-time.Minute)
		require.NoError(t, cache.CheckAndRecord(t.Context(), replayClient, "jti-1", past))
		require.NoError(t, cache.CheckAndRecord(t.Context(), replayClient, "jti-1", future))
	})

	t.Run("exactly one caller wins under contention", func(t *testing.T) {
		// The check and the record must be atomic, or two replicas both observe
		// "unseen" and both accept.
		cache := witwpt.NewMemoryReplayCache()

		const goroutines = 50
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			successes int
		)
		start := make(chan struct{})

		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := cache.CheckAndRecord(t.Context(), replayClient, "contended", future); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			}()
		}

		close(start)
		wg.Wait()
		assert.Equal(t, 1, successes, "exactly one caller may record a given jti")
	})
}
