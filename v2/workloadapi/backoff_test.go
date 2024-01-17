package workloadapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackoff(t *testing.T) {
	new := func() *backoff { //nolint:all
		b := newBackoff()
		b.InitialDelay = time.Second
		b.MaxDelay = 30 * time.Second
		return b
	}

	testUntilMax := func(t *testing.T, b *backoff) {
		for i := 1; i < 30; i++ {
			require.Equal(t, time.Duration(i)*time.Second, b.Duration())
		}
		require.Equal(t, 30*time.Second, b.Duration())
		require.Equal(t, 30*time.Second, b.Duration())
		require.Equal(t, 30*time.Second, b.Duration())
	}

	t.Run("test max", func(t *testing.T) {
		t.Parallel()

		b := new()
		testUntilMax(t, b)
	})

	t.Run("test reset", func(t *testing.T) {
		t.Parallel()

		b := new()
		testUntilMax(t, b)

		b.Reset()

		testUntilMax(t, b)
	})
}
