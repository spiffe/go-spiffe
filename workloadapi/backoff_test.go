package workloadapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLinearBackoff(t *testing.T) {
	testUntilMax := func(t *testing.T, b *linearBackoff) {
		for i := 1; i < 30; i++ {
			require.Equal(t, time.Duration(i)*time.Second, b.Next())
		}
		require.Equal(t, 30*time.Second, b.Next())
		require.Equal(t, 30*time.Second, b.Next())
		require.Equal(t, 30*time.Second, b.Next())
	}

	t.Run("test max", func(t *testing.T) {
		t.Parallel()

		b := newLinearBackoff()
		testUntilMax(t, b)
	})

	t.Run("test reset", func(t *testing.T) {
		t.Parallel()

		b := newLinearBackoff()
		testUntilMax(t, b)

		b.Reset()

		testUntilMax(t, b)
	})
}
