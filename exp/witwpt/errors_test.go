package witwpt_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStageString(t *testing.T) {
	// Stage names are used as metric labels, so they are part of the API.
	assert.Equal(t, "wit", witwpt.StageWIT.String())
	assert.Equal(t, "proof", witwpt.StageProof.String())
	assert.Equal(t, "replay", witwpt.StageReplay.String())
	assert.Equal(t, "unknown", witwpt.Stage(0).String())
}

func TestErrorCarriesStageAndUnwraps(t *testing.T) {
	cause := errors.New("boom")
	err := &witwpt.Error{Stage: witwpt.StageProof, Err: cause}

	t.Run("message names the stage and the cause", func(t *testing.T) {
		for stage, want := range map[witwpt.Stage]string{
			witwpt.StageWIT:    "witwpt: WIT-SVID validation failed: boom",
			witwpt.StageProof:  "witwpt: proof verification failed: boom",
			witwpt.StageReplay: "witwpt: replay check failed: boom",
			witwpt.Stage(0):    "witwpt: verification failed: boom",
		} {
			assert.EqualError(t, &witwpt.Error{Stage: stage, Err: cause}, want)
		}
	})

	t.Run("unwraps to the cause", func(t *testing.T) {
		assert.ErrorIs(t, err, cause)
	})

	t.Run("errors.As recovers the stage through wrapping", func(t *testing.T) {
		wrapped := fmt.Errorf("middleware: %w", err)

		var got *witwpt.Error
		require.ErrorAs(t, wrapped, &got)
		assert.Equal(t, witwpt.StageProof, got.Stage)
	})
}
