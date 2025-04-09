package spiffeid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJoinPathSegments(t *testing.T) {
	assertBad := func(t *testing.T, expectErr error, segments ...string) {
		_, err := JoinPathSegments(segments...)
		assert.ErrorIs(t, err, expectErr)
	}
	assertOK := func(t *testing.T, expectPath string, segments ...string) {
		path, err := JoinPathSegments(segments...)
		if assert.NoError(t, err) {
			assert.Equal(t, expectPath, path)
		}
	}

	t.Run("empty", func(t *testing.T) {
		assertBad(t, errEmptySegment, "")
	})
	t.Run("single dot", func(t *testing.T) {
		assertBad(t, errDotSegment, ".")
	})
	t.Run("double dot", func(t *testing.T) {
		assertBad(t, errDotSegment, "..")
	})
	t.Run("invalid char", func(t *testing.T) {
		assertBad(t, errBadPathSegmentChar, "/")
	})
	t.Run("valid segment", func(t *testing.T) {
		assertOK(t, "/a", "a")
	})
	t.Run("valid segments", func(t *testing.T) {
		assertOK(t, "/a/b", "a", "b")
	})
}

func TestValidatePathSegment(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		require.ErrorIs(t, ValidatePathSegment(""), errEmptySegment)
	})
	t.Run("single dot", func(t *testing.T) {
		require.ErrorIs(t, ValidatePathSegment("."), errDotSegment)
	})
	t.Run("double dot", func(t *testing.T) {
		require.ErrorIs(t, ValidatePathSegment(".."), errDotSegment)
	})
	t.Run("invalid char", func(t *testing.T) {
		require.ErrorIs(t, ValidatePathSegment("/"), errBadPathSegmentChar)
	})
	t.Run("valid segment", func(t *testing.T) {
		require.NoError(t, ValidatePathSegment("a"))
	})
}
