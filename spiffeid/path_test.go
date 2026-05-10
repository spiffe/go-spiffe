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
	t.Run("valid mixed segment charset", func(t *testing.T) {
		require.NoError(t, ValidatePathSegment("abc-_.Z9"))
	})
	t.Run("reject percent-encoded segment text", func(t *testing.T) {
		require.ErrorIs(t, ValidatePathSegment("%61pi"), errBadPathSegmentChar)
	})
}

func TestValidatePath(t *testing.T) {
	t.Run("reject root path only", func(t *testing.T) {
		require.ErrorIs(t, ValidatePath("/"), errTrailingSlash)
	})
	t.Run("reject trailing slash", func(t *testing.T) {
		require.ErrorIs(t, ValidatePath("/foo/"), errTrailingSlash)
	})
	t.Run("reject empty segment in middle", func(t *testing.T) {
		require.ErrorIs(t, ValidatePath("/foo//bar"), errEmptySegment)
	})
}

func TestJoinPathSegmentsHierarchical(t *testing.T) {
	path, err := JoinPathSegments("ns", "default", "sa", "web")
	require.NoError(t, err)
	require.Equal(t, "/ns/default/sa/web", path)
}
