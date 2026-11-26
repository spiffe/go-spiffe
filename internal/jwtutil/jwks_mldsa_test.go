//go:build go1.27

package jwtutil_test

import (
	"encoding/json"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ML-DSA keys are supported on Go 1.27 and later, so a well-formed one is
// decoded and a malformed one is an error.
func TestDecodeKeyMLDSA(t *testing.T) {
	t.Run("well-formed key", func(t *testing.T) {
		expectKey := test.NewMLDSAKey(t, test.MLDSAParameters[0]).Public()

		key, ok, err := jwtutil.DecodeKey(json.RawMessage(marshalKey(t, expectKey)))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, keyID, key.KeyID)
		assert.Equal(t, expectKey, key.Key)
	})

	t.Run("malformed key", func(t *testing.T) {
		_, ok, err := jwtutil.DecodeKey(json.RawMessage(`{"kty":"AKP","kid":"key-id","alg":"ML-DSA-44","pub":"!!!"}`))
		require.ErrorContains(t, err, "illegal base64 data at input byte 0")
		assert.False(t, ok)
	})
}
