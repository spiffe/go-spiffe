//go:build !go1.27

package jwtutil_test

import (
	"encoding/json"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ML-DSA keys are not supported before Go 1.27, so they are ignored whether
// or not they are well formed.
func TestDecodeKeyMLDSA(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "key with a base64url member",
			raw:  `{"kty":"AKP","kid":"key-id","alg":"ML-DSA-44","pub":"AAAA"}`,
		},
		{
			name: "key with a member that is not base64url",
			raw:  `{"kty":"AKP","kid":"key-id","alg":"ML-DSA-44","pub":"!!!"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ok, err := jwtutil.DecodeKey(json.RawMessage(tt.raw))
			require.NoError(t, err)
			assert.False(t, ok)
			assert.Nil(t, key.Key)
		})
	}
}
