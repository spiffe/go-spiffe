package jwtutil_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeKey(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		expectOK  bool
		expectErr string
	}{
		{
			name:     "supported key type",
			raw:      `{"kty":"EC","kid":"ec-key","crv":"P-256","x":"ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k","y":"tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"}`,
			expectOK: true,
		},
		{
			name: "unknown key type",
			raw:  `{"kty":"AKP","kid":"ml-dsa-key","alg":"ML-DSA-44","pub":"AAAA"}`,
		},
		{
			name: "unknown key type with a member that is not base64url",
			raw:  `{"kty":"FUTURE","kid":"future-key","x":"!!!"}`,
		},
		{
			name: "unknown key type with a member of another JSON type",
			raw:  `{"kty":"FUTURE","kid":"future-key","n":{"bits":2048}}`,
		},
		{
			name: "unknown key type with a malformed certificate",
			raw:  `{"kty":"FUTURE","kid":"future-key","x5c":["AAAA"]}`,
		},
		{
			name: "known key type on an unsupported curve",
			raw:  `{"kty":"OKP","kid":"ed448-key","crv":"Ed448","x":"AAAA"}`,
		},
		{
			name:      "malformed key of a supported type",
			raw:       `{"kty":"EC","kid":"ec-key","crv":"P-256","x":"!!!","y":"!!!"}`,
			expectErr: "illegal base64 data at input byte 0",
		},
		{
			name:      "missing key type",
			raw:       `{"kid":"no-kty"}`,
			expectErr: "go-jose/go-jose: missing json web key type",
		},
		{
			name:      "key type is not a string",
			raw:       `{"kty":1,"kid":"numeric-kty"}`,
			expectErr: "cannot unmarshal number",
		},
		{
			name:      "entry is not an object",
			raw:       `"EC"`,
			expectErr: "cannot unmarshal string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ok, err := jwtutil.DecodeKey(json.RawMessage(tt.raw))
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				assert.False(t, ok)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectOK, ok)
			if !tt.expectOK {
				assert.Nil(t, key.Key)
				return
			}
			assert.Equal(t, "ec-key", key.KeyID)
			assert.IsType(t, &ecdsa.PublicKey{}, key.Key)
		})
	}
}
