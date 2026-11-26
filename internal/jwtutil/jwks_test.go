package jwtutil_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keyID = "key-id"

func TestDecodeKey(t *testing.T) {
	ecKey := test.NewEC256Key(t).Public()
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey := rsaPrivateKey.Public()
	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	octKey := []byte("symmetric-key")

	tests := []struct {
		name      string
		raw       string
		expectKey any
		expectErr string
	}{
		{
			name:      "EC key",
			raw:       marshalKey(t, ecKey),
			expectKey: ecKey,
		},
		{
			name:      "RSA key",
			raw:       marshalKey(t, rsaKey),
			expectKey: rsaKey,
		},
		{
			name:      "OKP key",
			raw:       marshalKey(t, edKey),
			expectKey: edKey,
		},
		{
			name:      "oct key",
			raw:       marshalKey(t, octKey),
			expectKey: octKey,
		},
		{
			name:      "supported key type next to a member differing only in case",
			raw:       `{"KTY":"FUTURE",` + marshalKey(t, ecKey)[1:],
			expectKey: ecKey,
		},
		{
			name: "unknown key type",
			raw:  `{"kty":"FUTURE","kid":"key-id","pub":"AAAA"}`,
		},
		{
			name: "key type differing only in case from a supported one",
			raw:  `{"kty":"Ec","kid":"key-id","x":"!!!"}`,
		},
		{
			name: "unknown key type next to a member differing only in case",
			raw:  `{"kty":"FUTURE","KTY":"EC","kid":"key-id","x":"!!!"}`,
		},
		{
			name: "unknown key type with a member that is not base64url",
			raw:  `{"kty":"FUTURE","kid":"key-id","x":"!!!"}`,
		},
		{
			name: "unknown key type with a member of another JSON type",
			raw:  `{"kty":"FUTURE","kid":"key-id","n":{"bits":2048}}`,
		},
		{
			name: "unknown key type with a malformed certificate",
			raw:  `{"kty":"FUTURE","kid":"key-id","x5c":["AAAA"]}`,
		},
		{
			name: "known key type on an unsupported curve",
			raw:  `{"kty":"OKP","kid":"key-id","crv":"Ed448","x":"AAAA"}`,
		},
		{
			name:      "malformed key of a supported type",
			raw:       `{"kty":"EC","kid":"key-id","crv":"P-256","x":"!!!","y":"!!!"}`,
			expectErr: "illegal base64 data at input byte 0",
		},
		{
			name:      "duplicate key type",
			raw:       `{"kty":"FUTURE","kty":"EC","kid":"key-id"}`,
			expectErr: "duplicate key 'kty'",
		},
		{
			name:      "missing key type",
			raw:       `{"kid":"key-id"}`,
			expectErr: "go-jose/go-jose: missing json web key type",
		},
		{
			name:      "key type is not a string",
			raw:       `{"kty":1,"kid":"key-id"}`,
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
			if tt.expectKey == nil {
				assert.False(t, ok)
				assert.Nil(t, key.Key)
				return
			}
			assert.True(t, ok)
			assert.Equal(t, keyID, key.KeyID)
			assert.Equal(t, tt.expectKey, key.Key)
		})
	}
}

// marshalKey returns the JWK for the key, as an entry of a JWK Set.
func marshalKey(t *testing.T, key any) string {
	t.Helper()
	raw, err := jose.JSONWebKey{Key: key, KeyID: keyID}.MarshalJSON()
	require.NoError(t, err)
	return string(raw)
}
