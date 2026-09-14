package witwpt_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// witFixture is a committed WIT-SVID whose exp is 2100-01-01, so it does not
// rot. Its signature is a fixed 64-byte filler: ParseInsecure does not verify
// signatures, and holding the token bytes constant is what makes wantWTH below
// a stable, independently checkable value.
const witFixture = "eyJhbGciOiJFUzI1NiIsImtpZCI6IndpdC1hdXRob3JpdHktMSIsInR5cCI6IndpdCtqd3QifQ." +
	"eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjbmYtMSIsImt0eSI6IkVDIiwi" +
	"eCI6ImlLWnM3QzlPTWFrWm9DTkZDSmpjSWU4aHB4QkR2SGVDSTJsdzVnRVR1dWsiLCJ5IjoieHkzMGFfYzJ3YmduMkxl" +
	"SV9od28xRVR3S2tzb0szemlTZGVyM2loOTR3OCJ9fSwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjE3NTAwMDAwMDAsImlz" +
	"cyI6InNwaWZmZTovL2V4YW1wbGUub3JnIiwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvY2xpZW50In0." +
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"

// witFixturePrivJWK is the private half of witFixture's cnf.jwk. It is a test
// fixture, not a credential.
const witFixturePrivJWK = `{"kty":"EC","kid":"cnf-1","crv":"P-256","alg":"ES256",` +
	`"x":"iKZs7C9OMakZoCNFCJjcIe8hpxBDvHeCI2lw5gETuuk",` +
	`"y":"xy30a_c2wbgn2LeI_hwo1ETwKksoK3ziSder3ih94w8",` +
	`"d":"i7Q5Wgfd1jPpqMlApObMNHhkyTSEnVVLKtLfIOizFPE"}`

// wantWTH is base64url(SHA-256(ASCII(witFixture))) per draft-ietf-wimse-wpt-01
// §2 -- a hash of the whole compact serialization, NOT an RFC 7638 JWK
// thumbprint. Derived without this package's code, and reproducible with:
//
//	printf '%s' "$WIT" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
const wantWTH = "YbWmBlkKlYIC8qAmT-RLp-ZWyPIfrijSxszwpN3CUyQ"

const testAudience = "https://server.example.org/v2/orders"

// TestMintWTHMatchesIndependentlyDerivedConstant is the anchor test for the
// single highest-risk value in the implementation: the wrong reading of wth
// (a JWK thumbprint) would still round-trip against our own verifier.
func TestMintWTHMatchesIndependentlyDerivedConstant(t *testing.T) {
	svid := fixtureSVID(t)

	proof, err := witwpt.Mint(svid, testAudience)
	require.NoError(t, err)

	claims := parseProofClaims(t, proof, svid.PublicKey)
	assert.Equal(t, wantWTH, claims["wth"],
		"wth must be base64url(SHA-256(WIT compact serialization))")

	// Guard against the tempting-but-wrong RFC 7638 thumbprint reading.
	thumbprint, err := (&jose.JSONWebKey{Key: svid.PublicKey}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.NotEqual(t, base64.RawURLEncoding.EncodeToString(thumbprint), claims["wth"],
		"wth must not be the JWK thumbprint")
}

func TestMintClaimAndHeaderShape(t *testing.T) {
	svid := fixtureSVID(t)

	before := time.Now()
	proof, err := witwpt.Mint(svid, testAudience)
	require.NoError(t, err)

	tok, err := jwt.ParseSigned(proof, allProofAlgorithms)
	require.NoError(t, err)

	t.Run("typ header is wpt+jwt", func(t *testing.T) {
		assert.Equal(t, "wpt+jwt", tok.Headers[0].ExtraHeaders[jose.HeaderType])
	})

	claims := parseProofClaims(t, proof, svid.PublicKey)

	t.Run("aud is the full target URI, query and fragment aside", func(t *testing.T) {
		assert.Equal(t, testAudience, claims["aud"])
	})

	t.Run("exp defaults to DefaultProofLifetime ahead", func(t *testing.T) {
		exp := numericDate(t, claims["exp"])
		assert.WithinDuration(t, before.Add(witwpt.DefaultProofLifetime), exp, 5*time.Second)
	})

	t.Run("jti is present", func(t *testing.T) {
		assert.NotEmpty(t, claims["jti"])
	})

	t.Run("no aud-free or identity claims are invented", func(t *testing.T) {
		// The WPT carries no identity; sub must not appear.
		assert.NotContains(t, claims, "sub")
	})
}

func TestMintAlgTracksCnfJWKAlg(t *testing.T) {
	// wpt-01 §2 requires the proof's alg to string-equal the WIT's cnf.jwk.alg,
	// so it is read from the credential rather than chosen by us.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey := test.NewEC256Key(t)

	tests := []struct {
		alg jose.SignatureAlgorithm
		key crypto.Signer
	}{
		{alg: jose.ES256, key: ecKey},
		{alg: jose.RS256, key: rsaKey},
		{alg: jose.PS256, key: rsaKey},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			svid := makeWITSVID(t, tt.alg, tt.key)

			proof, err := witwpt.Mint(svid, testAudience)
			require.NoError(t, err)

			tok, err := jwt.ParseSigned(proof, allProofAlgorithms)
			require.NoError(t, err)
			assert.Equal(t, string(tt.alg), tok.Headers[0].Algorithm)

			// And the signature really verifies under the cnf public key.
			var claims map[string]any
			require.NoError(t, tok.Claims(tt.key.Public(), &claims))
		})
	}
}

func TestMintJTIIsUniqueAndAtLeast128Bits(t *testing.T) {
	svid := fixtureSVID(t)

	seen := make(map[string]struct{})
	for range 50 {
		proof, err := witwpt.Mint(svid, testAudience)
		require.NoError(t, err)

		jti, ok := parseProofClaims(t, proof, svid.PublicKey)["jti"].(string)
		require.True(t, ok, "jti must be a string")

		raw, err := base64.RawURLEncoding.DecodeString(jti)
		require.NoError(t, err, "jti should be base64url")
		assert.GreaterOrEqual(t, len(raw)*8, 128, "jti must carry at least 128 bits of entropy")

		_, duplicate := seen[jti]
		require.False(t, duplicate, "jti must not repeat")
		seen[jti] = struct{}{}
	}
}

func TestMintWithProofLifetime(t *testing.T) {
	svid := fixtureSVID(t)

	before := time.Now()
	proof, err := witwpt.Mint(svid, testAudience, witwpt.WithProofLifetime(5*time.Second))
	require.NoError(t, err)

	exp := numericDate(t, parseProofClaims(t, proof, svid.PublicKey)["exp"])
	assert.WithinDuration(t, before.Add(5*time.Second), exp, 2*time.Second)
}

func TestMintErrors(t *testing.T) {
	tests := []struct {
		name string
		svid func(*testing.T) *witsvid.SVID
		aud  string
		err  string
	}{
		{
			name: "nil SVID",
			svid: func(*testing.T) *witsvid.SVID { return nil },
			aud:  testAudience,
			err:  "witwpt: no WIT-SVID provided",
		},
		{
			name: "SVID without a private key cannot prove possession",
			svid: func(t *testing.T) *witsvid.SVID {
				svid := fixtureSVID(t)
				svid.PrivateKey = nil
				return svid
			},
			aud: testAudience,
			err: "witwpt: WIT-SVID has no private key, so possession cannot be proven",
		},
		{
			name: "empty audience",
			svid: fixtureSVID,
			aud:  "",
			err:  "witwpt: no audience provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := witwpt.Mint(tt.svid(t), tt.aud)
			require.EqualError(t, err, tt.err)
			assert.Empty(t, proof)
		})
	}
}

// --- helpers ---

var allProofAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// fixtureSVID parses witFixture and attaches its committed private key, giving
// an SVID whose token bytes -- and therefore whose wth -- are constant.
func fixtureSVID(t *testing.T) *witsvid.SVID {
	t.Helper()
	svid, err := witsvid.ParseInsecure(witFixture)
	require.NoError(t, err)
	require.Equal(t, witFixture, svid.Marshal())

	var jwk jose.JSONWebKey
	require.NoError(t, jwk.UnmarshalJSON([]byte(witFixturePrivJWK)))
	svid.PrivateKey = jwk.Key
	return svid
}

// makeWITSVID builds a WIT-SVID whose cnf.jwk.alg is alg and whose confirmation
// key is key, for cases where the token bytes need not be fixed.
func makeWITSVID(t *testing.T, alg jose.SignatureAlgorithm, key crypto.Signer) *witsvid.SVID {
	t.Helper()

	cnfJWK := jose.JSONWebKey{Key: key.Public(), KeyID: "cnf-1", Algorithm: string(alg)}
	cnfBytes, err := cnfJWK.MarshalJSON()
	require.NoError(t, err)
	var cnfMap map[string]any
	require.NoError(t, json.Unmarshal(cnfBytes, &cnfMap))

	authority := test.NewEC256Key(t)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: authority, KeyID: "auth-1"}},
		(&jose.SignerOptions{}).WithType("wit+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(map[string]any{
		"sub": spiffeid.RequireFromString("spiffe://example.org/client").String(),
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"cnf": map[string]any{"jwk": cnfMap},
	}).Serialize()
	require.NoError(t, err)

	svid, err := witsvid.ParseInsecure(token)
	require.NoError(t, err)
	svid.PrivateKey = key
	return svid
}

// parseProofClaims parses a proof and verifies its signature under pub, then
// returns its claims. It never routes through this package's Verify, so mint
// coverage does not depend on verify being correct.
func parseProofClaims(t *testing.T, proof string, pub crypto.PublicKey) map[string]any {
	t.Helper()
	tok, err := jwt.ParseSigned(proof, allProofAlgorithms)
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, tok.Claims(pub, &claims))
	return claims
}

func numericDate(t *testing.T, raw any) time.Time {
	t.Helper()
	seconds, ok := raw.(float64)
	require.True(t, ok, "expected a JSON number, got %T", raw)
	return time.Unix(int64(seconds), 0)
}
