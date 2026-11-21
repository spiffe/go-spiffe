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

// witFixture is a fixed WIT-SVID expiring in 2100 with a filler signature,
// which ParseInsecure accepts, so its wth is a stable constant.
const witFixture = "eyJhbGciOiJFUzI1NiIsImtpZCI6IndpdC1hdXRob3JpdHktMSIsInR5cCI6IndpdCtqd3QifQ." +
	"eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjbmYtMSIsImt0eSI6IkVDIiwi" +
	"eCI6ImlLWnM3QzlPTWFrWm9DTkZDSmpjSWU4aHB4QkR2SGVDSTJsdzVnRVR1dWsiLCJ5IjoieHkzMGFfYzJ3YmduMkxl" +
	"SV9od28xRVR3S2tzb0szemlTZGVyM2loOTR3OCJ9fSwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjE3NTAwMDAwMDAsImlz" +
	"cyI6InNwaWZmZTovL2V4YW1wbGUub3JnIiwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvY2xpZW50In0." +
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"

// witFixturePrivJWK is the test-only private half of witFixture's cnf.jwk.
const witFixturePrivJWK = `{"kty":"EC","kid":"cnf-1","crv":"P-256","alg":"ES256",` +
	`"x":"iKZs7C9OMakZoCNFCJjcIe8hpxBDvHeCI2lw5gETuuk",` +
	`"y":"xy30a_c2wbgn2LeI_hwo1ETwKksoK3ziSder3ih94w8",` +
	`"d":"i7Q5Wgfd1jPpqMlApObMNHhkyTSEnVVLKtLfIOizFPE"}`

// wantWTH is base64url(SHA-256(witFixture)), computed outside this package with:
//
//	printf '%s' "$WIT" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
const wantWTH = "YbWmBlkKlYIC8qAmT-RLp-ZWyPIfrijSxszwpN3CUyQ"

const testAudience = "https://server.example.org/v2/orders"

// TestMintWTHMatchesIndependentlyDerivedConstant pins wth to an external value,
// since a misreading shared by Mint and Verify would still round-trip.
func TestMintWTHMatchesIndependentlyDerivedConstant(t *testing.T) {
	svid := fixtureSVID(t)

	proof, err := witwpt.Mint(svid, testAudience)
	require.NoError(t, err)

	claims := parseProofClaims(t, proof, svid.PublicKey)
	assert.Equal(t, wantWTH, claims["wth"],
		"wth must be base64url(SHA-256(WIT compact serialization))")

	// wth is not the RFC 7638 JWK thumbprint.
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

	t.Run("claim set is exactly aud, exp, iat, jti, and wth", func(t *testing.T) {
		names := make([]string, 0, len(claims))
		for name := range claims {
			names = append(names, name)
		}
		assert.ElementsMatch(t, []string{"aud", "exp", "iat", "jti", "wth"}, names)
	})

	t.Run("aud is the audience as given", func(t *testing.T) {
		assert.Equal(t, testAudience, claims["aud"])
	})

	t.Run("iat is the minting time", func(t *testing.T) {
		assert.WithinDuration(t, before, numericDate(t, claims["iat"]), 2*time.Second)
	})

	t.Run("exp defaults to DefaultProofLifetime after iat", func(t *testing.T) {
		iat := numericDate(t, claims["iat"])
		assert.Equal(t, iat.Add(witwpt.DefaultProofLifetime), numericDate(t, claims["exp"]))
	})

	t.Run("jti is present", func(t *testing.T) {
		assert.NotEmpty(t, claims["jti"])
	})
}

func TestMintAlgTracksCnfJWKAlg(t *testing.T) {
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
	withClaims := func(edit func(claims map[string]any)) func(*testing.T) *witsvid.SVID {
		return func(t *testing.T) *witsvid.SVID {
			svid := fixtureSVID(t)
			edit(svid.Claims)
			return svid
		}
	}

	tests := []struct {
		name string
		svid func(*testing.T) *witsvid.SVID
		aud  string
		opts []witwpt.MintOption
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
		{
			name: "SVID without a token",
			svid: func(t *testing.T) *witsvid.SVID {
				return &witsvid.SVID{PrivateKey: test.NewEC256Key(t)}
			},
			aud: testAudience,
			err: "witwpt: WIT-SVID has no token to bind the proof to",
		},
		{
			name: "expired SVID",
			svid: func(t *testing.T) *witsvid.SVID {
				svid := fixtureSVID(t)
				svid.Expiry = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
				return svid
			},
			aud: testAudience,
			err: "witwpt: WIT-SVID expired at 2020-01-01T00:00:00Z",
		},
		{
			name: "missing cnf",
			svid: withClaims(func(claims map[string]any) { delete(claims, "cnf") }),
			aud:  testAudience,
			err:  "witwpt: WIT-SVID claims have no cnf object",
		},
		{
			name: "missing cnf.jwk",
			svid: withClaims(func(claims map[string]any) { claims["cnf"] = map[string]any{} }),
			aud:  testAudience,
			err:  "witwpt: WIT-SVID cnf claim has no jwk object",
		},
		{
			name: "missing cnf.jwk.alg",
			svid: withClaims(func(claims map[string]any) {
				delete(claims["cnf"].(map[string]any)["jwk"].(map[string]any), "alg")
			}),
			aud: testAudience,
			err: "witwpt: WIT-SVID cnf.jwk has no alg",
		},
		{
			name: "private key is not a signer",
			svid: func(t *testing.T) *witsvid.SVID {
				svid := fixtureSVID(t)
				svid.PrivateKey = "not a key"
				return svid
			},
			aud: testAudience,
			err: "witwpt: WIT-SVID private key of type string cannot sign",
		},
		{
			name: "private key does not match the confirmation key",
			svid: func(t *testing.T) *witsvid.SVID {
				svid := fixtureSVID(t)
				svid.PrivateKey = test.NewEC256Key(t)
				return svid
			},
			aud: testAudience,
			err: "witwpt: WIT-SVID private key does not match its cnf.jwk",
		},
		{
			name: "zero proof lifetime",
			svid: fixtureSVID,
			aud:  testAudience,
			opts: []witwpt.MintOption{witwpt.WithProofLifetime(0)},
			err:  "witwpt: proof lifetime must be positive, got 0s",
		},
		{
			name: "negative proof lifetime",
			svid: fixtureSVID,
			aud:  testAudience,
			opts: []witwpt.MintOption{witwpt.WithProofLifetime(-time.Second)},
			err:  "witwpt: proof lifetime must be positive, got -1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := witwpt.Mint(tt.svid(t), tt.aud, tt.opts...)
			require.EqualError(t, err, tt.err)
			assert.Empty(t, proof)
		})
	}
}

func TestMintRejectsAlgorithmThatDoesNotSuitTheKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	proof, err := witwpt.Mint(makeWITSVID(t, jose.ES256, rsaKey), testAudience)
	require.ErrorContains(t, err, "witwpt: unable to build proof signer")
	assert.Empty(t, proof)
}

// --- helpers ---

var allProofAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// fixtureSVID returns witFixture parsed, with its private key attached.
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

// parseProofClaims parses a proof, verifies its signature under pub, and
// returns its claims.
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
