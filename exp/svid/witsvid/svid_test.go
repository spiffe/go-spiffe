package witsvid_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Pre-baked HS256 token; exercises the "unsupported algorithm" path since
// go-jose won't produce HS256 tokens via the public signer API.
const hs256Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG" +
	"4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

var (
	td       = spiffeid.RequireTrustDomainFromString("example.org")
	workload = spiffeid.RequireFromPath(td, "/workload")
)

func TestParseInsecure(t *testing.T) {
	key := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	const kid = "key-1"

	// withClaims builds a valid "wit+jwt" token, applying fn to the claims
	// map before signing. Pass nil fn to get an unmodified valid token.
	withClaims := func(fn func(map[string]any)) func(*testing.T) string {
		return func(t *testing.T) string {
			t.Helper()
			c := makeValidClaims(t, workload, cnfKey.Public(), kid)
			if fn != nil {
				fn(c)
			}
			return makeToken(t, key, kid, "wit+jwt", c)
		}
	}

	tests := []struct {
		name  string
		token func(*testing.T) string
		err   string
		check func(*testing.T, *witsvid.SVID)
	}{
		{
			name:  "valid token",
			token: withClaims(nil),
			check: func(t *testing.T, svid *witsvid.SVID) {
				assert.Equal(t, workload, svid.ID)
				assert.Equal(t, kid, svid.KeyID)
				assert.NotNil(t, svid.PublicKey)
				assert.NotZero(t, svid.Expiry)
				assert.NotEmpty(t, svid.Marshal())
			},
		},
		{
			name: "nbf in the past is accepted",
			token: withClaims(func(c map[string]any) {
				c["nbf"] = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			}),
		},
		{
			name:  "malformed",
			token: func(*testing.T) string { return "not.a.valid.jwt" },
			err:   "witsvid: unable to parse WIT-SVID token",
		},
		{
			name:  "unsupported algorithm",
			token: func(*testing.T) string { return hs256Token },
			err:   "witsvid: unable to parse WIT-SVID token",
		},
		{
			name: "wrong typ",
			token: func(t *testing.T) string {
				return makeToken(t, key, kid, "JWT", makeValidClaims(t, workload, cnfKey.Public(), kid))
			},
			err: `witsvid: token header type must be "wit+jwt", got "JWT"`,
		},
		{
			name: "missing typ",
			token: func(t *testing.T) string {
				return makeToken(t, key, kid, "", makeValidClaims(t, workload, cnfKey.Public(), kid))
			},
			err: `witsvid: token header type must be "wit+jwt", got ""`,
		},
		{
			name: "missing kid",
			token: func(t *testing.T) string {
				return makeToken(t, key, "", "wit+jwt", makeValidClaims(t, workload, cnfKey.Public(), kid))
			},
			err: "witsvid: token header missing key id",
		},
		{
			name:  "missing sub",
			token: withClaims(func(c map[string]any) { delete(c, "sub") }),
			err:   "witsvid: token missing subject claim",
		},
		{
			name:  "missing exp",
			token: withClaims(func(c map[string]any) { delete(c, "exp") }),
			err:   "witsvid: token missing exp claim",
		},
		{
			name: "aud present",
			token: withClaims(func(c map[string]any) {
				c["aud"] = []string{"audience"}
			}),
			err: "witsvid: WIT-SVID must not contain aud claim",
		},
		{
			name: "invalid sub",
			token: withClaims(func(c map[string]any) {
				c["sub"] = "not-a-spiffe-id"
			}),
			err: "witsvid: token has an invalid subject claim: scheme is missing or invalid",
		},
		{
			name: "expired",
			token: withClaims(func(c map[string]any) {
				c["exp"] = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			}),
			err: "witsvid: token has expired",
		},
		{
			name: "nbf in future",
			token: withClaims(func(c map[string]any) {
				c["nbf"] = jwt.NewNumericDate(time.Now().Add(time.Hour))
			}),
			err: "witsvid: token is not yet valid",
		},
		{
			name:  "missing cnf",
			token: withClaims(func(c map[string]any) { delete(c, "cnf") }),
			err:   "witsvid: token missing cnf claim",
		},
		{
			name: "cnf not an object",
			token: withClaims(func(c map[string]any) {
				c["cnf"] = "not-an-object"
			}),
			err: "witsvid: cnf claim is not an object",
		},
		{
			name: "missing cnf.jwk",
			token: withClaims(func(c map[string]any) {
				c["cnf"] = map[string]any{"other": "field"}
			}),
			err: "witsvid: cnf claim missing jwk field",
		},
		{
			name: "cnf.jwk not an object",
			token: withClaims(func(c map[string]any) {
				c["cnf"] = map[string]any{"jwk": "not-an-object"}
			}),
			err: "witsvid: cnf.jwk is not an object",
		},
		{
			name: "cnf.jwk missing alg",
			token: withClaims(func(c map[string]any) {
				jwkMap := makeCnfJWKMap(t, cnfKey.Public(), kid)
				delete(jwkMap, "alg")
				c["cnf"] = map[string]any{"jwk": jwkMap}
			}),
			err: "witsvid: cnf.jwk missing alg field",
		},
		{
			name: "cnf.jwk alg not a string",
			token: withClaims(func(c map[string]any) {
				// Integer value: after JWT JSON round-trip this becomes float64,
				// failing the string type assertion in extractCnfJWK.
				jwkMap := makeCnfJWKMap(t, cnfKey.Public(), kid)
				jwkMap["alg"] = 123
				c["cnf"] = map[string]any{"jwk": jwkMap}
			}),
			err: "witsvid: cnf.jwk alg field is not a string",
		},
		{
			name: "cnf.jwk alg unsupported",
			token: withClaims(func(c map[string]any) {
				jwkMap := makeCnfJWKMap(t, cnfKey.Public(), kid)
				jwkMap["alg"] = "HS256"
				c["cnf"] = map[string]any{"jwk": jwkMap}
			}),
			err: `witsvid: cnf.jwk alg "HS256" is not supported`,
		},
		{
			name: "cnf.jwk is private key",
			token: withClaims(func(c map[string]any) {
				// Pass private key so the marshaled JWK contains private material.
				c["cnf"] = map[string]any{"jwk": makeCnfJWKMap(t, cnfKey, kid)}
			}),
			err: "witsvid: cnf.jwk must be a public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := tt.token(t)
			svid, err := witsvid.ParseInsecure(tok)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.Nil(t, svid)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, svid)
			if tt.check != nil {
				tt.check(t, svid)
			}
		})
	}
}

func TestParseAndValidate(t *testing.T) {
	signingKey := test.NewEC256Key(t)
	wrongKey := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	const kid = "key-1"

	// Build the token once; all subtests reuse it, varying only the bundle.
	tok := makeToken(t, signingKey, kid, "wit+jwt", makeValidClaims(t, workload, cnfKey.Public(), kid))

	t.Run("valid token", func(t *testing.T) {
		bundle := witbundle.New(td)
		require.NoError(t, bundle.AddWITAuthority(kid, signingKey.Public()))

		svid, err := witsvid.ParseAndValidate(tok, bundle)
		require.NoError(t, err)
		assert.Equal(t, workload, svid.ID)
		assert.Equal(t, kid, svid.KeyID)
		assert.NotNil(t, svid.PublicKey)
	})

	t.Run("no bundle for trust domain", func(t *testing.T) {
		bundle := witbundle.New(spiffeid.RequireTrustDomainFromString("other.org"))
		_, err := witsvid.ParseAndValidate(tok, bundle)
		require.EqualError(t, err, `witsvid: no WIT bundle found for trust domain "example.org"`)
	})

	t.Run("no authority for key ID", func(t *testing.T) {
		bundle := witbundle.New(td) // empty — kid not registered
		_, err := witsvid.ParseAndValidate(tok, bundle)
		require.EqualError(t, err, `witsvid: no WIT authority "key-1" found for trust domain "example.org"`)
	})

	t.Run("signature mismatch", func(t *testing.T) {
		// Bundle holds wrongKey, but token is signed with signingKey.
		bundle := witbundle.New(td)
		require.NoError(t, bundle.AddWITAuthority(kid, wrongKey.Public()))
		_, err := witsvid.ParseAndValidate(tok, bundle)
		require.ErrorContains(t, err, "witsvid: signature verification failed")
	})
}

func TestMarshal(t *testing.T) {
	key := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	tok := makeToken(t, key, "key-1", "wit+jwt", makeValidClaims(t, workload, cnfKey.Public(), "cnf-key"))

	svid, err := witsvid.ParseInsecure(tok)
	require.NoError(t, err)
	assert.Equal(t, tok, svid.Marshal())
	assert.Empty(t, (&witsvid.SVID{}).Marshal())
}

// makeCnfJWKMap returns the JSON map for the cnf.jwk claim. key may be a
// public or private key — passing a private key exercises the
// "cnf.jwk must be a public key" failure path.
func makeCnfJWKMap(t *testing.T, key any, kid string) map[string]any {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.ES256)}
	data, err := jwk.MarshalJSON()
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	return m
}

// makeValidClaims returns a complete, valid WIT-SVID claims map.
func makeValidClaims(t *testing.T, id spiffeid.ID, cnfPub any, kid string) map[string]any {
	t.Helper()
	return map[string]any{
		"sub": id.String(),
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat": jwt.NewNumericDate(time.Now()),
		"cnf": map[string]any{"jwk": makeCnfJWKMap(t, cnfPub, kid)},
	}
}

// makeToken builds and signs a WIT-SVID token. An empty typ omits the typ
// header entirely (producing typ="" when parsed).
func makeToken(t *testing.T, signingKey *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	opts := new(jose.SignerOptions)
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       jose.JSONWebKey{Key: signingKey, KeyID: kid},
		},
		opts,
	)
	require.NoError(t, err)
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return tok
}
