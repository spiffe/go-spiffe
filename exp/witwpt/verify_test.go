package witwpt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Proofs here come from makeWPT rather than Mint, so a misreading shared by
// Mint and Verify cannot pass a loopback test.

const verifyAudience = "https://server.example.org/v2/orders"

type verifyFixture struct {
	bundle    *witbundle.Bundle
	witToken  string
	cnfKey    *ecdsa.PrivateKey
	authority *ecdsa.PrivateKey
	id        spiffeid.ID
	td        spiffeid.TrustDomain
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/client")
	authority := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	const kid = "authority-1"

	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddWITAuthority(kid, authority.Public()))

	witToken := makeWIT(t, authority, kid, id, cnfKey.Public(), jose.ES256,
		time.Now().Add(time.Hour))

	return &verifyFixture{
		bundle:    bundle,
		witToken:  witToken,
		cnfKey:    cnfKey,
		authority: authority,
		id:        id,
		td:        td,
	}
}

// validProofClaims returns the claims of a proof that should verify.
func (f *verifyFixture) validProofClaims() map[string]any {
	return map[string]any{
		"aud": verifyAudience,
		"exp": jwt.NewNumericDate(time.Now().Add(witwpt.DefaultProofLifetime)),
		"jti": "jti-fixture-0001",
		"wth": witwpt.WITThumbprint(f.witToken),
	}
}

func TestVerifyAcceptsAValidPair(t *testing.T) {
	f := newVerifyFixture(t)
	proof := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", f.validProofClaims())

	svid, err := witwpt.Verify(t.Context(), f.witToken, proof, f.bundle,
		serverAudience(t))
	require.NoError(t, err)
	require.NotNil(t, svid)

	assert.Equal(t, f.id, svid.ID, "the identity comes from the WIT-SVID's sub claim")
	assert.Equal(t, f.witToken, svid.Marshal())
	assert.Contains(t, svid.Claims, "cnf")
}

func TestVerifyRejections(t *testing.T) {
	tests := []struct {
		name  string
		stage witwpt.Stage
		// proof builds the proof token; wit optionally overrides the WIT token.
		proof   func(*testing.T, *verifyFixture) string
		wit     func(*testing.T, *verifyFixture) string
		errPart string
	}{
		{
			name:    "proof is missing",
			stage:   witwpt.StageProof,
			proof:   func(*testing.T, *verifyFixture) string { return "" },
			errPart: "no proof token",
		},
		{
			name:    "proof is malformed",
			stage:   witwpt.StageProof,
			proof:   func(*testing.T, *verifyFixture) string { return "not.a.jwt" },
			errPart: "unable to parse",
		},
		{
			name:  "proof signed by a key other than cnf.jwk",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				unrelated := test.NewEC256Key(t)
				return makeWPT(t, unrelated, jose.ES256, "wpt+jwt", f.validProofClaims())
			},
			errPart: "signature",
		},
		{
			name:  "proof alg does not match cnf.jwk.alg",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				key := test.NewEC256Key(t)
				return makeWPT(t, key, jose.ES256, "wpt+jwt", f.validProofClaims())
			},
			wit: func(t *testing.T, f *verifyFixture) string {
				// Declare a different alg in cnf.jwk so alg equality fails first.
				return makeWIT(t, f.authority, "authority-1", f.id, f.cnfKey.Public(),
					jose.ES512, time.Now().Add(time.Hour))
			},
			errPart: "alg",
		},
		{
			name:  "proof signed with a different algorithm than cnf.jwk.alg",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				// An ES384-signed proof, not just a relabeled header.
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return makeWPT(t, key, jose.ES384, "wpt+jwt", f.validProofClaims())
			},
			errPart: "does not match",
		},
		{
			name:  "WIT kid names an authority the bundle does not hold",
			stage: witwpt.StageWIT,
			wit: func(t *testing.T, f *verifyFixture) string {
				return makeWIT(t, f.authority, "rotated-away", f.id, f.cnfKey.Public(),
					jose.ES256, time.Now().Add(time.Hour))
			},
			errPart: "no WIT authority",
		},
		{
			name:  "proof binds an OAuth access token via ath",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				// ath is not enforced here, so accepting it would make the
				// binding look enforced.
				claims := f.validProofClaims()
				claims["ath"] = "Zm9vYmFy"
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "token binding",
		},
		{
			name:  "proof binds a Txn-Token via tth",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				claims["tth"] = "Zm9vYmFy"
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "token binding",
		},
		{
			name:  "proof carries oth entries this verifier does not understand",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				// wpt-01 §2: "If the oth claim contains entries that are not
				// understood by the recipient, the WPT MUST be rejected."
				claims := f.validProofClaims()
				claims["oth"] = map[string]any{"x-vendor-assertion": "Zm9vYmFy"}
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "token binding",
		},
		{
			name:  "proof typ is not wpt+jwt",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				return makeWPT(t, f.cnfKey, jose.ES256, "jwt", f.validProofClaims())
			},
			errPart: "wpt+jwt",
		},
		{
			name:  "proof is bound to a different WIT",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				other := makeWIT(t, f.authority, "authority-1", f.id, f.cnfKey.Public(),
					jose.ES256, time.Now().Add(2*time.Hour))
				claims := f.validProofClaims()
				claims["wth"] = witwpt.WITThumbprint(other)
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "wth",
		},
		{
			name:  "proof is missing wth",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				delete(claims, "wth")
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "wth",
		},
		{
			name:  "proof is for another target",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				claims["aud"] = "https://elsewhere.example.org/v2/orders"
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "not accepted here",
		},
		{
			name:  "proof has expired",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				claims["exp"] = jwt.NewNumericDate(time.Now().Add(-time.Hour))
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "expired",
		},
		{
			name:  "proof exp is implausibly distant",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				claims["exp"] = jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour))
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "too far in the future",
		},
		{
			name:  "proof is missing exp",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				delete(claims, "exp")
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "exp",
		},
		{
			name:  "proof is missing jti",
			stage: witwpt.StageProof,
			proof: func(t *testing.T, f *verifyFixture) string {
				claims := f.validProofClaims()
				delete(claims, "jti")
				return makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)
			},
			errPart: "jti",
		},
		{
			name:    "WIT is missing",
			stage:   witwpt.StageWIT,
			wit:     func(*testing.T, *verifyFixture) string { return "" },
			errPart: "no WIT-SVID token",
		},
		{
			name:    "WIT is malformed",
			stage:   witwpt.StageWIT,
			wit:     func(*testing.T, *verifyFixture) string { return "not.a.jwt" },
			errPart: "witsvid",
		},
		{
			name:  "WIT has expired",
			stage: witwpt.StageWIT,
			wit: func(t *testing.T, f *verifyFixture) string {
				return makeWIT(t, f.authority, "authority-1", f.id, f.cnfKey.Public(),
					jose.ES256, time.Now().Add(-time.Hour))
			},
			errPart: "expired",
		},
		{
			name:  "WIT signed by an authority not in the bundle",
			stage: witwpt.StageWIT,
			wit: func(t *testing.T, f *verifyFixture) string {
				imposter := test.NewEC256Key(t)
				return makeWIT(t, imposter, "authority-1", f.id, f.cnfKey.Public(),
					jose.ES256, time.Now().Add(time.Hour))
			},
			errPart: "signature verification failed",
		},
		{
			name:  "WIT from an unfederated trust domain",
			stage: witwpt.StageWIT,
			wit: func(t *testing.T, f *verifyFixture) string {
				otherTD := spiffeid.RequireTrustDomainFromString("other.org")
				return makeWIT(t, f.authority, "authority-1",
					spiffeid.RequireFromPath(otherTD, "/client"), f.cnfKey.Public(),
					jose.ES256, time.Now().Add(time.Hour))
			},
			errPart: "no WIT bundle found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newVerifyFixture(t)

			witToken := f.witToken
			if tt.wit != nil {
				witToken = tt.wit(t, f)
			}

			// Rebuild valid proof claims against whichever WIT is being sent, so
			// only the property under test is wrong.
			proof := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", map[string]any{
				"aud": verifyAudience,
				"exp": jwt.NewNumericDate(time.Now().Add(witwpt.DefaultProofLifetime)),
				"jti": "jti-fixture-0001",
				"wth": witwpt.WITThumbprint(witToken),
			})
			if tt.proof != nil {
				proof = tt.proof(t, f)
			}

			svid, err := witwpt.Verify(t.Context(), witToken, proof, f.bundle,
				serverAudience(t))

			require.Error(t, err)
			assert.Nil(t, svid)
			assert.ErrorContains(t, err, tt.errPart)

			var verr *witwpt.Error
			require.ErrorAs(t, err, &verr, "failures must carry a machine-readable stage")
			assert.Equal(t, tt.stage, verr.Stage)
		})
	}
}

func TestVerifyValidatesTheWITBeforeTheProof(t *testing.T) {
	// With both tokens broken, the WIT failure is reported (wpt-01 ordering).
	f := newVerifyFixture(t)

	expiredWIT := makeWIT(t, f.authority, "authority-1", f.id, f.cnfKey.Public(),
		jose.ES256, time.Now().Add(-time.Hour))
	garbageProof := "not.a.jwt"

	_, err := witwpt.Verify(t.Context(), expiredWIT, garbageProof, f.bundle,
		serverAudience(t))

	var verr *witwpt.Error
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, witwpt.StageWIT, verr.Stage)
}

func TestVerifyReplayCache(t *testing.T) {
	f := newVerifyFixture(t)
	proof := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", f.validProofClaims())
	audience := serverAudience(t)

	t.Run("without a cache a proof may be presented twice", func(t *testing.T) {
		verifier := witwpt.NewVerifier(f.bundle)
		_, err := verifier.Verify(t.Context(), f.witToken, proof, audience)
		require.NoError(t, err)
		_, err = verifier.Verify(t.Context(), f.witToken, proof, audience)
		require.NoError(t, err, "replay protection is opt-in")
	})

	t.Run("with a cache the second presentation is rejected", func(t *testing.T) {
		verifier := witwpt.NewVerifier(f.bundle,
			witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

		_, err := verifier.Verify(t.Context(), f.witToken, proof, audience)
		require.NoError(t, err)

		_, err = verifier.Verify(t.Context(), f.witToken, proof, audience)
		require.Error(t, err)

		var verr *witwpt.Error
		require.ErrorAs(t, err, &verr)
		assert.Equal(t, witwpt.StageReplay, verr.Stage)
	})

	t.Run("a proof still inside the leeway window cannot be replayed", func(t *testing.T) {
		// The record must last while the proof is acceptable: exp plus leeway.
		verifier := witwpt.NewVerifier(f.bundle,
			witwpt.WithReplayCache(witwpt.NewMemoryReplayCache()))

		claims := f.validProofClaims()
		claims["exp"] = jwt.NewNumericDate(time.Now().Add(-witwpt.DefaultLeeway / 2))
		expiring := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)

		_, err := verifier.Verify(t.Context(), f.witToken, expiring, audience)
		require.NoError(t, err, "precondition: leeway still accepts this proof")

		_, err = verifier.Verify(t.Context(), f.witToken, expiring, audience)
		require.Error(t, err, "the replay must be rejected")

		var verr *witwpt.Error
		require.ErrorAs(t, err, &verr)
		assert.Equal(t, witwpt.StageReplay, verr.Stage)
	})
}

func TestVerifyWithMaxProofLifetime(t *testing.T) {
	f := newVerifyFixture(t)
	audience := serverAudience(t)

	claims := f.validProofClaims()
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(30 * time.Minute))
	proof := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)

	t.Run("rejected under the default maximum", func(t *testing.T) {
		_, err := witwpt.NewVerifier(f.bundle).Verify(t.Context(), f.witToken, proof, audience)
		require.ErrorContains(t, err, "too far in the future")
	})

	t.Run("accepted when the operator raises the maximum", func(t *testing.T) {
		verifier := witwpt.NewVerifier(f.bundle, witwpt.WithMaxProofLifetime(time.Hour))
		_, err := verifier.Verify(t.Context(), f.witToken, proof, audience)
		require.NoError(t, err)
	})
}

func TestVerifyWithLeeway(t *testing.T) {
	f := newVerifyFixture(t)
	audience := serverAudience(t)

	// Expired by 30s: inside a 60s leeway, outside the 10s default.
	claims := f.validProofClaims()
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(-30 * time.Second))
	proof := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", claims)

	t.Run("rejected under the default leeway", func(t *testing.T) {
		_, err := witwpt.NewVerifier(f.bundle).Verify(t.Context(), f.witToken, proof, audience)
		require.ErrorContains(t, err, "expired")
	})

	t.Run("accepted when the operator widens the leeway", func(t *testing.T) {
		verifier := witwpt.NewVerifier(f.bundle, witwpt.WithLeeway(60*time.Second))
		_, err := verifier.Verify(t.Context(), f.witToken, proof, audience)
		require.NoError(t, err)
	})
}

func TestVerifyRequiresAnAudienceMatcher(t *testing.T) {
	f := newVerifyFixture(t)
	proof := makeWPT(t, f.cnfKey, jose.ES256, "wpt+jwt", f.validProofClaims())

	// A nil matcher must fail closed rather than accept any audience.
	_, err := witwpt.Verify(t.Context(), f.witToken, proof, f.bundle, nil)
	require.ErrorContains(t, err, "no audience matcher")
}

// --- local minters ---

// makeWIT builds a WIT-SVID signed by authority, declaring cnfPub as the
// confirmation key with the given alg.
func makeWIT(t *testing.T, authority *ecdsa.PrivateKey, kid string, id spiffeid.ID,
	cnfPub crypto.PublicKey, cnfAlg jose.SignatureAlgorithm, exp time.Time) string {
	t.Helper()

	cnfJWK := jose.JSONWebKey{Key: cnfPub, KeyID: "cnf-1", Algorithm: string(cnfAlg)}
	cnfBytes, err := cnfJWK.MarshalJSON()
	require.NoError(t, err)
	var cnfMap map[string]any
	require.NoError(t, json.Unmarshal(cnfBytes, &cnfMap))

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: authority, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("wit+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(map[string]any{
		"sub": id.String(),
		"exp": jwt.NewNumericDate(exp),
		"iat": jwt.NewNumericDate(time.Now()),
		"cnf": map[string]any{"jwk": cnfMap},
	}).Serialize()
	require.NoError(t, err)
	return token
}

// makeWPT builds a proof token with full control over its alg, typ, and claims,
// so each verification rule can be violated in isolation.
func makeWPT(t *testing.T, key crypto.Signer, alg jose.SignatureAlgorithm, typ string,
	claims map[string]any) string {
	t.Helper()

	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func serverAudience(t *testing.T) witwpt.AudienceMatcher {
	t.Helper()
	matcher, err := witwpt.AcceptAudience("https://server.example.org")
	require.NoError(t, err)
	return matcher
}
