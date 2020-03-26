package jwtsvid_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const hs256Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG" +
	"4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

var (
	key1, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	key2, _ = rsa.GenerateKey(rand.Reader, 2048)
)

func TestParseAndValidate(t *testing.T) {
	// Create numeric dates
	issuedAt := jwt.NewNumericDate(time.Now())
	expiresTime := time.Now().Add(time.Minute)
	expires := jwt.NewNumericDate(expiresTime)

	// Create trust domain
	trustDomain1 := spiffeid.RequireTrustDomainFromString("test.domain")

	// Create a bundle and add keys
	bundle1 := jwtbundle.New(trustDomain1)
	err := bundle1.AddJWTKey("key1", key1.Public())
	require.NoError(t, err)
	err = bundle1.AddJWTKey("key2", key2.Public())
	require.NoError(t, err)

	testCases := []struct {
		name          string
		bundle        *jwtbundle.Bundle
		audience      []string
		generateToken func(testing.TB) string
		err           string
		svid          *jwtsvid.SVID
	}{
		{
			name:   "success",
			bundle: bundle1,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			svid: &jwtsvid.SVID{
				ID:       trustDomain1.NewID("/host"),
				Audience: []string{"audience"},
				Expiry:   expiresTime,
			},
		},
		{
			name:   "malformed",
			bundle: bundle1,
			generateToken: func(tb testing.TB) string {
				return "invalid token"
			},
			err: "jwtsvid: unable to parse JWT token",
		},
		{
			name:   "unsupported algorithm",
			bundle: bundle1,
			generateToken: func(tb testing.TB) string {
				return hs256Token
			},
			err: `jwtsvid: unsupported token signature algorithm "HS256"`,
		},
		{
			name:   "missing subject",
			bundle: bundle1,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token missing subject claim",
		},
		{
			name:   "missing expiration claim",
			bundle: bundle1,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token missing exp claim",
		},
		{
			name:     "expired",
			bundle:   bundle1,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token has expired",
		},
		{
			name:     "unexpected audience",
			bundle:   bundle1,
			audience: []string{"another"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: `jwtsvid: expected audience in ["another"] (audience=["audience"])`,
		},
		{
			name:     "invalid subject claim",
			bundle:   bundle1,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  "invalid subject",
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token has in invalid subject claim: spiffeid: invalid scheme",
		},
		{
			name:     "missing key",
			bundle:   bundle1,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "")
			},
			err: "jwtsvid: token header missing key id",
		},
		{
			name:     "no bundle for trust domain",
			bundle:   bundle1,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  spiffeid.MustJoin("another.domain", "host"),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "noKey")
			},
			err: `jwtsvid: no bundle found for trust domain "another.domain"`,
		},
		{
			name:     "no bundle for key",
			bundle:   bundle1,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "noKey")
			},
			err: `jwtsvid: no key "noKey" found for trust domain "test.domain"`,
		},
		{
			name:     "mismatched key",
			bundle:   bundle1,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key2, "key1")
			},
			err: "jwtsvid: unable to get claims from token: square/go-jose: error in cryptographic primitive",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Generate token
			token := testCase.generateToken(t)

			// Parse and validate
			svid, err := jwtsvid.ParseAndValidate(token, testCase.bundle, testCase.audience)

			// Verify returned error, in case it is expected
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)

			// Verify returned svid
			require.Equal(t, testCase.svid.ID, svid.ID)
			require.Equal(t, testCase.svid.Expiry.Unix(), svid.Expiry.Unix())
			require.Equal(t, testCase.svid.Audience, svid.Audience)

			claims := parseToken(t, token)
			require.Equal(t, claims, svid.Claims)
		})
	}
}

func TestParseInsecure(t *testing.T) {
	// Create numeric dates
	issuedAt := jwt.NewNumericDate(time.Now())
	expiresTime := time.Now().Add(time.Minute)
	expires := jwt.NewNumericDate(expiresTime)

	// Create trust domain
	trustDomain1 := spiffeid.RequireTrustDomainFromString("test.domain")

	testCases := []struct {
		name          string
		audience      []string
		generateToken func(testing.TB) string
		err           string
		svid          *jwtsvid.SVID
	}{
		{
			name: "success",
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			svid: &jwtsvid.SVID{
				ID:       trustDomain1.NewID("/host"),
				Audience: []string{"audience"},
				Expiry:   expiresTime,
			},
		},
		{
			name: "malformed",
			generateToken: func(tb testing.TB) string {
				return "invalid token"
			},
			err: "jwtsvid: unable to parse JWT token",
		},
		{
			name: "invalid algorithm",
			generateToken: func(tb testing.TB) string {
				return hs256Token
			},
			err: `jwtsvid: unsupported token signature algorithm "HS256"`,
		},
		{
			name: "missing subject claim",
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token missing subject claim",
		},
		{
			name: "missing expiration claim",
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token missing exp claim",
		},
		{
			name:     "expired",
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: "jwtsvid: token has expired",
		},
		{
			name:     "unexpected audience",
			audience: []string{"another"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  trustDomain1.NewID("host").String(),
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: `jwtsvid: expected audience in ["another"] (audience=["audience"])`,
		},
		{
			name:     "invalid subject claim",
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  "invalid subject",
					Issuer:   "issuer",
					Expiry:   expires,
					Audience: []string{"audience"},
					IssuedAt: issuedAt,
				}

				return generateToken(tb, claims, key1, "key1")
			},
			err: `jwtsvid: token has in invalid subject claim: spiffeid: invalid scheme`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Create token
			token := testCase.generateToken(t)

			// Call ParseInsecure
			svid, err := jwtsvid.ParseInsecure(token, testCase.audience)

			// Verify returned error, in case it is expected
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)

			// Verify SVID
			require.Equal(t, testCase.svid.ID, svid.ID)
			require.Equal(t, testCase.svid.Expiry.Unix(), svid.Expiry.Unix())
			require.Equal(t, testCase.svid.Audience, svid.Audience)

			claims := parseToken(t, token)
			require.Equal(t, claims, svid.Claims)
		})
	}
}

func TestMarshal(t *testing.T) {
	// Generate trust domain
	trustDomain1 := spiffeid.RequireTrustDomainFromString("test.domain")

	// Generate Token
	claims := jwt.Claims{
		Subject:  trustDomain1.NewID("host").String(),
		Issuer:   "issuer",
		Expiry:   jwt.NewNumericDate(time.Now()),
		Audience: []string{"audience"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}
	token := generateToken(t, claims, key1, "key1")

	// Create SVID
	svid, err := jwtsvid.ParseInsecure(token, []string{"audience"})
	require.NoError(t, err)
	// Validate token is returned
	require.Equal(t, token, svid.Marshal())

	// Update SVID does not affect token
	svid.ID = trustDomain1.NewID("host2")
	require.Equal(t, token, svid.Marshal())

	// Empty Marshall when no token
	svid = &jwtsvid.SVID{}
	require.Empty(t, svid.Marshal())
}

func parseToken(t testing.TB, token string) map[string]interface{} {
	tok, err := jwt.ParseSigned(token)
	require.NoError(t, err)
	claimsMap := make(map[string]interface{})
	err = tok.UnsafeClaimsWithoutVerification(&claimsMap)
	require.NoError(t, err)
	return claimsMap
}

// Generate generates a signed string token
func generateToken(tb testing.TB, claims jwt.Claims, signer crypto.Signer, keyID string) string {
	// Get signer algorithm
	alg, err := getSignerAlgorithm(signer)
	require.NoError(tb, err)

	// Create signer using crypto.Signer and its algorithm along with provided key ID
	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: keyID,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(tb, err)

	// Sign and serialize token
	token, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	require.NoError(tb, err)

	return token
}

// getSignerAlgorithm deduces signer algorithm and return it
func getSignerAlgorithm(signer crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch publicKey := signer.Public().(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", fmt.Errorf("unsupported RSA key size: %d", publicKey.Size())
		}
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			return jose.ES256, nil
		case 384:
			return jose.ES384, nil
		default:
			return "", fmt.Errorf("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	default:
		return "", fmt.Errorf("unable to determine signature algorithm for public key type %T", publicKey)
	}
}
