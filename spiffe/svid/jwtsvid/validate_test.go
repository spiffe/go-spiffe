package jwtsvid

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/spiffe/svid/bundle"
	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestValidateAlgorithm(t *testing.T) {
	testCases := []struct {
		name  string
		token *jwt.JSONWebToken
		err   string
	}{
		{
			name: "multiple headers",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "RS256"},
					{KeyID: "key2", Algorithm: "RS384"},
				},
			},
			err: "expected a single token header; got 2",
		},
		{
			name: "invalid algorithm",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "HS256"},
				},
			},
			err: "unsupported token signature algorithm \"HS256\"",
		},
		{
			name: "RS256",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "RS256"},
				},
			},
		},
		{
			name: "RS384",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "RS384"},
				},
			},
		},
		{
			name: "RS512",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "RS512"},
				},
			},
		},
		{
			name: "ES256",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "ES256"},
				},
			},
		},
		{
			name: "ES384",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "ES384"},
				},
			},
		}, {
			name: "ES512",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "ES512"},
				},
			},
		}, {
			name: "PS256",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "PS256"},
				},
			},
		}, {
			name: "PS384",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "PS384"},
				},
			},
		}, {
			name: "PS512",
			token: &jwt.JSONWebToken{
				Headers: []jose.Header{
					{KeyID: "key1", Algorithm: "PS512"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			err := validateTokenAlgorithm(testCase.token)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetSpiffeID(t *testing.T) {
	// Create keys
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create bundle
	bundle1 := &bundle.Bundle{
		TrustDomainID: "spiffe://trustdomain1.com",
		RootCAs:       []*x509.Certificate{},
		JWTKeys: map[string]crypto.PublicKey{
			"key1": key1.Public(),
			"key2": key2.Public(),
		},
	}

	// Add bundle to Bundles map
	bundles := bundle.Bundles{bundle1.TrustDomainID: bundle1}

	// Create a success token generator, it will be updated on each test case to make it fails in different scenarios
	tg := &spiffetest.TokenGenerator{
		TB:       t,
		Issuer:   "issuer",
		SpiffeID: "spiffe://trustdomain1.com/token",
		Audience: []string{"audience"},
		Expires:  time.Now().Add(time.Minute),
		Signer:   key1,
		KeyID:    "key1",
	}

	// serialize success scenario it will be used multiple times
	successToken := tg.Generate()

	testCases := []struct {
		name          string
		spiffeID      string
		keyStore      bundle.KeyStore
		err           string
		generateToken func(tg spiffetest.TokenGenerator) string
		audience      []string
	}{
		{
			name: "invalid token",
			err:  "unable to parse JWT token",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				return "invalid token"
			},
		},
		{
			name: "no key id",
			err:  "token header missing key id",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				tg.KeyID = ""
				return tg.Generate()
			},
		},
		{
			name: "no subject",
			err:  "token missing subject claim",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				tg.SpiffeID = ""
				return tg.Generate()
			},
		}, {
			name: "invalid SPIFFE ID",
			err:  "token has in invalid subject claim: invalid workload SPIFFE ID \"invalidId\": invalid scheme",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				tg.SpiffeID = "invalidId"
				return tg.Generate()
			},
		},
		{
			name:     "bundle not found",
			keyStore: bundles,
			err:      "no keys found for trust domain \"spiffe://trustdomain2.com\"",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				tg.SpiffeID = "spiffe://trustdomain2.com/token"
				return tg.Generate()
			},
		},
		{
			name:     "another signer",
			keyStore: bundles,
			err:      "unable to get claims from token: square/go-jose: error in cryptographic primitive",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				tg.KeyID = "key2"
				return tg.Generate()
			},
		},
		{
			name:     "invalid audience",
			keyStore: bundles,
			audience: []string{"something else"},
			err:      "expected audience in [\"something else\"] (audience=[\"audience\"])",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				return successToken
			},
		},
		{
			name:     "expired token",
			keyStore: bundles,
			err:      "token has expired",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				tg.Expires = time.Now().Add(-1 * time.Minute)
				return tg.Generate()
			},
		},
		{
			name:     "success",
			keyStore: bundles,
			spiffeID: "spiffe://trustdomain1.com/token",

			generateToken: func(tg spiffetest.TokenGenerator) string {
				return successToken
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			spiffeID, err := GetSpiffeID(testCase.generateToken(*tg), testCase.keyStore, testCase.audience)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				require.Empty(t, spiffeID)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.spiffeID, spiffeID)
		})
	}
}
