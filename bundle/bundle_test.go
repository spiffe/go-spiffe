package bundle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestRootCAs(t *testing.T) {
	ca1ID := spiffe.TrustDomainURI("trustdomain1.com")
	ca1 := &x509.Certificate{
		URIs: []*url.URL{
			ca1ID,
		},
	}

	ca2ID := spiffe.TrustDomainURI("trustdomain2.com")
	ca2 := &x509.Certificate{
		URIs: []*url.URL{
			ca2ID,
		},
	}

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testCases := []struct {
		name    string
		bundle  *Bundle
		rootCAs []*x509.Certificate
	}{
		{
			name: "bundle without keys",
			bundle: &Bundle{
				JSONWebKeySet: jose.JSONWebKeySet{},
			},
		},
		{
			name: "bundle without rootCAs",
			bundle: &Bundle{
				JSONWebKeySet: jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							KeyID: ca1ID.String(),
							Key:   key1.Public(),
							Use:   string(UseJWTSVID),
						},
					},
				},
			},
		},
		{
			name: "bundle with empty JWTSVID",
			bundle: &Bundle{
				JSONWebKeySet: jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							KeyID: ca1ID.String(),
							Key:   key1.Public(),
							Use:   string(UseJWTSVID),
						},
						{
							Certificates: []*x509.Certificate{},
							Use:          string(UseX509SVID),
						},
					},
				},
			},
		},
		{
			name: "bundle single rootCA",
			bundle: &Bundle{
				JSONWebKeySet: jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							KeyID: ca1ID.String(),
							Key:   key1.Public(),
							Use:   string(UseJWTSVID),
						},
						{
							KeyID:        ca1ID.String(),
							Certificates: []*x509.Certificate{ca1},
							Use:          string(UseX509SVID),
						},
					},
				},
			},
			rootCAs: []*x509.Certificate{ca1},
		},
		{
			name: "bundle multiple rootCAs",
			bundle: &Bundle{
				JSONWebKeySet: jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							KeyID:        ca1ID.String(),
							Certificates: []*x509.Certificate{ca1},
							Use:          string(UseX509SVID),
						},
						{
							KeyID:        ca2ID.String(),
							Certificates: []*x509.Certificate{ca2},
							Use:          string(UseX509SVID),
						},
					},
				},
			},
			rootCAs: []*x509.Certificate{ca1, ca2},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			rootCAs := testCase.bundle.RootCAs()
			require.Equal(t, testCase.rootCAs, rootCAs)
		})
	}
}

func TestDecode(t *testing.T) {
	testCases := []struct {
		name        string
		doc         string
		errContains string
		sequence    uint64
		refreshHint int
	}{
		{
			name:        "Fails because it is not a json document",
			doc:         "not a json",
			errContains: "failed to decode bundle",
		},
		{
			name: "Fails because it contains invalid key",
			doc: `{
				"keys": [
					{
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			errContains: "key validation failed: found 1 invalid key(s)",
		},
		{
			name:        "Success",
			doc:         `{"spiffe_refresh_hint": 10, "spiffe_sequence": 2}`,
			refreshHint: 10,
			sequence:    2,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			_, err := r.Write([]byte(testCase.doc))
			require.NoError(t, err)

			b, err := Decode(r.Result().Body)
			if testCase.errContains != "" {
				require.Contains(t, err.Error(), testCase.errContains)
				require.Nil(t, b)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, b)
			assert.Equal(t, b.Sequence, testCase.sequence)
			assert.Equal(t, b.RefreshHint, testCase.refreshHint)
		})
	}
}

func TestDecodeLenient(t *testing.T) {
	testCases := []struct {
		name           string
		doc            string
		errContains    string
		sequence       uint64
		refreshHint    int
		invalidKeysLen int
		bundleKeysLen  int
	}{
		{
			name:        "Fails because it is not a json document",
			doc:         "not a json",
			errContains: "failed to decode bundle",
		},
		{
			name:           "Success with invalid key",
			invalidKeysLen: 1,
			bundleKeysLen:  0,
			doc: `{
				"keys": [
					{
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
		},
		{
			name:        "Success",
			doc:         `{"spiffe_refresh_hint": 10, "spiffe_sequence": 2}`,
			refreshHint: 10,
			sequence:    2,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			_, err := r.Write([]byte(testCase.doc))
			require.NoError(t, err)

			b, invalidKeys, err := DecodeLenient(r.Result().Body)
			if testCase.errContains != "" {
				require.Contains(t, err.Error(), testCase.errContains)
				require.Nil(t, b)
				require.Nil(t, invalidKeys)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, b.Sequence, testCase.sequence)
			assert.Equal(t, b.RefreshHint, testCase.refreshHint)

			require.NotNil(t, b)
			assert.Len(t, b.Keys, testCase.bundleKeysLen)

			require.NotNil(t, invalidKeys)
			assert.Len(t, invalidKeys, testCase.invalidKeysLen)
		})
	}
}

func TestValidateKeys(t *testing.T) {
	ca := spiffetest.NewCA(t)
	rootCA := ca.CreateCA().Roots()[0]

	testCases := []struct {
		name   string
		doc    string
		reason InvalidKeyReason
	}{
		{
			name: "unrecognized use",
			doc: `{
				"keys": [
					{
						"use": "bad stuff",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			reason: ReasonUnrecognizedUse,
		},
		{
			name: "entry missing use",
			doc: `{
				"keys": [
					{
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			reason: ReasonMissingUse,
		},
		{
			name: "x509-svid without x5c",
			doc: `{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			reason: ReasonSingleCertExpected,
		},
		{
			name: "x509-svid with more than one x5c",
			doc: fmt.Sprintf(`{
			"keys": [
				{
					"use": "x509-svid",
					"kty": "EC",
					"crv": "P-256",
					"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
					"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
					"x5c": [
						%q,
						%q
					]
				}
			]
		}`, x5c(rootCA), x5c(rootCA)),
			reason: ReasonSingleCertExpected,
		},
		{
			name: "valid x509-svid",
			doc: fmt.Sprintf(`{
			"keys": [
				{
					"use": "x509-svid",
					"kty": "EC",
					"crv": "P-256",
					"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
					"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
					"x5c": [
						%q
					]
				}
			]
		}`, x5c(rootCA)),
		},

		{
			name: "valid jwt-svid",
			doc: `{
				"keys": [
					{
						"use": "jwt-svid",
						"kty": "EC",
						"crv": "P-256",
						"kid": "key-id",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			_, err := r.Write([]byte(testCase.doc))
			require.NoError(t, err)

			b := new(Bundle)
			err = json.NewDecoder(r.Result().Body).Decode(b)
			require.NoError(t, err)
			require.NotNil(t, b)

			valid, invalid := ValidateKeys(b.Keys)
			if testCase.reason != "" {
				require.Len(t, valid, 0)
				require.Len(t, invalid, 1)
				assert.Equal(t, invalid[0].Reason, testCase.reason)
				return
			}
			assert.Len(t, invalid, 0)
			assert.Len(t, valid, 1)
		})
	}
}

func TestKeysForUse(t *testing.T) {
	ca := spiffetest.NewCA(t)
	rootCA := ca.CreateCA().Roots()[0]

	testCases := []struct {
		name    string
		doc     string
		lenJWT  int
		lenX509 int
	}{
		{
			name:   "Only one JWT key",
			lenJWT: 1,
			doc: `{
				"keys": [
					{
						"use": "jwt-svid",
						"kty": "EC",
						"crv": "P-256",
						"kid": "key-id",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
		},
		{
			name:    "Only one X509 key",
			lenX509: 1,
			doc: fmt.Sprintf(`{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							%q
						]
					}
				]
			}`, x5c(rootCA)),
		},
		{
			name:    "Two different key uses",
			lenJWT:  1,
			lenX509: 1,
			doc: fmt.Sprintf(`{
				"keys": [
					{
						"use": "jwt-svid",
						"kty": "EC",
						"crv": "P-256",
						"kid": "key-id",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					},
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							%q
						]
					}
				]
			}`, x5c(rootCA)),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			_, err := r.Write([]byte(testCase.doc))
			require.NoError(t, err)

			b, err := Decode(r.Result().Body)
			require.NoError(t, err)
			require.NotNil(t, b)

			assert.Len(t, b.KeysForUse(UseJWTSVID), testCase.lenJWT)
			assert.Len(t, b.KeysForUse(UseX509SVID), testCase.lenX509)
		})
	}
}

func x5c(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
