package bundle

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestValidateKeys(t *testing.T) {
	ca := spiffetest.NewCA(t)
	rootCA := ca.CreateCA().Roots()[0]

	testCases := []struct {
		name        string
		doc         string
		errContains string
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
			errContains: `unrecognized use "bad stuff" for key entry 0`,
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
			errContains: "missing use for key entry 0",
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
			errContains: "expected a single certificate in x509-svid entry 0; got 0",
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
			errContains: "expected a single certificate in x509-svid entry 0; got 2",
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

			b, err := Decode(r.Result().Body)
			require.NoError(t, err)
			require.NotNil(t, b)

			valid, invalid := ValidateKeys(b.Keys)
			if testCase.errContains != "" {
				require.Len(t, valid, 0)
				require.Len(t, invalid, 1)
				assert.Contains(t, invalid[0].reason.Error(), testCase.errContains)
				return
			}
			assert.Len(t, invalid, 0)
			assert.Len(t, valid, 1)

		})
	}
}

func x5c(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
