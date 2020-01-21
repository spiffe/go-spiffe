package endpoint

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	testCases := []struct {
		name        string
		errContains string
		config      ClientConfig
	}{
		{
			name:   "Success web PKI authentication",
			config: ClientConfig{Address: "localhost:9999"},
		},
		{
			name: "Success SPIFFE authentication",
			config: ClientConfig{
				Address: "localhost:9999",
				Auth: &AuthConfig{
					ServerID: "spiffe://example.org/bundle",
					RootCAs:  []*x509.Certificate{&x509.Certificate{}},
				},
			},
		},
		{
			name:        "Fail because of empty Server ID",
			errContains: "bundle endpoint spiffe ID is required",
			config: ClientConfig{
				Address: "localhost:9999",
				Auth:    &AuthConfig{RootCAs: []*x509.Certificate{}},
			},
		},
		{
			name:        "Fail because Server ID is malformed",
			errContains: "cannot get TLS config: unable to get trust domain from SPIFFE ID",
			config: ClientConfig{
				Address: "localhost:9999",
				Auth: &AuthConfig{
					ServerID: "not a spiffe ID",
					RootCAs:  []*x509.Certificate{&x509.Certificate{}},
				},
			},
		},
		{
			name:        "Fail because no initial root CAs are provided",
			errContains: "an initial up-to-date bundle from the remote trust domain is required",
			config: ClientConfig{
				Address: "localhost:9999",
				Auth: &AuthConfig{
					ServerID: "spiffe://example.org/bundle",
				},
			},
		},
		{
			name:        "Fail because of empty endpoint address",
			errContains: "bundle endpoint address is required",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client, err := NewClient(testCase.config)
			if testCase.errContains != "" {
				assert.Contains(t, err.Error(), testCase.errContains)
				assert.Nil(t, client)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestFetchBundle(t *testing.T) {
	testCases := []struct {
		name        string
		spiffeID    string
		status      int
		body        string
		errContains string
	}{
		{
			name:     "success",
			status:   http.StatusOK,
			spiffeID: "spiffe://example.org/bundle",
			body:     `{"spiffe_refresh_hint": 10}`,
		},
		{
			name:        "SPIFFE ID override",
			spiffeID:    "spiffe://otherdomain.org/bundle",
			errContains: "unable to verify client peer chain",
		},
		{
			name:        "non-200 status",
			status:      http.StatusServiceUnavailable,
			spiffeID:    "spiffe://example.org/bundle",
			body:        "tHe SYsTEm iS DowN",
			errContains: "unexpected status 503 fetching bundle: tHe SYsTEm iS DowN",
		},
		{
			name:        "invalid bundle content",
			status:      http.StatusOK,
			spiffeID:    "spiffe://example.org/bundle",
			body:        "NOT JSON",
			errContains: "failed to decode bundle",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			serverCert, serverKey := createServerCertificate(t)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(testCase.body))
			}))

			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{serverCert.Raw},
						PrivateKey:  serverKey,
					},
				},
			}
			server.StartTLS()
			defer server.Close()

			client, err := NewClient(ClientConfig{
				Address: server.Listener.Addr().String(),
				Auth: &AuthConfig{
					ServerID: testCase.spiffeID,
					RootCAs:  []*x509.Certificate{serverCert},
				},
			})
			require.NoError(t, err)

			b, err := client.FetchBundle(context.Background())
			if testCase.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.errContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, b)
			require.Equal(t, uint64(0), b.Sequence)
			require.Equal(t, 10, b.RefreshHint)
		})
	}
}

func createServerCertificate(t *testing.T) (*x509.Certificate, crypto.Signer) {
	ca, signer := spiffetest.CreateCACertificate(t, nil, nil)
	return spiffetest.CreateX509SVID(t, ca, signer, "spiffe://example.org/bundle")
}
