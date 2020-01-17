// Package endpoint implements a SPIFFE bundle endpoint client.
package endpoint

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/spiffe/go-spiffe/bundle"
	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/zeebo/errs"
)

// SPIFFEAuthConfig contains the configuration of the SPIFFE authentication
// mechanism for authenticating the bundle endpoint.
type SPIFFEAuthConfig struct {
	// EndpointSpiffeID is the expected SPIFFE ID of the endpoint server.
	EndpointSpiffeID string

	// RootCAs is the set of root CA certificates used to authenticate the
	// endpoint server.
	RootCAs []*x509.Certificate
}

// ClientConfig contains the configuration to create a bundle endpoint client.
type ClientConfig struct {
	// EndpointAddress is the bundle endpoint for the trust domain.
	EndpointAddress string

	// SPIFFEAuth contains required configuration to authenticate the endpoint
	// using SPIFFE authentication. If unset, it is assumed that the endpoint
	// is authenticated via Web PKI.
	SPIFFEAuth *SPIFFEAuthConfig
}

// Client is used to fetch a bundle and metadata from a bundle endpoint
type Client interface {
	FetchBundle(context.Context) (*bundle.Bundle, error)
}

type client struct {
	c      ClientConfig
	client *http.Client
}

// NewClient creates a new bundle endpoint client
func NewClient(config ClientConfig) (Client, error) {
	if config.EndpointAddress == "" {
		return nil, errs.New("bundle endpoint address is required")
	}

	httpClient := &http.Client{}
	if config.SPIFFEAuth != nil {
		spiffeID := config.SPIFFEAuth.EndpointSpiffeID
		if spiffeID == "" {
			return nil, errs.New("bundle endpoint spiffe ID is required")
		}
		if len(config.SPIFFEAuth.RootCAs) == 0 {
			return nil, errs.New("an initial up-to-date bundle from the remote trust domain is required")
		}

		peer := &spiffe_tls.TLSPeer{
			SpiffeIDs:  []string{spiffeID},
			TrustRoots: newCertPool(config.SPIFFEAuth.RootCAs...),
		}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: peer.NewTLSConfig(nil),
		}
	}
	return &client{
		c:      config,
		client: httpClient,
	}, nil
}

// FetchBundle fetches a SPIFFE bundle from a bundle endpoint.
// Any JWK element not matching the SPIFFE specification requirements won't
// be included in the bundle.
func (c *client) FetchBundle(ctx context.Context) (*bundle.Bundle, error) {
	resp, err := c.client.Get(fmt.Sprintf("https://%s", c.c.EndpointAddress))
	if err != nil {
		return nil, errs.New("failed to fetch bundle: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errs.New("unexpected status %d fetching bundle: %s", resp.StatusCode, tryRead(resp.Body))
	}

	b, err := bundle.Decode(resp.Body)
	if err != nil {
		return nil, err
	}

	validKeys, _ := bundle.ValidateKeys(b.Keys)
	b.Keys = validKeys

	return b, nil
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}

// newCertPool creates a new *x509.CertPool based on the certificates given
// as parameters.
func newCertPool(certs ...*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}
