// Package endpoint implements a SPIFFE bundle endpoint client.
package endpoint

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/spiffe/go-spiffe/bundle"
	"github.com/spiffe/go-spiffe/internal"
	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/zeebo/errs"
)

// AuthConfig contains the configuration of the SPIFFE authentication
// mechanism for authenticating the bundle endpoint.
type AuthConfig struct {
	// ServerID is the expected SPIFFE ID of the endpoint server.
	ServerID string

	// RootCAs is the set of root CA certificates used to authenticate the
	// endpoint server.
	RootCAs []*x509.Certificate
}

// ClientConfig contains the configuration to create a bundle endpoint client.
type ClientConfig struct {
	// Address is the bundle endpoint for the trust domain.
	Address string

	// Auth contains required configuration to authenticate the endpoint
	// using SPIFFE authentication. If unset, it is assumed that the endpoint
	// is authenticated via Web PKI.
	Auth *AuthConfig
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
	if config.Address == "" {
		return nil, errs.New("bundle endpoint address is required")
	}

	httpClient := &http.Client{}
	if config.Auth != nil {
		spiffeID := config.Auth.ServerID
		if spiffeID == "" {
			return nil, errs.New("bundle endpoint spiffe ID is required")
		}
		if len(config.Auth.RootCAs) == 0 {
			return nil, errs.New("an initial up-to-date bundle from the remote trust domain is required")
		}

		tlsConfig, err := getTLSConfig(spiffeID, config.Auth.RootCAs)
		if err != nil {
			return nil, errs.New("cannot get TLS config: %v", err)
		}

		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
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
	resp, err := c.client.Get(fmt.Sprintf("https://%s", c.c.Address))
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

	return b, nil
}

func tryRead(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Scan()
	return scanner.Text()
}

func getTLSConfig(spiffeID string, rootCAs []*x509.Certificate) (*tls.Config, error) {
	trustDomainID, err := spiffe.TrustDomainIDFromID(spiffeID, spiffe.AllowAnyTrustDomainWorkload())
	if err != nil {
		return nil, errs.New("unable to get trust domain from SPIFFE ID: %v", err)
	}

	roots := make(map[string]*x509.CertPool)
	roots[trustDomainID] = internal.CertPoolFromCerts(rootCAs)

	return &tls.Config{
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: adaptVerifyPeerCertificate(roots, spiffe.ExpectPeer(spiffeID)),
	}, nil
}

func adaptVerifyPeerCertificate(roots map[string]*x509.CertPool, expectPeer spiffe.ExpectPeerFunc) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var certs []*x509.Certificate
		for i, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return errs.New("unable to parse certificate %d: %v", i, err)
			}
			certs = append(certs, cert)
		}

		if _, err := spiffe.VerifyPeerCertificate(certs, roots, expectPeer); err != nil {
			return errs.New("unable to verify client peer chain: %v", err)
		}
		return nil
	}
}
