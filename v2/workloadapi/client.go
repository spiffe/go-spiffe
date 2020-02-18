package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
	"gopkg.in/square/go-jose.v2"
)

// Client is a Workload API client.
type Client struct{}

// Dial dials the workload API and returns a client.
func Dial(ctx context.Context, options ...Option) (*Client, error) {
	panic("not implemented")
}

// Close closes a workload API client.
func (c *Client) Close() error {
	panic("not implemented")
}

// FetchX509SVID fetches the default X509-SVID.
func (c *Client) FetchX509SVID(ctx context.Context) (*spiffex509.SVID, error) {
	panic("not implemented")
}

// FetchX509SVIDs fetches all X509-SVIDs.
func (c *Client) FetchX509SVIDs(ctx context.Context) ([]*spiffex509.SVID, error) {
	panic("not implemented")
}

// FetchX509Roots fetches the trusted X.509 roots.
func (c *Client) FetchX509Roots(ctx context.Context) (*spiffex509.Roots, error) {
	panic("not implemented")
}

// FetchX509Context fetches the X.509 context.
func (c *Client) FetchX509Context(ctx context.Context) (*X509Context, error) {
	panic("not implemented")
}

// WatchX509Context watches for updates to the X.509 context.
func (c *Client) WatchX509Context(ctx context.Context, watcher X509ContextWatcher) error {
	panic("not implemented")
}

// FetchJWTSVID fetches a JWT-SVID.
func (c *Client) FetchJWTSVID(ctx context.Context, audience string, options ...JWTSVIDOption) (*spiffejwt.SVID, error) {
	panic("not implemented")
}

// FetchJWTBundles fetches the JWT bundles for JWT-SVID validation, keyed
// by a SPIFFE ID of the trust domain to which they belong.
func (c *Client) FetchJWTBundles(ctx context.Context) (map[string]jose.JSONWebKeySet, error) {
	panic("not implemented")
}

// WatchJWTBundles watches for changes to the JWT bundles.
func (c *Client) WatchJWTBundles(ctx context.Context, watcher JWTBundleWatcher) error {
	panic("not implemented")
}

// ValidateJWTSVID dials the Workload API, validates the JWT-SVID token, and
// returns the validated JWT-SVID.
func (c *Client) ValidateJWTSVID(ctx context.Context, token, audience string) (*spiffejwt.SVID, error) {
	panic("not implemented")
}
