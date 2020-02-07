package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Client is a Workload API client.
type Client struct{}

// New dials the Workload API and returns a client.
func New(ctx context.Context, options ...ClientOption) (*Client, error) {
	panic("not implemented")
}

// Close closes the client.
func (c *Client) Close() error {
	panic("not implemented")
}

// FetchX509SVID fetches the default X509-SVID, i.e. the first in the list
// returned by the Workload API.
func (c *Client) FetchX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	panic("not implemented")
}

// FetchX509SVIDs fetches all X509-SVIDs.
func (c *Client) FetchX509SVIDs(ctx context.Context) ([]*x509svid.SVID, error) {
	panic("not implemented")
}

// FetchX509Bundle fetches the X.509 bundles.
func (c *Client) FetchX509Bundles(ctx context.Context) (*x509bundle.Set, error) {
	panic("not implemented")
}

// FetchX509Context fetches the X.509 context, which contains both X509-SVIDs
// and X.509 bundles.
func (c *Client) FetchX509Context(ctx context.Context) (*X509Context, error) {
	panic("not implemented")
}

// WatchX509Context watches for updates to the X.509 context. The watcher
// receives the updated X.509 context.
func (c *Client) WatchX509Context(ctx context.Context, watcher X509ContextWatcher) error {
	panic("not implemented")
}

// FetchJWTSVID fetches a JWT-SVID.
func (c *Client) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	panic("not implemented")
}

// FetchJWTBundles fetches the JWT bundles for JWT-SVID validation, keyed
// by a SPIFFE ID of the trust domain to which they belong.
func (c *Client) FetchJWTBundles(ctx context.Context) (*jwtbundle.Set, error) {
	panic("not implemented")
}

// WatchJWTBundles watches for changes to the JWT bundles. The watcher receives
// the updated JWT bundles.
func (c *Client) WatchJWTBundles(ctx context.Context, watcher JWTBundleWatcher) error {
	panic("not implemented")
}

// ValidateJWTSVID validates the JWT-SVID token. The parsed and validated
// JWT-SVID is returned.
func (c *Client) ValidateJWTSVID(ctx context.Context, token, audience string) (*jwtsvid.SVID, error) {
	panic("not implemented")
}

// X509ContextWatcher receives X509Context updates from the Workload API.
type X509ContextWatcher interface {
	// OnX509ContextUpdate is called with the latest X.509 context retrieved
	// from the Workload API.
	OnX509ContextUpdate(*X509Context)

	// OnX509ContextWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnX509ContextWatchError(error)
}

// JWTBundleWatcher receives JWT bundle updates from the Workload API.
type JWTBundleWatcher interface {
	// OnJWTBundlesUpdate is called with the latest JWT bundle set retrieved
	// from the Workload API.
	OnJWTBundlesUpdate(*jwtbundle.Set)

	// OnJWTBundlesWatchError is called when there is a problem establishing
	// or maintaining connectivity with the Workload API.
	OnJWTBundlesWatchError(error)
}
