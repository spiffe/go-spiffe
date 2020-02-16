package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
	"gopkg.in/square/go-jose.v2"
)

// FetchX509SVID fetches the default X509-SVID from the Workload API
func FetchX509SVID(ctx context.Context, options ...Option) (*spiffex509.SVID, error) {
	panic("not implemented")
}

// FetchX509SVIDs fetches all X509-SVIDs from the Workload API
func FetchX509SVIDs(ctx context.Context, options ...Option) ([]*spiffex509.SVID, error) {
	panic("not implemented")
}

// FetchX509Roots fetches the trusted X.509 roots from the Workload API
func FetchX509Roots(ctx context.Context, options ...Option) (*spiffex509.Roots, error) {
	panic("not implemented")
}

// FetchX509Context fetches the X.509 context from the Workload API
func FetchX509Context(ctx context.Context, options ...Option) (*X509Context, error) {
	panic("not implemented")
}

// WatchX509Context watches for updates to the X.509 context from the Workload
// API
func WatchX509Context(ctx context.Context, watcher X509ContextWatcher, options ...Option) error {
	panic("not implemented")
}

// FetchJWTSVID fetches a JWT-SVID from the Workload API
func FetchJWTSVID(ctx context.Context, audience string, jwtOptions []JWTSVIDOption, options ...Option) (*spiffejwt.SVID, error) {
	panic("not implemented")
}

// FetchJWTBundles fetches the JWT bundles for JWT-SVID validation from the
// Workload API, keyed by a SPIFFE ID of the trust domain to which they belong.
func FetchJWTBundles(ctx context.Context, options ...Option) (map[string]jose.JSONWebKeySet, error) {
	panic("not implemented")
}

// WatchJWTBundles watches for changes to the JWT bundles from the Workload API
func WatchJWTBundles(ctx context.Context, watcher JWTBundleWatcher, options ...Option) error {
	panic("not implemented")
}

// ValidateJWTSVID validates the JWT-SVID token using the Workload API and
// returns the validated JWT-SVID.
func ValidateJWTSVID(ctx context.Context, token, audience string, options ...Option) (*spiffejwt.SVID, error) {
	panic("not implemented")
}
