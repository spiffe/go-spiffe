package federation

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

var federationErr = errs.Class("federation")

// FetchOption is an option used when dialing the bundle endpoint.
type FetchOption interface{}

// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication
// using the provided root store. It validates that the endpoint presents the
// expected SPIFFE ID.
func WithSPIFFEAuth(bundleSource x509bundle.Source, endpointID spiffeid.ID) FetchOption {
	panic("not implemented")
}

// FetchBundle retrieves a bundle from a bundle endpoint.
func FetchBundle(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
	panic("not implemented")
}
