package bundleendpoint

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

// FetchOption is an option used when dialing the bundle endpoint.
type FetchOption interface{}

// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication
// using the provided root store. It validates that the endpoint presents the
// expected SPIFFE ID.
func WithSPIFFEAuth(store spiffex509.RootStore, validator spiffetls.Validator) FetchOption {
	panic("not implemented")
}

// FetchBundle retrieves a bundle from a bundle endpoint.
func FetchBundle(ctx context.Context, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
	panic("not implemented")
}
