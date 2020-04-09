package federation

import (
	"context"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/zeebo/errs"
)

var federationErr = errs.Class("federation")

// FetchOption is an option used when dialing the bundle endpoint.
type FetchOption interface {
	apply(*fetchOptions)
}

type fetchOptions struct {
	transport *http.Transport
}

// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication
// using the provided root store. It validates that the endpoint presents the
// expected SPIFFE ID.
func WithSPIFFEAuth(bundleSource x509bundle.Source, endpointID spiffeid.ID) FetchOption {
	return fetchOption(func(o *fetchOptions) {
		o.transport.TLSClientConfig = tlsconfig.TLSClientConfig(bundleSource, tlsconfig.AuthorizeID(endpointID))
	})
}

// FetchBundle retrieves a bundle from a bundle endpoint.
func FetchBundle(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
	opts := fetchOptions{
		transport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	for _, o := range option {
		o.apply(&opts)
	}

	var client = &http.Client{
		Transport: opts.transport,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, federationErr.New("could not create request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, federationErr.New("could not GET bundle: %w", err)
	}
	defer response.Body.Close()

	bundle, err := spiffebundle.Read(trustDomain, response.Body)
	if err != nil {
		return nil, federationErr.Wrap(err)
	}

	return bundle, nil
}

type fetchOption func(*fetchOptions)

func (fo fetchOption) apply(opts *fetchOptions) {
	fo(opts)
}
