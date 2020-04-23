package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	apply(*fetchOptions) error
}

type fetchOptions struct {
	transport  *http.Transport
	authMethod authMethod
}

// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication
// using the provided root store. It validates that the endpoint presents the
// expected SPIFFE ID. This option cannot be used in conjuntion with WithWebPKIRoots
// option.
func WithSPIFFEAuth(bundleSource x509bundle.Source, endpointID spiffeid.ID) FetchOption {
	return fetchOption(func(o *fetchOptions) error {
		if o.authMethod != authMethodDefault {
			return federationErr.New("cannot use both SPIFFE and Web PKI authentication")
		}
		o.transport.TLSClientConfig = tlsconfig.TLSClientConfig(bundleSource, tlsconfig.AuthorizeID(endpointID))
		o.authMethod = authMethodSPIFFE
		return nil
	})
}

// WithWebPKIRoots authenticates the bundle endpoint using Web PKI authentication
// using the provided X.509 root certificates instead of the system ones. This option
// cannot be used in conjuntion with WithSPIFFEAuth option.
func WithWebPKIRoots(rootCAs *x509.CertPool) FetchOption {
	return fetchOption(func(o *fetchOptions) error {
		if o.authMethod != authMethodDefault {
			return federationErr.New("cannot use both SPIFFE and Web PKI authentication")
		}
		o.transport.TLSClientConfig = &tls.Config{
			RootCAs: rootCAs,
		}
		o.authMethod = authMethodWebPKI
		return nil
	})
}

// FetchBundle retrieves a bundle from a bundle endpoint.
func FetchBundle(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
	opts := fetchOptions{
		transport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	for _, o := range option {
		if err := o.apply(&opts); err != nil {
			return nil, err
		}
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

type fetchOption func(*fetchOptions) error

func (fo fetchOption) apply(opts *fetchOptions) error {
	return fo(opts)
}

type authMethod int

const (
	authMethodDefault authMethod = iota
	authMethodSPIFFE
	authMethodWebPKI
)
