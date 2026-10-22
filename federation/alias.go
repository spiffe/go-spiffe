// Package federation provides functionality to fetch and serve SPIFFE bundles.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/federation].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package federation

import lite "github.com/spiffe/go-spiffe/lite/federation"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// BundleWatcher is used by WatchBundle to provide the caller with bundle updates and control the next refresh time.
	BundleWatcher = lite.BundleWatcher

	// FetchOption is an option used when dialing the bundle endpoint.
	FetchOption = lite.FetchOption

	// HandlerOption is an alias for the identifier of the same name in the lite module.
	HandlerOption = lite.HandlerOption
)

var (
	// FetchBundle retrieves a bundle from a bundle endpoint.
	FetchBundle = lite.FetchBundle

	// NewHandler returns an HTTP handler that provides the trust domain bundle for the given trust domain. The bundle is encoded according to the format outlined in the SPIFFE Trust Domain and Bundle specification. The bundle source is used to obtain the bundle on each request. Source implementations should consider a caching strategy if retrieval is expensive. See the specification for more details: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
	NewHandler = lite.NewHandler

	// WatchBundle watches a bundle on a bundle endpoint. It returns when the context is canceled, returning ctx.Err().
	WatchBundle = lite.WatchBundle

	// WithLogger is an alias for the identifier of the same name in the lite module.
	WithLogger = lite.WithLogger

	// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication using the provided root store. It validates that the endpoint presents the expected SPIFFE ID. This option cannot be used in conjuntion with WithWebPKIRoots option.
	WithSPIFFEAuth = lite.WithSPIFFEAuth

	// WithWebPKIRoots authenticates the bundle endpoint using Web PKI authentication using the provided X.509 root certificates instead of the system ones. This option cannot be used in conjuntion with WithSPIFFEAuth option.
	WithWebPKIRoots = lite.WithWebPKIRoots
)
