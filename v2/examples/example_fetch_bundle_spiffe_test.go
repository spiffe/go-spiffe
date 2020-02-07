package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundleendpoint"
	"github.com/spiffe/go-spiffe/v2/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

func Example_fetchBundleViaSPIFFEAuth() {
	trustDomain := spiffeid.TrustDomain("domain.test")
	initialBundlePath := "bundle.json"
	serverURL := "https://domain.test:443/bundle"
	serverID := trustDomain.ID("bundle", "server")

	initialBundle, err := spiffebundle.Load(initialBundlePath)
	if err != nil {
		// TODO: error checking
	}

	bundles := spiffebundle.NewSet()
	bundles.Insert(trustDomain, initialBundle)

	updatedBundle, err := bundleendpoint.FetchBundle(context.TODO(), serverURL,
		bundleendpoint.WithSPIFFEAuth(bundles, spiffetls.AllowID(serverID)))
	if err != nil {
		// TODO: error checking
	}

	// To reuse the client to fetch another bundle, the bundle set should be
	// updated with the new bundle.
	bundles.Insert(trustDomain, updatedBundle)
}
