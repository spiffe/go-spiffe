package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundleendpoint"
	"github.com/spiffe/go-spiffe/v2/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

func Example_watchBundleViaSPIFFAuth() {
	initialBundle, err := spiffebundle.Load("bundle.json")
	if err != nil {
		// TODO: error checking
	}

	bundles := spiffebundle.NewSet()
	bundles.Insert(spiffeid.TrustDomain("domain.test"), initialBundle)

	// Retrieve the bundle from the URL, authenticating the server using a
	// bundle pulled from the workload API.
	// TODO: When implementing the watcher's OnUpdate, replace the bundle for
	// the trust domain in the bundle set so the next connection uses the
	// updated bundle.
	var watcher bundleendpoint.Watcher
	err = bundleendpoint.WatchBundle(context.TODO(), "https://domain.test:443/bundle", watcher,
		bundleendpoint.WithSPIFFEAuth(bundles, spiffetls.AllowID(spiffeid.Make("domain.test", "bundle", "server"))))
	if err != nil {
		panic(err)
	}
}
