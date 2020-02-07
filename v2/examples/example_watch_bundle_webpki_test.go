package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundleendpoint"
)

func Example_watchBundleViaWebPKI() {
	// Retrieve the bundle from the URL, authenticating the server using
	// a bundle pulled from the workload API.
	var watcher bundleendpoint.Watcher
	err := bundleendpoint.WatchBundle(context.TODO(), "https://domain.test:443/bundle", watcher)
	if err != nil {
		panic(err)
	}
}
