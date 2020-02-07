package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func Example_watchJWTBundles() {
	// WatchJWTBundles blocks until the passed in context is canceled or there
	// is a non-temporary error.
	var watcher workloadapi.JWTBundleWatcher
	if err := workloadapi.WatchJWTBundles(context.TODO(), watcher); err != nil {
		// TODO: handle error
	}
}
