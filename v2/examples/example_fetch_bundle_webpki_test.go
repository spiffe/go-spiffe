package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundleendpoint"
)

func Example_fetchBundleViaWebPKI() {
	bundle, err := bundleendpoint.FetchBundle(context.TODO(), "https://domain.test:443/bundle")
	if err != nil {
		// TODO: error checking
	}

	// TODO: use the bundle
	bundle = bundle
}
