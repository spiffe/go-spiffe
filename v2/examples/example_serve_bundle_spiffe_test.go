package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundleendpoint"
	"github.com/spiffe/go-spiffe/v2/bundleworkload"
	"github.com/spiffe/go-spiffe/v2/spiffehttp"
	"github.com/spiffe/go-spiffe/v2/tlsworkload"
)

func Example_serveBundleViaSPIFFEAuth() {
	bundleWorkload, err := bundleworkload.Open(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer bundleWorkload.Close()

	tlsWorkload, err := tlsworkload.Open(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer tlsWorkload.Close()

	handler := bundleendpoint.Handler(bundleWorkload)

	if err := spiffehttp.ListenAndServeTLS(":8443", tlsWorkload, handler); err != nil {
		// TODO: handle error
	}
}
