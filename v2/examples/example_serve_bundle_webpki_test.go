package examples_test

import (
	"context"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundleendpoint"
	"github.com/spiffe/go-spiffe/v2/bundleworkload"
)

func Example_serveBundleViaWebPKI() {
	workload, err := bundleworkload.Open(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer workload.Close()

	handler := bundleendpoint.Handler(workload)
	if err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", handler); err != nil {
		// TODO: handle error
	}
}
