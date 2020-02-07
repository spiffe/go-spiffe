package examples_test

import (
	"context"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffehttp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/tlsworkload"
)

func Example_hTTPSClientWithMTLS() {
	serverID := spiffeid.Make("example.org", "server")

	workload, err := tlsworkload.Open(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer workload.Close()

	// Create an MTLS transport that authenticates the server against the
	// expected SPIFFE ID.
	client := &http.Client{
		Transport: spiffehttp.NewMTLSTransport(workload, spiffetls.AllowID(serverID)),
	}

	resp, err := client.Get("https://example.org")
	if err != nil {
		// TODO: handle error
	}

	// TODO: handle response
	resp = resp
}
