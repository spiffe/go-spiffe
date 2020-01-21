package endpoint_test

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/go-spiffe/bundle/endpoint"
)

// This is an example of the bundle endpoint client used with the the SPIFFE
// authentication mechanism.
// The example assumes a SPIRE implementation of the SPIFFE bundle endpoint server
// is running on localhost:8443 under the trust domain 'spiffe://example.org'.
func Example() {
	// TODO: load the initial set of trust domain root CAs (obtained through an offline exchange). These root CAs
	// are used to bootstrap trust with the endpoint. Afterwards, the contents of the bundle returned by the endpoint
	// should be used for future authentication.
	var rootCAs []*x509.Certificate

	// Creates the bundle client using the SPIFFE authentication mechanim
	c, err := endpoint.NewClient(endpoint.ClientConfig{
		Address: "localhost:8443",
		Auth: &endpoint.AuthConfig{
			ServerID: "spiffe://example.org/spire/server",
			RootCAs:  rootCAs,
		},
	})
	if err != nil {
		fmt.Printf("Unable to create client: %v", err)
		return
	}

	// Fetch the bundle from the endpoint
	b, err := c.FetchBundle(context.Background())
	if err != nil {
		fmt.Printf("Unable to fetch bundle: %v", err)
		return
	}

	fmt.Printf("Bundle fetched: %+v", b)
}
