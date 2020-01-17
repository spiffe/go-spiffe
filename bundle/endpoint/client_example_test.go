package endpoint_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/spiffe/go-spiffe/bundle"
	"github.com/spiffe/go-spiffe/bundle/endpoint"
)

// This is an example of the bundle endpoint client used with the the SPIFFE
// authentication mechanism.
// The example assumes an SPIRE implementation of the SPIFFE bundle endpoint server
// is running on localhost:8443 under the trust domain 'spiffe://example.org'.
func Example_client() {
	// Load an initial up-to-date bundle from the remote trust domain (obtained
	// through an offline exchange).
	rootCAs, err := loadCertificate("dummy_upstream_ca.crt")
	if err != nil {
		fmt.Printf("Unable to load root CAs: %v", err)
		return
	}

	// Creates the bundle client using the SPIFFE authentication mechanim
	c, err := endpoint.NewClient(endpoint.ClientConfig{
		EndpointAddress: "localhost:8443",
		SPIFFEAuth: &endpoint.SPIFFEAuthConfig{
			EndpointSpiffeID: "spiffe://example.org/spire/server",
			RootCAs:          []*x509.Certificate{rootCAs},
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

	// Print the bundle content
	printBundle(b)
}

func printBundle(b *bundle.Bundle) {
	fmt.Println("Bundle fetched")
	fmt.Printf("Sequence number: %d\n", b.Sequence)
	fmt.Printf("Refresh hint   : %d\n", b.RefreshHint)
	for i, key := range b.Keys {
		fmt.Println("")
		keyJson, err := key.MarshalJSON()
		if err != nil {
			fmt.Printf("Unable to marshal key %d to json: %v\n", i, err)
			continue
		}
		var prettyJson bytes.Buffer
		err = json.Indent(&prettyJson, keyJson, "", "    ")
		if err != nil {
			fmt.Printf("Unable to pretty print key %d %v\n", i, err)
			continue
		}

		fmt.Printf("Key %d:\n%s\n", i, prettyJson.Bytes())
	}
}

func loadCertificate(path string) (*x509.Certificate, error) {
	r, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(r)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
