package examples_test

import (
	"context"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffehttp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/jwtworkload"
	"github.com/spiffe/go-spiffe/v2/tlsworkload"
)

func Example_hTTPSClientWithJWT() {
	serverID := spiffeid.Make("example.org", "server")

	tlsWorkload, err := tlsworkload.Open(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer tlsWorkload.Close()

	jwtWorkload, err := jwtworkload.Open(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer jwtWorkload.Close()

	// Grab an svid to attach to the request
	svid, err := jwtWorkload.FetchJWTSVID(context.TODO(), serverID.String())
	if err != nil {
		// TODO: handle error
	}

	req, err := spiffehttp.NewRequestWithJWT("GET", "https://example.org", nil, svid)
	if err != nil {
		// TODO: handle error
	}

	// Create a TLS transport that authenticates the server against the
	// expected SPIFFE ID.
	client := &http.Client{
		Transport: spiffehttp.NewTLSTransport(tlsWorkload, spiffetls.AllowID(serverID)),
	}

	resp, err := client.Do(req)
	if err != nil {
		// TODO: handle error
	}

	// TODO: handle response
	resp = resp
}
