package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func Example_fetchJWTSVID() {
	client, err := workloadapi.Dial(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer client.Close()

	// Fetch a JWT-SVID intended for spiffe://domain.test/server using the default
	// SPIFFE ID of the workload.
	svid, err := client.FetchJWTSVID(context.TODO(), spiffeid.String("domain.test", "server"))
	if err != nil {
		// TODO: handle error
	}

	// Use JWT-SVID
	svid = svid
}
