package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func Example_oneShotFetchJWTSVID() {
	// Fetch a JWT-SVID intended for spiffe://domain.test/server using the default
	// SPIFFE ID of the workload.
	svid, err := workloadapi.FetchJWTSVID(context.TODO(), spiffeid.String("domain.test", "server"), nil)
	if err != nil {
		// TODO: handle error
	}

	// Use JWT-SVID
	svid = svid
}
