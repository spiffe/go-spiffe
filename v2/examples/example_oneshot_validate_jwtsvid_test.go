package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func Example_oneShotValidateJWTSVID() {
	var token string

	svid, err := workloadapi.ValidateJWTSVID(context.TODO(), token, spiffeid.String("domain.test", "server"))
	if err != nil {
		// TODO: handle error
	}

	// TODO: consume JWT-SVID
	svid = svid
}
