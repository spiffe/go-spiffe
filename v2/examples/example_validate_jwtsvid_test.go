package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func Example_validateJWTSVID() {
	var token string

	client, err := workloadapi.Dial(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer client.Close()

	svid, err := client.ValidateJWTSVID(context.TODO(), token, spiffeid.String("domain.test", "server"))
	if err != nil {
		// TODO: handle error
	}

	// TODO: consume JWT-SVID
	svid = svid
}
