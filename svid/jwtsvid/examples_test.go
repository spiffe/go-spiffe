package jwtsvid_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func ExampleParseAndValidate() {
	td, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: error handling
	}

	token := "TODO"
	audience := []string{spiffeid.RequireFromPath(td, "/server").String()}

	jwtSource, err := workloadapi.NewJWTSource(context.TODO())
	if err != nil {
		// TODO: error handling
	}
	defer jwtSource.Close()

	svid, err := jwtsvid.ParseAndValidate(token, jwtSource, audience)
	if err != nil {
		// TODO: error handling
	}

	// TODO: do something with the JWT-SVID
	svid = svid
}
