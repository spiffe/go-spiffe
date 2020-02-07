package jwtsvid_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func ExampleParseAndValidate() {
	token := "TODO"
	audience := []string{spiffeid.String("example.org", "server")}
	authorizer := jwtsvid.AuthorizeID(spiffeid.Make("example.org", "client"))

	jwtSource, err := workloadapi.NewJWTSource(context.TODO())
	if err != nil {
		// TODO: error handling
	}
	defer jwtSource.Close()

	svid, err := jwtsvid.ParseAndValidate(token, jwtSource, audience, authorizer)
	if err != nil {
		// TODO: error handling
	}

	// TODO: do something with the JWT-SVID
	svid = svid
}

func ExampleParseAndValidate_customAuthorization() {
	token := "TODO"
	serverID := spiffeid.Make("example.org", "server")
	audience := []string{serverID.String()}

	authorizer := func(id spiffeid.ID, claims map[string]interface{}) error {
		// TODO: perform custom authorization on the ID and token claims
		return nil
	}

	jwtSource, err := workloadapi.NewJWTSource(context.TODO())
	if err != nil {
		// TODO: error handling
	}
	defer jwtSource.Close()

	svid, err := jwtsvid.ParseAndValidate(token, jwtSource, audience, authorizer)
	if err != nil {
		// TODO: error handling
	}

	// TODO: do something with the JWT-SVID
	svid = svid
}
