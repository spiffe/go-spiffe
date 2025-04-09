package workloadapi_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func ExampleFetchX509SVID() {
	svid, err := workloadapi.FetchX509SVID(context.TODO())
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the X509-SVID
	svid = svid
}

func ExampleFetchJWTSVID() {
	serverID, err := spiffeid.FromString("spiffe://example.org/server")
	if err != nil {
		// TODO: error handling
	}

	svid, err := workloadapi.FetchJWTSVID(context.TODO(), jwtsvid.Params{
		Audience: serverID.String(),
	})
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the JWT-SVID
	svid = svid
}

func ExampleValidateJWTSVID() {
	serverID, err := spiffeid.FromString("spiffe://example.org/server")
	if err != nil {
		// TODO: error handling
	}

	token := "TODO"
	svid, err := workloadapi.ValidateJWTSVID(context.TODO(), token, serverID.String())
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the JWT-SVID
	svid = svid
}
