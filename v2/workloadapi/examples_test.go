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
	svid, err := workloadapi.FetchJWTSVID(context.TODO(), jwtsvid.Params{
		Audience: spiffeid.String("example.org", "server"),
	})
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the JWT-SVID
	svid = svid
}

func ExampleValidateJWTSVID() {
	token := "TODO"
	svid, err := workloadapi.ValidateJWTSVID(context.TODO(), token, spiffeid.String("example.org", "server"))
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the JWT-SVID
	svid = svid
}
