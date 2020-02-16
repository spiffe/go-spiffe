package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
)

// AuthenticateRequests returns a wrapping handler that authenticates incoming
// requests.
//
//	var handler http.Handler =  ...
//	http.ListenAndServe(":8080",
//		spiffehttp.AuthenticateRequests(mux, keyStore, spiffehttp.Validator("spiffe://example.org/workload"), "spiffe://example.org/workload")
//	)
func AuthenticateRequests(handler http.Handler, keys spiffejwt.KeyStore, validator Validator, audience string, moreAudiences ...string) http.Handler {
	panic("not implemented")
}

// JWTSVIDFromRequest returns the JWT-SVID attached to the request. It is
// attached to the request context by the AuthenticateRequests middleware.
func JWTSVIDFromRequest(req *http.Request) (*spiffejwt.SVID, bool) {
	panic("not implemented")
}
