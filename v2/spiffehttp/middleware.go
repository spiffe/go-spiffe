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
	fullAudience := append([]string{audience}, moreAudiences...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := JWTSVIDTokenFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// TODO: stuff the JWT information on the request context
		svid, err := spiffejwt.ParseAndValidate(token, keys, fullAudience, spiffejwt.AllowAny())
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := validator(svid.ID, r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r)
	})
}
