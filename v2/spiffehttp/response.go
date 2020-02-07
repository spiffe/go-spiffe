package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// JWTSVIDTokenFromRequest returns the JWT-SVID bearer token from an HTTP request
func JWTSVIDTokenFromRequest(req *http.Request) (string, bool) {
	panic("not implemented")
}

func SPIFFEIDFromRequest(req *http.Request) (spiffeid.ID, bool) {
	panic("not implemented")
}

func JWTClaimsFromRequest(req *http.Request) (map[string]interface{}, bool) {
	panic("not implemented")
}
