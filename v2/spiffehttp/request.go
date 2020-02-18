package spiffehttp

import (
	"io"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
)

// NewRequest returns a new HTTP request with a JWT-SVID attached for
// authorization.
func NewRequestWithJWT(method, url string, body io.Reader, svid *spiffejwt.SVID) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	AttachJWTSVID(req, svid)
	return req, nil
}

// AttachJWTSVID attaches a JWT-SVID to an HTTP request as authorization.
func AttachJWTSVID(req *http.Request, svid *spiffejwt.SVID) {
	req.Header.Add("Authorization", "Bearer "+svid.Token)
}
