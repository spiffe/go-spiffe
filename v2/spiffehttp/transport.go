package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

// NewTLSTransport provides an TLS transport that uses the given root store
// and validator to verify and validate the server X509-SVID.
func NewTLSTransport(store spiffex509.RootStore, validator spiffetls.Validator) *http.Transport {
	panic("not implemented")
}

// NewMTLSTransport provides an mTLS transport that uses the given root store
// and validator to verify and validate the server X509-SVID. The peer store
// also provides the X509-SVID for the client TLS handshake.
func NewMTLSTransport(store spiffetls.PeerStore, validator spiffetls.Validator) *http.Transport {
	panic("not implemented")
}
