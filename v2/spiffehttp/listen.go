package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

// ListenAndServeTLS starts an HTTP server over TLS with the given address
// and handler. The SVID store is used to provide X509-SVIDs for the server
// TLS handshake.
func ListenAndServeTLS(addr string, store spiffetls.SVIDStore, handler http.Handler) error {
	panic("not implemented")
}

// ListenAndServeMTLS starts an HTTP server over mTLS with the given address
// and handler. The peer store is used to provide X509-SVIDs for the server
// TLS handshake. Client X509-SVIDs are verified and validated using the given
// peer store and validator.
func ListenAndServeMTLS(addr string, store spiffetls.PeerStore, validator Validator, handler http.Handler) error {
	panic("not implemented")
}
