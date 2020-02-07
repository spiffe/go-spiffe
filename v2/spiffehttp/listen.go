package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

func ListenAndServeTLS(addr string, store spiffetls.SVIDStore, handler http.Handler) error {
	panic("not implemented")
}

func ListenAndServeMTLS(addr string, store spiffetls.PeerStore, validator Validator, handler http.Handler) error {
	panic("not implemented")
}
