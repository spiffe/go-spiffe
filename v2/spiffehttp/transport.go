package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

func NewTLSTransport(store spiffex509.RootStore, validator spiffetls.Validator) *http.Transport {
	panic("not implemented")
}

func NewMTLSTransport(store spiffetls.PeerStore, validator spiffetls.Validator) *http.Transport {
	panic("not implemented")
}
