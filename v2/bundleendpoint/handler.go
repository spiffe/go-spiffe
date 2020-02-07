package bundleendpoint

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffebundle"
)

// Source is used by the handler to retrieve the bundle for each request
type Source interface {
	GetBundle() (*spiffebundle.Bundle, error)
}

// Handler is an HTTP handler that returns the JSON encoded bundle according
// to the SPIFFE Bundle and Endpoint specification. The store is used to
// obtain the bundle.
func Handler(store Source) http.Handler {
	panic("not implemented")
}
