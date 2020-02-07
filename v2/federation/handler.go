package federation

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Handler is an HTTP handler that returns the JSON encoded bundle for the
// given trust domain the SPIFFE Trust Domain and Bundle specification. The
// bundle source is used to obtain the bundle on each request. Source
// implementations should consider a caching strategy if retrieval is
// expensive.
// See the specification for more details:
// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md
func Handler(trustDomain spiffeid.TrustDomain, source spiffebundle.Source) http.Handler {
	panic("not implemented")
}
