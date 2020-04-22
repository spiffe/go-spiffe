package federation

import (
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Handler is an HTTP handler that returns the JSON encoded bundle for the
// given trust domain the SPIFFE Trust Domain and Bundle specification. The
// bundle source is used to obtain the bundle on each request. Source
// implementations should consider a caching strategy if retrieval is
// expensive.
// See the specification for more details:
// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md
func Handler(trustDomain spiffeid.TrustDomain, source spiffebundle.Source, log logger.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method is not allowed", http.StatusMethodNotAllowed)
			return
		}

		bundle, err := source.GetBundleForTrustDomain(trustDomain)
		if err != nil {
			log.Errorf("unable to get bundle for trust domain %q: %v", trustDomain, err)
			http.Error(w, fmt.Sprintf("unable to serve bundle for %q", trustDomain), http.StatusInternalServerError)
			return
		}
		data, err := bundle.Marshal()
		if err != nil {
			log.Errorf("unable to marshal bundle for trust domain %q: %v", trustDomain, err)
			http.Error(w, fmt.Sprintf("unable to serve bundle for %q", trustDomain), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
}
