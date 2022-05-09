package federation

import (
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type HandlerOption interface {
	apply(*handlerConfig) error
}

func WithLogger(log logger.Logger) HandlerOption {
	return handlerOption(func(c *handlerConfig) error {
		c.log = log
		return nil
	})
}

// NewHandler returns an HTTP handler that provides the trust domain bundle for
// the given trust domain. The bundle is encoded according to the format
// outlined in the SPIFFE Trust Domain and Bundle specification. The bundle
// source is used to obtain the bundle on each request. Source implementations
// should consider a caching strategy if retrieval is expensive.
// See the specification for more details:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
func NewHandler(trustDomain spiffeid.TrustDomain, source spiffebundle.Source, opts ...HandlerOption) (http.Handler, error) {
	conf := &handlerConfig{
		log: logger.Null,
	}

	for _, opt := range opts {
		if err := opt.apply(conf); err != nil {
			return nil, fmt.Errorf("handler configuration is invalid: %w", err)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method is not allowed", http.StatusMethodNotAllowed)
			return
		}

		bundle, err := source.GetBundleForTrustDomain(trustDomain)
		if err != nil {
			conf.log.Errorf("unable to get bundle for trust domain %q: %v", trustDomain, err)
			http.Error(w, fmt.Sprintf("unable to serve bundle for %q", trustDomain), http.StatusInternalServerError)
			return
		}
		data, err := bundle.Marshal()
		if err != nil {
			conf.log.Errorf("unable to marshal bundle for trust domain %q: %v", trustDomain, err)
			http.Error(w, fmt.Sprintf("unable to serve bundle for %q", trustDomain), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}), nil
}

type handlerConfig struct {
	log logger.Logger
}

type handlerOption func(*handlerConfig) error

func (o handlerOption) apply(conf *handlerConfig) error {
	return o(conf)
}
