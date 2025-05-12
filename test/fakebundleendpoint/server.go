package fakebundleendpoint

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
)

type Server struct {
	tb         testing.TB
	httpServer *httptest.Server
	// Root certificates used by clients to verify server certificates.
	rootCAs *x509.CertPool
	// TLS configuration used by the server.
	tlscfg *tls.Config
	// SPIFFE bundles that can be returned by this Server.
	bundles []*spiffebundle.Bundle
}

type ServerOption interface {
	apply(*Server)
}

func New(tb testing.TB, option ...ServerOption) *Server {
	rootCAs, cert := test.CreateWebCredentials(tb)
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	s := &Server{
		tb:      tb,
		rootCAs: rootCAs,
		tlscfg:  tlscfg,
	}

	for _, opt := range option {
		opt.apply(s)
	}

	sm := http.NewServeMux()
	sm.HandleFunc("/test-bundle", s.testbundle)

	server := httptest.NewUnstartedServer(sm)
	server.TLS = s.tlscfg

	if s.tlscfg.GetCertificate != nil {
		c, err := s.tlscfg.GetCertificate(&tls.ClientHelloInfo{
			ServerName: server.URL,
		})
		if err != nil {
			tb.Fatalf("TLS config error: %v", err)
		}
		server.TLS.Certificates = append(server.TLS.Certificates, *c)
	}
	server.StartTLS()

	s.httpServer = server
	return s
}

func (s *Server) Shutdown() {
	s.httpServer.Close()
}

func (s *Server) FetchBundleURL() string {
	return fmt.Sprintf("%s/test-bundle", s.httpServer.URL)
}

func (s *Server) RootCAs() *x509.CertPool {
	return s.rootCAs
}

func (s *Server) testbundle(w http.ResponseWriter, r *http.Request) {
	if len(s.bundles) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bb, err := s.bundles[0].Marshal()
	assert.NoError(s.tb, err)
	s.bundles = s.bundles[1:]
	w.Header().Add("Content-Type", "application/json")
	b, err := w.Write(bb)
	assert.NoError(s.tb, err)
	assert.Equal(s.tb, len(bb), b)
}

type serverOption func(*Server)

// WithTestBundles sets the bundles that are returned by the Bundle Endpoint. You can
// specify several bundles, which are going to be returned one at a time each time
// a bundle is GET by a client.
func WithTestBundles(bundles ...*spiffebundle.Bundle) ServerOption {
	return serverOption(func(s *Server) {
		s.bundles = bundles
	})
}

func WithSPIFFEAuth(bundle *spiffebundle.Bundle, svid *x509svid.SVID) ServerOption {
	return serverOption(func(s *Server) {
		s.rootCAs = x509util.NewCertPool(bundle.X509Authorities())
		s.tlscfg = tlsconfig.TLSServerConfig(svid)
	})
}

func (so serverOption) apply(s *Server) {
	so(s)
}
