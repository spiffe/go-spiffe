package fakebundleendpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"
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
	wg         sync.WaitGroup
	addr       net.Addr
	httpServer *http.Server
	// Root certificates used by clients to verify server certificates.
	rootCAs *x509.CertPool
	// TLS configuration used by the server.
	tlscfg *tls.Config
	// SPIFFE bundle returned by this Server.
	bundle *spiffebundle.Bundle
}

type ServerOption interface {
	apply(*Server)
}

func New(tb testing.TB, option ...ServerOption) *Server {
	rootCAs, cert := test.CreateWebCredentials(tb)
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
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
	s.httpServer = &http.Server{
		Handler:   sm,
		TLSConfig: s.tlscfg,
	}
	err := s.start()
	if err != nil {
		tb.Fatalf("Failed to start: %v", err)
	}
	return s
}

func (s *Server) Shutdown() {
	err := s.httpServer.Shutdown(context.Background())
	assert.NoError(s.tb, err)
	s.wg.Wait()
}

func (s *Server) Addr() string {
	return s.addr.String()
}

func (s *Server) FetchBundleURL() string {
	return fmt.Sprintf("https://%s/test-bundle", s.Addr())
}

func (s *Server) RootCAs() *x509.CertPool {
	return s.rootCAs
}

func (s *Server) start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}

	s.addr = ln.Addr()

	s.wg.Add(1)
	go func() {
		err := s.httpServer.ServeTLS(ln, "", "")
		assert.EqualError(s.tb, err, http.ErrServerClosed.Error())
		s.wg.Done()
		ln.Close()
	}()
	return nil
}

func (s *Server) testbundle(w http.ResponseWriter, r *http.Request) {
	if s.bundle == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bb, err := s.bundle.Marshal()
	assert.NoError(s.tb, err)
	w.Header().Add("Content-Type", "application/json")
	b, err := w.Write(bb)
	assert.NoError(s.tb, err)
	assert.Equal(s.tb, len(bb), b)
}

type serverOption func(*Server)

// WithTestBundle sets the bundle that is returned by the Bundle Endpoint.
func WithTestBundle(bundle *spiffebundle.Bundle) ServerOption {
	return serverOption(func(s *Server) {
		s.bundle = bundle
	})
}

func WithSPIFFEAuth(bundle *spiffebundle.Bundle, svid *x509svid.SVID) ServerOption {
	return serverOption(func(s *Server) {
		s.rootCAs = x509util.NewCertPool(bundle.X509Roots())
		s.tlscfg = tlsconfig.TLSServerConfig(svid)
	})
}

func (so serverOption) apply(s *Server) {
	so(s)
}
