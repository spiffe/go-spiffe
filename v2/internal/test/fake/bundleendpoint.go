package fake

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

type BundleEndpoint struct {
	tb     testing.TB
	wg     sync.WaitGroup
	addr   net.Addr
	server *http.Server
	// Root certificates used by clients to verify server certificates.
	rootCAs *x509.CertPool
	// TLS configuration used by the server.
	tlscfg *tls.Config
	// SPIFFE bundle returned by this BundleEndpoint.
	bundle *spiffebundle.Bundle
}

type BundleEndpointOption interface {
	apply(*BundleEndpoint)
}

// BEOption groups the available options for a BundleEndpoint.
var BEOption = new(bundleEndpointOption)

func NewBundleEndpoint(tb testing.TB, option ...BundleEndpointOption) *BundleEndpoint {
	rootCAs, cert := test.CreateWebCredentials(tb)
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	be := &BundleEndpoint{
		tb:      tb,
		rootCAs: rootCAs,
		tlscfg:  tlscfg,
	}

	for _, opt := range option {
		opt.apply(be)
	}

	sm := http.NewServeMux()
	sm.HandleFunc("/test-bundle", be.testbundle)
	be.server = &http.Server{
		Handler:   sm,
		TLSConfig: be.tlscfg,
	}
	err := be.start()
	if err != nil {
		tb.Fatalf("Failed to start: %v", err)
	}
	return be
}

func (be *BundleEndpoint) Shutdown() {
	err := be.server.Shutdown(context.Background())
	assert.NoError(be.tb, err)
	be.wg.Wait()
}

func (be *BundleEndpoint) Addr() string {
	return be.addr.String()
}

func (be *BundleEndpoint) FetchBundleURL() string {
	return fmt.Sprintf("https://%s/test-bundle", be.Addr())
}

func (be *BundleEndpoint) RootCAs() *x509.CertPool {
	return be.rootCAs
}

func (be *BundleEndpoint) start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}

	be.addr = ln.Addr()

	be.wg.Add(1)
	go func() {
		err := be.server.ServeTLS(ln, "", "")
		assert.EqualError(be.tb, err, http.ErrServerClosed.Error())
		be.wg.Done()
		ln.Close()
	}()
	return nil
}

func (be *BundleEndpoint) testbundle(w http.ResponseWriter, r *http.Request) {
	if be.bundle == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bb, err := be.bundle.Marshal()
	assert.NoError(be.tb, err)
	w.Header().Add("Content-Type", "application/json")
	b, err := w.Write(bb)
	assert.NoError(be.tb, err)
	assert.Equal(be.tb, len(bb), b)
}

type bundleEndpointOption func(*BundleEndpoint)

// WithTestBundle sets the bundle that is returned by the Bundle Endpoint.
func (bundleEndpointOption) WithTestBundle(bundle *spiffebundle.Bundle) BundleEndpointOption {
	return bundleEndpointOption(func(be *BundleEndpoint) {
		be.bundle = bundle
	})
}

func (bundleEndpointOption) WithSPIFFEAuth(bundle *spiffebundle.Bundle, svid *x509svid.SVID) BundleEndpointOption {
	return bundleEndpointOption(func(be *BundleEndpoint) {
		be.rootCAs = x509util.NewCertPool(bundle.X509Roots())
		be.tlscfg = tlsconfig.TLSServerConfig(svid)
	})
}

func (beo bundleEndpointOption) apply(be *BundleEndpoint) {
	beo(be)
}
