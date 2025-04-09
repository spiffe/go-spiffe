package federation_test

import (
	"context"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebundleendpoint"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

var (
	td           = spiffeid.RequireTrustDomainFromString("domain.test")
	localhostIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
)

func TestFetchBundle_WebPKIRoots(t *testing.T) {
	ca := test.NewCA(t, td)
	bundle := ca.Bundle()

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle))
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithWebPKIRoots(be.RootCAs()))
	assert.NoError(t, err)
	assert.Equal(t, fetchedBundle, bundle)
}

func TestFetchBundle_SPIFFEAuth(t *testing.T) {
	id := spiffeid.RequireFromPath(td, "/control-plane/test-bundle-endpoint")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(id, test.WithIPAddresses(localhostIPs...))
	bundle := ca.Bundle()

	be := fakebundleendpoint.New(t,
		fakebundleendpoint.WithTestBundles(bundle),
		fakebundleendpoint.WithSPIFFEAuth(bundle, svid))
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithSPIFFEAuth(bundle, id))
	assert.NoError(t, err)
	assert.Equal(t, fetchedBundle, bundle)
}

func TestFetchBundle_SPIFFEAuth_UnexpectedID(t *testing.T) {
	id := spiffeid.RequireFromPath(td, "/control-plane/test-bundle-endpoint")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(id, test.WithIPAddresses(localhostIPs...))
	bundle := ca.Bundle()

	be := fakebundleendpoint.New(t,
		fakebundleendpoint.WithTestBundles(bundle),
		fakebundleendpoint.WithSPIFFEAuth(bundle, svid))
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithSPIFFEAuth(bundle, spiffeid.RequireFromPath(td, "/other/id")))
	assert.Regexp(t, `federation: could not GET bundle: Get "?`+be.FetchBundleURL()+`"?: unexpected ID "spiffe://domain.test/control-plane/test-bundle-endpoint"`, err.Error())
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_SPIFFEAuthAndWebPKIRoots(t *testing.T) {
	fetchedBundle, err := federation.FetchBundle(context.Background(), td, "url not used",
		federation.WithSPIFFEAuth(nil, spiffeid.ID{}),
		federation.WithWebPKIRoots(nil))
	assert.EqualError(t, err, `federation: cannot use both SPIFFE and Web PKI authentication`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_WebPKIRootsAndSPIFFEAuth(t *testing.T) {
	fetchedBundle, err := federation.FetchBundle(context.Background(), td, "url not used",
		federation.WithWebPKIRoots(nil),
		federation.WithSPIFFEAuth(nil, spiffeid.ID{}))
	assert.EqualError(t, err, `federation: cannot use both SPIFFE and Web PKI authentication`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorCreatingRequest(t *testing.T) {
	fetchedBundle, err := federation.FetchBundle(nil, td, "url not used") //nolint
	assert.EqualError(t, err, `federation: could not create request: net/http: nil Context`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorGettingBundle(t *testing.T) {
	be := fakebundleendpoint.New(t)
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetchedBundle, err := federation.FetchBundle(ctx, td, be.FetchBundleURL(),
		federation.WithWebPKIRoots(be.RootCAs()))
	assert.Regexp(t, `federation: could not GET bundle: Get "?`+be.FetchBundleURL()+`"?: context canceled`, err.Error())
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorReadingBundleBody(t *testing.T) {
	be := fakebundleendpoint.New(t)
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithWebPKIRoots(be.RootCAs()))
	assert.EqualError(t, err, `federation: spiffebundle: unable to parse JWKS: unexpected end of JSON input`)
	assert.Nil(t, fetchedBundle)
}
