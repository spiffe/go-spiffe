package federation_test

import (
	"context"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fake"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
)

func TestFetchBundle_WebPKIAuth(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t)
	bundle := spiffebundle.FromX509Bundle(ca.Bundle(td))

	be := fake.NewBundleEndpoint(context.Background(), t, 1025,
		fake.BEOption.WithTestBundle(bundle))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetchedBundle, err := federation.FetchBundle(ctx, td, "https://127.0.0.1:1025/test-bundle",
		federation.WithWebPKIAuth(be.RootCAs()))
	assert.NoError(t, err)
	assert.True(t, bundle.Equal(fetchedBundle))
}

func TestFetchBundle_SPIFFEAuth(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := td.NewID("control-plane/test-bundle-endpoint")
	ipaddresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	ca := test.NewCA(t, test.WithIPAddresses(ipaddresses))
	cert, pk := ca.CreateX509SVID(id.String(), test.WithIPAddresses(ipaddresses))
	svid := &x509svid.SVID{ID: id, Certificates: cert, PrivateKey: pk}
	bundle := spiffebundle.FromX509Bundle(ca.Bundle(td))

	be := fake.NewBundleEndpoint(context.Background(), t, 1025,
		fake.BEOption.WithTestBundle(bundle),
		fake.BEOption.WithSPIFFEAuth(bundle, svid))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetchedBundle, err := federation.FetchBundle(ctx, td, "https://localhost:1025/test-bundle",
		federation.WithSPIFFEAuth(bundle, id))
	assert.NoError(t, err)
	assert.True(t, bundle.Equal(fetchedBundle))
}

func TestFetchBundle_SPIFFEAuth_UnexpectedID(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := td.NewID("control-plane/test-bundle-endpoint")
	ipaddresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	ca := test.NewCA(t, test.WithIPAddresses(ipaddresses))
	cert, pk := ca.CreateX509SVID(id.String(), test.WithIPAddresses(ipaddresses))
	svid := &x509svid.SVID{ID: id, Certificates: cert, PrivateKey: pk}
	bundle := spiffebundle.FromX509Bundle(ca.Bundle(td))

	be := fake.NewBundleEndpoint(context.Background(), t, 1025,
		fake.BEOption.WithTestBundle(bundle),
		fake.BEOption.WithSPIFFEAuth(bundle, svid))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetchedBundle, err := federation.FetchBundle(ctx, td, "https://localhost:1025/test-bundle",
		federation.WithSPIFFEAuth(bundle, td.NewID("other/id")))
	assert.EqualError(t, err, `federation: could not GET bundle: Get "https://localhost:1025/test-bundle": unexpected ID "spiffe://domain.test/control-plane/test-bundle-endpoint"`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorCreatingRequest(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	fetchedBundle, err := federation.FetchBundle(nil, td, "https://127.0.0.1:1025/test-bundle") //nolint
	assert.EqualError(t, err, `federation: could not create request: net/http: nil Context`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorGettingBundle(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	be := fake.NewBundleEndpoint(context.Background(), t, 1025)
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetchedBundle, err := federation.FetchBundle(ctx, td, "https://127.0.0.1:1025/test-bundle",
		federation.WithWebPKIAuth(be.RootCAs()))
	assert.EqualError(t, err, `federation: could not GET bundle: Get "http://localhost:1025/test-bundle": context canceled`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorReadingBundleBody(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	be := fake.NewBundleEndpoint(context.Background(), t, 1025)
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetchedBundle, err := federation.FetchBundle(ctx, td, "https://127.0.0.1:1025/test-bundle",
		federation.WithWebPKIAuth(be.RootCAs()))
	assert.EqualError(t, err, `federation: spiffebundle: unable to parse JWKS: unexpected end of JSON input`)
	assert.Nil(t, fetchedBundle)
}
