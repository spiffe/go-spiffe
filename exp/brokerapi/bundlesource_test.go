package brokerapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/exp/brokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestBundleSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	federatedTD := spiffeid.RequireTrustDomainFromString("federated.test")
	federatedCA := test.NewCA(t, federatedTD)

	api.SetX509BundlesResponse(makeX509BundlesResponse(t, ca.X509Bundle()))
	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))

	reference := workloadReference()
	source, err := brokerapi.NewBundleSource(ctx, client, reference)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	requireX509Bundle(t, source, td, ca.X509Bundle())
	requireJWTBundle(t, source, td, ca.JWTBundle())
	requireWorkloadReference(t, api, reference)

	api.SetX509BundlesResponse(makeX509BundlesResponse(t, ca.X509Bundle(), federatedCA.X509Bundle()))
	require.NoError(t, source.WaitUntilUpdated(ctx))
	requireX509Bundle(t, source, td, ca.X509Bundle())
	requireX509Bundle(t, source, federatedTD, federatedCA.X509Bundle())

	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle(), federatedCA.JWTBundle()))
	require.NoError(t, source.WaitUntilUpdated(ctx))
	requireJWTBundle(t, source, td, ca.JWTBundle())
	requireJWTBundle(t, source, federatedTD, federatedCA.JWTBundle())
}

func TestBundleSourceWaitsForInitialUpdates(t *testing.T) {
	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	api.SetX509BundlesResponse(makeX509BundlesResponse(t, ca.X509Bundle()))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	source, err := brokerapi.NewBundleSource(ctx, client, workloadReference())
	require.EqualError(t, err, context.DeadlineExceeded.Error())
	require.Nil(t, source)
}

func TestBundleSourceFailsCallsIfClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	api.SetX509BundlesResponse(makeX509BundlesResponse(t, ca.X509Bundle()))
	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))

	source, err := brokerapi.NewBundleSource(ctx, client, workloadReference())
	require.NoError(t, err)
	require.NoError(t, source.Close())

	_, err = source.GetX509BundleForTrustDomain(td)
	require.EqualError(t, err, "bundlesource: source is closed")

	_, err = source.GetJWTBundleForTrustDomain(td)
	require.EqualError(t, err, "bundlesource: source is closed")
}

func TestBundleSourceClientMethod(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	api.SetX509BundlesResponse(makeX509BundlesResponse(t, ca.X509Bundle()))
	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))

	source, err := client.NewBundleSource(ctx, workloadReference())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	requireX509Bundle(t, source, td, ca.X509Bundle())
	requireJWTBundle(t, source, td, ca.JWTBundle())
}

var (
	_ x509bundle.Source = (*brokerapi.BundleSource)(nil)
	_ jwtbundle.Source  = (*brokerapi.BundleSource)(nil)
)
