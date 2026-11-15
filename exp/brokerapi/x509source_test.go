package brokerapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/exp/brokerapi"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX509Source(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	federatedTD := spiffeid.RequireTrustDomainFromString("federated.test")
	federatedCA := test.NewCA(t, federatedTD)

	svid1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload1"))
	api.SetX509SVIDResponse(makeX509SVIDResponse(t, ca.X509Bundle(), []*x509svid.SVID{svid1}))

	reference := workloadReference()
	source, err := brokerapi.NewX509Source(ctx, client, reference)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	requireX509SVID(t, source, svid1)
	requireX509Bundle(t, source, td, ca.X509Bundle())
	requireWorkloadReference(t, api, reference)

	svid2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload2"))
	api.SetX509SVIDResponse(makeX509SVIDResponse(t, ca.X509Bundle(), []*x509svid.SVID{svid2}, federatedCA.X509Bundle()))
	require.NoError(t, source.WaitUntilUpdated(ctx))

	requireX509SVID(t, source, svid2)
	requireX509Bundle(t, source, td, ca.X509Bundle())
	requireX509Bundle(t, source, federatedTD, federatedCA.X509Bundle())

	// A PermissionDenied response indicates the workload is no longer
	// entitled to the previously received materials. The source must drop
	// them and retry.
	api.SetX509SVIDResponse(nil)
	require.NoError(t, source.WaitUntilUpdated(ctx))

	_, err = source.GetX509SVID()
	require.EqualError(t, err, "x509source: missing X509-SVID")

	_, err = source.GetX509BundleForTrustDomain(td)
	require.EqualError(t, err, `x509bundle: no X.509 bundle for trust domain "domain.test"`)
}

func TestX509SourceWaitsForInitialUpdate(t *testing.T) {
	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	source, err := brokerapi.NewX509Source(ctx, client, workloadReference())
	require.EqualError(t, err, context.DeadlineExceeded.Error())
	require.Nil(t, source)
}

func TestX509SourcePicker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload1"))
	svid2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload2"))
	svid3 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload3"))

	api.SetX509SVIDResponse(makeX509SVIDResponse(t, ca.X509Bundle(), []*x509svid.SVID{svid1, svid2, svid3}))

	source, err := brokerapi.NewX509Source(ctx, client, workloadReference(),
		brokerapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
			return svids[1]
		}),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	requireX509SVID(t, source, svid2)
}

func TestX509SourceFailsCallsIfClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	api.SetX509SVIDResponse(makeX509SVIDResponse(t, ca.X509Bundle(), []*x509svid.SVID{svid}))

	source, err := brokerapi.NewX509Source(ctx, client, workloadReference())
	require.NoError(t, err)
	require.NoError(t, source.Close())

	_, err = source.GetX509SVID()
	require.EqualError(t, err, "x509source: source is closed")

	_, err = source.GetX509BundleForTrustDomain(td)
	require.EqualError(t, err, "x509source: source is closed")
}

func TestX509SourceClientMethod(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	api.SetX509SVIDResponse(makeX509SVIDResponse(t, ca.X509Bundle(), []*x509svid.SVID{svid}))

	source, err := client.NewX509Source(ctx, workloadReference())
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, source.Close())
	}()

	requireX509SVID(t, source, svid)
}

func TestX509SourceRequiresClient(t *testing.T) {
	_, err := brokerapi.NewX509Source(context.Background(), nil, workloadReference())
	require.EqualError(t, err, "brokerapi: client is required")
}

func TestX509SourceRequiresWorkloadReference(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	source, err := brokerapi.NewX509Source(ctx, client, nil)
	require.EqualError(t, err, "brokerapi: workload reference is required")
	require.Nil(t, source)

	var typedNil *brokerpb.WorkloadPIDReference
	source, err = brokerapi.NewX509Source(ctx, client, typedNil)
	require.EqualError(t, err, "brokerapi: workload reference is not valid")
	require.Nil(t, source)
}

var (
	_ x509svid.Source   = (*brokerapi.X509Source)(nil)
	_ x509bundle.Source = (*brokerapi.X509Source)(nil)
)
