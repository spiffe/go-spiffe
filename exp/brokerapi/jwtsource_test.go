package brokerapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/exp/brokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
)

func TestJWTSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	federatedTD := spiffeid.RequireTrustDomainFromString("federated.test")
	federatedCA := test.NewCA(t, federatedTD)

	audience := []string{"audience"}
	svid1 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/workload1"), audience)
	svid2 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/workload2"), audience)

	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))
	api.SetJWTSVIDResponse(makeJWTSVIDResponse(svid1, svid2))

	reference := workloadReference()
	source, err := brokerapi.NewJWTSource(ctx, client, reference)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	requireJWTBundle(t, source, td, ca.JWTBundle())

	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience[0]})
	require.NoError(t, err)
	require.Equal(t, svid1.Marshal(), svid.Marshal())

	svid, err = source.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience[0],
		Subject:  svid2.ID,
	})
	require.NoError(t, err)
	require.Equal(t, svid2.Marshal(), svid.Marshal())

	svids, err := source.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: audience[0]})
	require.NoError(t, err)
	require.Len(t, svids, 2)

	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle(), federatedCA.JWTBundle()))
	require.NoError(t, source.WaitUntilUpdated(ctx))

	requireJWTBundle(t, source, td, ca.JWTBundle())
	requireJWTBundle(t, source, federatedTD, federatedCA.JWTBundle())
	requireWorkloadReference(t, api, reference)
}

func TestJWTSourceWaitsForInitialUpdate(t *testing.T) {
	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	source, err := brokerapi.NewJWTSource(ctx, client, workloadReference())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "PermissionDenied")
	require.Nil(t, source)
}

func TestJWTSourcePicker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	audience := []string{"audience"}
	svid1 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/workload1"), audience)
	svid2 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/workload2"), audience)

	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))
	api.SetJWTSVIDResponse(makeJWTSVIDResponse(svid1, svid2))

	source, err := brokerapi.NewJWTSource(ctx, client, workloadReference(),
		brokerapi.WithDefaultJWTSVIDPicker(func(svids []*jwtsvid.SVID) *jwtsvid.SVID {
			return svids[1]
		}),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience[0]})
	require.NoError(t, err)
	require.Equal(t, svid2.Marshal(), svid.Marshal())
}

func TestJWTSourceFailsCallsIfClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))

	source, err := brokerapi.NewJWTSource(ctx, client, workloadReference())
	require.NoError(t, err)
	require.NoError(t, source.Close())

	_, err = source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "audience"})
	require.EqualError(t, err, "jwtsource: source is closed")

	_, err = source.GetJWTBundleForTrustDomain(td)
	require.EqualError(t, err, "jwtsource: source is closed")
}

func TestJWTSourceRequiresAudience(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()
	client := newTestClient(t, api)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	api.SetJWTBundlesResponse(makeJWTBundlesResponse(t, ca.JWTBundle()))

	source, err := brokerapi.NewJWTSource(ctx, client, workloadReference())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	_, err = source.FetchJWTSVID(ctx, jwtsvid.Params{})
	require.EqualError(t, err, "jwtsource: audience is required")
}

var (
	_ jwtsvid.Source   = (*brokerapi.JWTSource)(nil)
	_ jwtbundle.Source = (*brokerapi.JWTSource)(nil)
)
