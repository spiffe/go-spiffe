package brokerapi

import (
	"context"
	"testing"
	"time"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func TestClientClosesOwnedWorkloadAPISource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := fakeworkloadapi.New(t)
	defer workloadAPI.Stop()
	workloadAPI.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{api.MTLSClientSVID()},
		Bundle: api.Bundle(),
	})
	t.Setenv(workloadapi.SocketEnv, workloadAPI.Addr())

	client, err := New(ctx, tlsconfig.AuthorizeID(api.ServerID()), WithAddr(api.Addr()))
	require.NoError(t, err)
	require.NotNil(t, client.ownedSource)

	require.NoError(t, client.Close())

	_, err = client.ownedSource.GetX509SVID()
	require.EqualError(t, err, "x509source: source is closed")
}

func TestClientAuthorizesServerSVID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := fakeworkloadapi.New(t)
	defer workloadAPI.Stop()
	workloadAPI.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{api.MTLSClientSVID()},
		Bundle: api.Bundle(),
	})

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	unauthorizedID := spiffeid.RequireFromPath(td, "/unauthorized")

	client, err := New(ctx,
		tlsconfig.AuthorizeID(unauthorizedID),
		WithAddr(api.Addr()),
		WithWorkloadAPISourceOptions(
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
		),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, client.Close())
	}()

	_, err = client.apiClient.SubscribeToX509SVID(ctx, &brokerpb.SubscribeToX509SVIDRequest{})
	require.ErrorContains(t, err, "unexpected ID")
}
