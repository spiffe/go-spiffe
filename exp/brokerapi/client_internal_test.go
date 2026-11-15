package brokerapi

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
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

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/broker"))

	workloadAPI := fakeworkloadapi.New(t)
	defer workloadAPI.Stop()
	workloadAPI.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid},
		Bundle: ca.X509Bundle(),
	})
	t.Setenv(workloadapi.SocketEnv, workloadAPI.Addr())

	api := fakebrokerapi.New(t)
	defer api.Stop()

	client, err := New(ctx, tlsconfig.AuthorizeAny(), WithAddr(api.Addr()))
	require.NoError(t, err)
	require.NotNil(t, client.ownedSource)

	require.NoError(t, client.Close())

	_, err = client.ownedSource.GetX509SVID()
	require.EqualError(t, err, "x509source: source is closed")
}
