package brokerapi

import (
	"context"
	"strings"
	"testing"
	"time"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
)

func TestRoundRobinLoadBalancing(t *testing.T) {
	testCases := []struct {
		name    string
		options []ClientOption
	}{
		{
			name:    "WithRoundRobin",
			options: []ClientOption{WithRoundRobin()},
		},
		{
			name: "WithDialOptions",
			options: []ClientOption{
				WithDialOptions(grpc.WithDefaultServiceConfig(roundRobinServiceConfig)),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testRoundRobinLoadBalancing(t, testCase.options...)
		})
	}
}

func testRoundRobinLoadBalancing(t *testing.T, serviceConfigOptions ...ClientOption) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := fakeworkloadapi.New(t)
	defer workloadAPI.Stop()
	workloadAPI.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{api.MTLSClientSVID()},
		Bundle: api.Bundle(),
	})

	addr1 := strings.TrimPrefix(api.Addr(), "tcp://")
	addr2 := api.AddListener(t)

	options := []ClientOption{
		WithAddr("dns:///broker.example.org:443"),
		WithWorkloadAPISourceOptions(
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
		),
		WithDialOptions(grpc.WithResolvers(staticResolverBuilder{
			addrs: []resolver.Address{{Addr: addr1}, {Addr: addr2}},
		})),
	}
	options = append(options, serviceConfigOptions...)

	client, err := New(context.Background(), tlsconfig.AuthorizeID(api.ServerID()), options...)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, client.Close())
	}()

	reference, err := newWorkloadReference(&brokerpb.WorkloadPIDReference{Pid: 1234})
	require.NoError(t, err)
	api.SetJWTSVIDResponse(&brokerpb.FetchJWTSVIDResponse{})

	fetch := func() {
		_, err := client.apiClient.FetchJWTSVID(ctx, &brokerpb.FetchJWTSVIDRequest{
			Reference: reference,
			Audience:  []string{"audience"},
		}, grpc.WaitForReady(true))
		require.NoError(t, err)
	}

	// Wait until the round-robin balancer has served requests on both
	// resolved addresses.
	require.Eventually(t, func() bool {
		fetch()
		counts := api.RequestCountsByLocalAddr()
		return counts[addr1] > 0 && counts[addr2] > 0
	}, 10*time.Second, 10*time.Millisecond)

	before := api.RequestCountsByLocalAddr()
	const requests = 10
	for range requests {
		fetch()
	}
	after := api.RequestCountsByLocalAddr()

	require.Equal(t, requests/2, after[addr1]-before[addr1])
	require.Equal(t, requests/2, after[addr2]-before[addr2])
}

type staticResolverBuilder struct {
	addrs []resolver.Address
}

func (staticResolverBuilder) Scheme() string {
	return "dns"
}

func (b staticResolverBuilder) Build(_ resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	if err := cc.UpdateState(resolver.State{Addresses: b.addrs}); err != nil {
		return nil, err
	}
	return b, nil
}

func (b staticResolverBuilder) ResolveNow(resolver.ResolveNowOptions) {}

func (b staticResolverBuilder) Close() {}
