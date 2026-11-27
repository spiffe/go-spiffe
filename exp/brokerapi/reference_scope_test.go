package brokerapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/brokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func TestSourcesRejectPIDReferenceForRemoteBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := newTestWorkloadAPI(t, api)

	client, err := brokerapi.New(ctx,
		tlsconfig.AuthorizeAny(),
		brokerapi.WithAddr("tcp://192.0.2.1:8443"),
		brokerapi.WithWorkloadAPISourceOptions(
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
		),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, client.Close())
	}()

	testCases := []struct {
		name      string
		newSource func() error
	}{
		{
			name: "X.509 source",
			newSource: func() error {
				_, err := brokerapi.NewX509Source(ctx, client, workloadReference())
				return err
			},
		},
		{
			name: "JWT source",
			newSource: func() error {
				_, err := brokerapi.NewJWTSource(ctx, client, workloadReference())
				return err
			},
		},
		{
			name: "bundle source",
			newSource: func() error {
				_, err := brokerapi.NewBundleSource(ctx, client, workloadReference())
				return err
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.ErrorContains(t, testCase.newSource(), "workload PID references can only be used with a local Broker API address")
		})
	}
}
