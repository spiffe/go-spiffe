package brokerapi_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/brokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func TestNewRequiresAuthorizer(t *testing.T) {
	client, err := brokerapi.New(context.Background(), nil)
	require.EqualError(t, err, "brokerapi: authorizer is required")
	require.Nil(t, client)
}

func TestNewRequiresAddress(t *testing.T) {
	unsetEnv(t, brokerapi.SocketEnv)

	client, err := brokerapi.New(context.Background(), tlsconfig.AuthorizeAny())
	require.EqualError(t, err, "brokerapi: address is not configured")
	require.Nil(t, client)
}

func TestNewUsesDefaultAddress(t *testing.T) {
	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := newTestWorkloadAPI(t, api)
	t.Setenv(workloadapi.SocketEnv, workloadAPI.Addr())
	t.Setenv(brokerapi.SocketEnv, api.Addr())

	client, err := brokerapi.New(context.Background(),
		tlsconfig.AuthorizeID(api.ServerID()),
	)
	require.NoError(t, err)
	require.NoError(t, client.Close())
}

func TestNewRejectsInvalidAddress(t *testing.T) {
	t.Setenv(brokerapi.SocketEnv, "")

	client, err := brokerapi.New(context.Background(), tlsconfig.AuthorizeAny())
	require.EqualError(t, err, "brokerapi: invalid address: "+brokerapi.ErrInvalidEndpointScheme.Error())
	require.Nil(t, client)
}

func TestNewHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, err := brokerapi.New(ctx, tlsconfig.AuthorizeAny())
	require.EqualError(t, err, context.Canceled.Error())
	require.Nil(t, client)
}

func TestClientClose(t *testing.T) {
	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := newTestWorkloadAPI(t, api)

	client, err := brokerapi.New(context.Background(),
		tlsconfig.AuthorizeID(api.ServerID()),
		brokerapi.WithAddr(api.Addr()),
		brokerapi.WithWorkloadAPISourceOptions(
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
		),
	)
	require.NoError(t, err)
	require.NoError(t, client.Close())
}

func TestNewUsesDefaultWorkloadAPISource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	unsetEnv(t, workloadapi.SocketEnv)

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := newTestWorkloadAPI(t, api)
	t.Setenv(workloadapi.SocketEnv, workloadAPI.Addr())

	client, err := brokerapi.New(ctx, tlsconfig.AuthorizeID(api.ServerID()), brokerapi.WithAddr(api.Addr()))
	require.NoError(t, err)
	require.NoError(t, client.Close())
}

func TestNewPassesWorkloadAPISourceOptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	unsetEnv(t, workloadapi.SocketEnv)

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := newTestWorkloadAPI(t, api)

	client, err := brokerapi.New(ctx,
		tlsconfig.AuthorizeID(api.ServerID()),
		brokerapi.WithAddr(api.Addr()),
		brokerapi.WithWorkloadAPISourceOptions(
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
		),
	)
	require.NoError(t, err)
	require.NoError(t, client.Close())
}

func TestNewUsesProvidedMTLSSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	unsetEnv(t, workloadapi.SocketEnv)

	api := fakebrokerapi.New(t)
	defer api.Stop()

	workloadAPI := newTestWorkloadAPI(t, api)

	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, source.Close())
	}()

	client, err := brokerapi.New(ctx,
		tlsconfig.AuthorizeID(api.ServerID()),
		brokerapi.WithAddr(api.Addr()),
		brokerapi.WithMTLSSource(source),
	)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	// The client must not close a source it does not own.
	_, err = source.GetX509SVID()
	require.NoError(t, err)
}

func TestNewFailsIfDefaultWorkloadAPISourceFails(t *testing.T) {
	unsetEnv(t, workloadapi.SocketEnv)

	api := fakebrokerapi.New(t)
	defer api.Stop()

	client, err := brokerapi.New(context.Background(), tlsconfig.AuthorizeAny(), brokerapi.WithAddr(api.Addr()))
	require.EqualError(t, err, "brokerapi: failed to create X.509 source: workload endpoint socket address is not configured")
	require.Nil(t, client)
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()

	value, ok := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))
	t.Cleanup(func() {
		if ok {
			require.NoError(t, os.Setenv(key, value))
		} else {
			require.NoError(t, os.Unsetenv(key))
		}
	})
}
