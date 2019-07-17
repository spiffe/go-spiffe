package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestDial(t *testing.T) {
	_, err := Dial()
	require.EqualError(t, err, "workload endpoint socket address is not configured")

	_, err = Dial(WithAddr(""))
	require.EqualError(t, err, "workload endpoint socket address is not configured")

	_, err = Dial(WithAddr("blah"))
	require.EqualError(t, err, "workload endpoint socket URI must have a tcp:// or unix:// scheme")

	_, err = Dial(WithAddr("tcp://127.0.0.1:0"),
		WithGRPCOptions(grpc.WithBlock(), grpc.FailOnNonTempDialError(true)))
	require.Error(t, err)

	conn, err := Dial(WithAddr("tcp://127.0.0.1:0"))
	require.NoError(t, err)
	conn.Close()
}

func TestDialContext(t *testing.T) {
	_, err := DialContext(context.Background())
	require.EqualError(t, err, "workload endpoint socket address is not configured")

	_, err = DialContext(context.Background(), WithAddr(""))
	require.EqualError(t, err, "workload endpoint socket address is not configured")

	_, err = DialContext(context.Background(), WithAddr("blah"))
	require.EqualError(t, err, "workload endpoint socket URI must have a tcp:// or unix:// scheme")

	_, err = DialContext(context.Background(), WithAddr("tcp://127.0.0.1:0"),
		WithGRPCOptions(grpc.WithBlock(), grpc.FailOnNonTempDialError(true)))
	require.Error(t, err)

	conn, err := DialContext(context.Background(), WithAddr("tcp://127.0.0.1:0"))
	require.NoError(t, err)
	conn.Close()
}
