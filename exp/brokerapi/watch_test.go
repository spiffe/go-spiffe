package brokerapi

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWatchTerminalErrors(t *testing.T) {
	testCases := []struct {
		name        string
		code        codes.Code
		wantCleared bool
	}{
		{
			name: "invalid argument",
			code: codes.InvalidArgument,
		},
		{
			name: "unimplemented",
			code: codes.Unimplemented,
		},
		{
			name:        "not found",
			code:        codes.NotFound,
			wantCleared: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var cleared bool
			err := watch(context.Background(), logger.Null, zeroBackoffStrategy{}, "test",
				func(context.Context) (recvFunc[int], error) {
					return func() (int, error) {
						return 0, status.Error(testCase.code, "test error")
					}, nil
				},
				func(int) error { return nil },
				func() { cleared = true },
				nil,
			)
			require.Equal(t, testCase.code, status.Code(err))
			require.Equal(t, testCase.wantCleared, cleared)
		})
	}
}

func TestWatchClearsOnPermissionDenied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var clears int
	err := watch(ctx, logger.Null, zeroBackoffStrategy{}, "test",
		func(context.Context) (recvFunc[int], error) {
			return func() (int, error) {
				return 0, status.Error(codes.PermissionDenied, "permission denied")
			}, nil
		},
		func(int) error { return nil },
		func() {
			clears++
			cancel()
		},
		nil,
	)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, clears)
}

func TestWatchRetriesCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts := 0
	err := watch(ctx, logger.Null, zeroBackoffStrategy{}, "test",
		func(context.Context) (recvFunc[int], error) {
			attempts++
			if attempts > 1 {
				cancel()
			}
			return func() (int, error) {
				return 0, status.Error(codes.Canceled, "canceled")
			}, nil
		},
		func(int) error { return nil },
		nil,
		nil,
	)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 2, attempts)
}

func TestWatchTerminalUpdateError(t *testing.T) {
	err := watch(context.Background(), logger.Null, zeroBackoffStrategy{}, "test",
		func(context.Context) (recvFunc[int], error) {
			return func() (int, error) { return 1, nil }, nil
		},
		func(int) error {
			return newWatchTerminalError(status.Error(codes.Internal, "terminal"))
		},
		nil,
		nil,
	)
	require.EqualError(t, err, "rpc error: code = Internal desc = terminal")
}

type zeroBackoffStrategy struct{}

func (zeroBackoffStrategy) NewBackoff() workloadapi.Backoff {
	return zeroBackoff{}
}

type zeroBackoff struct{}

func (zeroBackoff) Next() time.Duration { return 0 }
func (zeroBackoff) Reset()              {}
