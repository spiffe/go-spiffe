package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"google.golang.org/grpc"
)

type Option interface{}

// WithAddr provides an address for the Workload API. The value of the
// SPIFFE_ENDPOINT_SOCKET environment variable will be used if the option
// is unused.
func WithAddr(addr string) Option {
	panic("not implemented")
}

// WithDialOptions provides extra GRPC dialing options when dialing the
// Workload API.
func WithDialOptions(options ...grpc.DialOption) Option {
	panic("not implemented")
}

// WithLogger provides a logger to the client.
func WithLogger(logger logger.Logger) Option {
	panic("not implemented")
}
