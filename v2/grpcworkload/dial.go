package grpcworkload

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"google.golang.org/grpc"
)

// DialOptions are options specific to dialing
type DialOption interface{}

type PerRPCJWTSVID struct {
	// Audience is one or more audience values to include in the per-rpc JWT-SVID
	Audience []string

	// If set, a JWT-SVID for this SPIFFE ID will be used
	ID spiffeid.ID
}

func WithPerPRCJWTSVID(func(uris ...string) PerRPCJWTSVID) DialOption {
	panic("not implemented")
}

// Conn is a gRPC workload connection. It uses the Workload API to facilitate
// authenticated connectivity to a gRPC server.
type Conn struct {
}

// GRPCClientConn returns the underlying workload gRPC client connection
func (c *Conn) GRPCClientConn() *grpc.ClientConn {
	panic("not implemented")
}

// Close closes the connection. The underlying gRPC client
// connection is also closed
func (c *Conn) Close() error {
	panic("not implemented")
}

func DialTLS(ctx context.Context, addr string, validator spiffetls.Validator, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}

func DialMTLS(ctx context.Context, addr string, validator spiffetls.Validator, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}
