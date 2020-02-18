package grpcworkload

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"google.golang.org/grpc"
)

// DialOptions are options specific to dialing
type DialOption interface{}

// PerRPCJWTSVID is returned from the WithPerRPCJWTSVID callback and influences
// the properties of the JWT-SVID that should be attached to the gRPC request.
type PerRPCJWTSVID struct {
	// Audience is one or more audience values to include in the per-rpc JWT-SVID
	Audience []string

	// If set, a JWT-SVID for this SPIFFE ID will be used
	ID spiffeid.ID
}

// WithPerRPCJWTSVID provides a callback that influences the properties of
// the JWT-SVID that should be attached to the gRPC request.
func WithPerRPCJWTSVID(func(uris ...string) PerRPCJWTSVID) DialOption {
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

// DialTLS dials a gRPC endpoint using the Workload API to obtain X.509 roots
// used to verify the server X509-SVID. The SPIFFE ID of the server is
// also validated against the given validator.
func DialTLS(ctx context.Context, addr string, validator spiffetls.Validator, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}

// DialMTLS dials a gRPC endpoint using the Workload API to obtain the
// X509-SVID presented to the server and X.509 roots used to the server
// X509-SVID. The SPIFFE ID of the server is also validated against the given
// validator.
func DialMTLS(ctx context.Context, addr string, validator spiffetls.Validator, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}
