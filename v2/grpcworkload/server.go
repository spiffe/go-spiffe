package grpcworkload

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"google.golang.org/grpc"
)

// ServerOption is additional options for the gRPC server
type ServerOption interface{}

// WithGRPCServerOptions are extra options to provide to grpc.NewServer when
// the server is being created. These options will be added before other
// options that are added by this package.
func WithGRPCServerOptions(options ...grpc.ServerOption) ServerOption {
	panic("not implemented")
}

// WithJWTSVIDValidation causes the server to require clients to provide
// JWT-SVIDs for authentication, which are verified using the Workload API and
// validated against the given audience and validator.
func WithJWTSVIDValidation(audience string, validator spiffejwt.Validator) ServerOption {
	panic("not implemented")
}

// Server is a gRPC server backed by SPIFFE authentication
type Server struct {
}

// GRPCServer returns the underlying gRPC server
func (s *Server) GRPCServer() *grpc.Server {
	panic("not implemented")
}

// Close closes the server, tearing down streams and disconnecting
// from the workload API. It also calls Stop() on the underlying
// gRPC server. If graceful shutdown is desired, the caller can invoke
// GracefulStop() on the underlying gRPC server before calling Close().
func (s *Server) Close() error {
	panic("not implemented")
}

// NewTLSServer creates a new TLS server that uses the Workload API to provide
// up-to-date X509-SVIDs for the TLS handshake.
func NewTLSServer(ctx context.Context, options ...ServerOption) (*Server, error) {
	panic("not implemented")
}

// NewMTLSServer creates a new mTLS server that uses the Workload API to provide
// up-to-date X509-SVIDs for the TLS handshake and trusted X.509 roots to verify
// client X509-SVIDs. The given validator is used to validate the client.
func NewMTLSServer(ctx context.Context, validator spiffetls.Validator, options ...ServerOption) (*Server, error) {
	panic("not implemented")
}
