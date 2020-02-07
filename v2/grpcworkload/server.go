package grpcworkload

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"google.golang.org/grpc"
)

type ServerOption interface{}

func WithGRPCServerOptions(options ...grpc.ServerOption) ServerOption {
	panic("not implemented")
}

func WithJWTSVIDValidation(audience string, validator spiffejwt.Validator) ServerOption {
	panic("not implemented")
}

type Server struct {
}

func (s *Server) GRPCServer() *grpc.Server {
	panic("not implemented")
}

func (s *Server) Close() error {
	panic("not implemented")
}

func NewTLSServer(ctx context.Context, options ...ServerOption) (*Server, error) {
	panic("not implemented")
}

func NewMTLSServer(ctx context.Context, validator spiffetls.Validator, options ...ServerOption) (*Server, error) {
	panic("not implemented")
}
