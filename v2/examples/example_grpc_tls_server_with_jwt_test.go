package examples_test

import (
	"context"
	"net"

	"github.com/spiffe/go-spiffe/v2/grpcworkload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffejwt"
)

func Example_gRPCTLSServerWithJWT() {
	td := spiffeid.TrustDomain("example.org")
	serverID := spiffeid.Make(td, "server")
	server, err := grpcworkload.NewTLSServer(context.TODO(),
		grpcworkload.WithJWTSVIDValidation(serverID.String(), spiffejwt.AllowTrustDomain(td)))
	if err != nil {
		// TODO: handle error
	}
	defer server.Close()

	// TODO: register services

	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		// TODO: handle error
	}

	if err := server.GRPCServer().Serve(listener); err != nil {
		// TODO: handle error
	}
}
