package examples_test

import (
	"context"
	"net"

	"github.com/spiffe/go-spiffe/v2/grpcworkload"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

func Example_gRPCMTLSServer() {
	server, err := grpcworkload.NewMTLSServer(context.TODO(), spiffetls.AllowAny())
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
