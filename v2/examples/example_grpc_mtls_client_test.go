package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/grpcworkload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

func Example_gRPCMTLSClient() {
	serverID := spiffeid.Make("example.org", "server")
	conn, err := grpcworkload.DialMTLS(context.TODO(), "example.org:8443", spiffetls.AllowID(serverID))
	if err != nil {
		// TODO: handle error
	}
	defer conn.Close()

	// TODO: create client
	// client := echo.NewEchoClient(conn.GRPCClientConn())
}
