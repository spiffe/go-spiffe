package main

import (
	"context"
	"log"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

// Workload API socket path
const socketPath = "unix:///tmp/agent.sock"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	// If socket path is not defined using `workloadapi.SourceOption`, value from environment variable `SPIFFE_ENDPOINT_SOCKET` is used.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireFromString("spiffe://example.org/server")

	// Dial the server with credentials that do mTLS and verify that presented certificate has SPIFFE ID `spiffe://example.org/server`
	conn, err := grpc.DialContext(ctx, "localhost:50051", grpc.WithTransportCredentials(
		grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeID(serverID)),
	))
	if err != nil {
		log.Fatalf("Error creating dial: %v", err)
	}

	client := pb.NewGreeterClient(conn)
	reply, err := client.SayHello(ctx, &pb.HelloRequest{Name: "world"})
	if err != nil {
		log.Fatalf("Error connecting to server %v", err)
	}

	log.Print(reply.Message)
}
