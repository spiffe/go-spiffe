package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

const socketPath = "unix:///tmp/agent.sock"

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	// If socket path is not defined using `workloadapi.SourceOption`, value from environment variable `SPIFFE_ENDPOINT_SOCKET` is used.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	clientID := spiffeid.RequireFromString("spiffe://example.org/client")

	// Create a server with credentials that do mTLS and verify that the presented certificate has SPIFFE ID `spiffe://example.org/client`
	s := grpc.NewServer(grpc.Creds(
		grpccredentials.MTLSServerCredentials(source, source, tlsconfig.AuthorizeID(clientID)),
	))

	lis, err := net.Listen("tcp", "127.0.0.1:50051")
	if err != nil {
		return fmt.Errorf("error creating listener: %w", err)
	}

	pb.RegisterGreeterServer(s, &server{})

	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}
