package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	socketPath    = "unix:///tmp/agent.sock"
	serverAddress = "localhost:55555"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireFromString("spiffe://example.org/server")

	// Create a TLS connection.
	// The client expects the server to present an SVID with the spiffeID: 'spiffe://example.org/server'
	//
	// An alternative when creating Dial is using `spiffetls.Dial` that uses environment variable `SPIFFE_ENDPOINT_SOCKET`
	conn, err := spiffetls.DialWithMode(ctx, "tcp", serverAddress,
		spiffetls.MTLSClientWithSourceOptions(
			tlsconfig.AuthorizeID(serverID),
			workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
		))
	if err != nil {
		return fmt.Errorf("unable to create TLS connection: %w", err)
	}
	defer conn.Close()

	// Send a message to the server using the TLS connection
	fmt.Fprintf(conn, "Hello server\n")

	// Read server response
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read server response: %w", err)
	}
	log.Printf("Server says: %q", status)
	return nil
}
