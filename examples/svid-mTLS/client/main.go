package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/spiffe"
)

// This example assumes this workload is identified by
// the SPIFFE ID: spiffe://example.org/client

const (
	serverAddress    = "localhost:55555"
	serverSpiffeID   = "spiffe://example.org/server"
	spiffeSocketPath = "unix:///tmp/agent.sock"
	dialTimeout      = 3 * time.Second
)

func main() {
	// Set SPIFFE_ENDPOINT_SOCKET to the workload API provider socket path (SPIRE is used in this example).
	// This can be set directly in your enviroment.
	err := os.Setenv("SPIFFE_ENDPOINT_SOCKET", spiffeSocketPath)
	if err != nil {
		log.Fatalf("Unable to set SPIFFE_ENDPOINT_SOCKET env variable: %v", err)
	}

	// Setup context
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	// Create a TLS connection.
	// The client expects the server to present an SVID with the spiffeID: 'spiffe://example.org/server'
	conn, err := spiffe.DialTLS(ctx, "tcp", serverAddress, spiffe.ExpectPeer(serverSpiffeID))
	if err != nil {
		log.Fatalf("Unable to create TLS connection: %v", err)
	}

	// Send a message to the server using the TLS connection
	fmt.Fprintf(conn, "Hello server\n")

	// Read server response
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		log.Fatalf("Unable to read server response: %v", err)
	}
	log.Printf("Server says: %q", status)
}
