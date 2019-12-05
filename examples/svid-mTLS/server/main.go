package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"

	"github.com/spiffe/go-spiffe/spiffe"
)

// This example assumes this workload is identified by
// the SPIFFE ID: spiffe://example.org/server

const (
	serverAddress    = "localhost:55555"
	clientSpiffeID   = "spiffe://example.org/client"
	spiffeSocketPath = "unix:///tmp/agent.sock"
)

func main() {
	// Set SPIFFE_ENDPOINT_SOCKET to the workload API provider socket path (SPIRE is used in this example).
	// This can be set directly in your enviroment.
	err := os.Setenv("SPIFFE_ENDPOINT_SOCKET", spiffeSocketPath)
	if err != nil {
		log.Fatalf("Unable to set SPIFFE_ENDPOINT_SOCKET env variable: %v", err)
	}

	// Creates a TLS listener
	// The server expects the client to present an SVID with the spiffeID: 'spiffe://example.org/client'
	listener, err := spiffe.ListenTLS(context.Background(), "tcp", serverAddress, spiffe.ExpectPeer(clientSpiffeID))
	if err != nil {
		log.Fatalf("Unable to create TLS listener: %v", err)
	}

	// Handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			go handleError(err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read incoming data into buffer
	req, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading incoming data: %v", err)
		return
	}
	log.Printf("Client says: %q", req)

	// Send a response back to the client
	_, err = conn.Write([]byte("Hello client\n"))
	if err != nil {
		log.Printf("Unable to send response: %v", err)
		return
	}
}

func handleError(err error) {
	log.Printf("Unable to accept connection: %v", err)
}
