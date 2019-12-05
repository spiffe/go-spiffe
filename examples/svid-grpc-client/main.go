package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	workload_dial "github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc/metadata"
)

const (
	// Workload API (SPIRE default socket is assumed)
	socketPath = "/tmp/agent.sock"

	// optional timeout for the client context
	timeout = 5 * time.Second
)

func main() {
	// Create a gRPC connection to the workload API
	ctx := context.Background()
	conn, err := workload_dial.Dial(ctx, &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		log.Fatalf("Unable to dial to %q: %v", socketPath, err)
	}

	// Create the spiffe workload client
	client := workload.NewSpiffeWorkloadAPIClient(conn)

	// Fetch X.509 SVIDs for this workload
	x509Resp, err := fetchX509SVID(ctx, timeout, client)
	if err != nil {
		log.Fatalf("Unable to fetch X.509 SVID: %v", err)
	}

	// Print the received X509 SVIDs
	printX509SVIDs(x509Resp)

	// Fetch JWT SVIDs for this workload
	jwtResp, err := fetchJWTSVID(ctx, timeout, client)
	if err != nil {
		log.Fatalf("Unable to fetch JWT SVID: %v", err)
	}

	// Print the received JWT SVIDs
	printJWTSVIDs(jwtResp)
}

// fetchX509SVID fetches the X.509 SVID(s) for this workload
func fetchX509SVID(ctx context.Context, timeout time.Duration, client workload.SpiffeWorkloadAPIClient) (*workload.X509SVIDResponse, error) {
	// Set up the context for fetch call
	ctx, cancel := prepareContext(ctx, timeout)
	defer cancel()

	// Open stream to SPIRE agent
	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch X.509 SVID: %v", err)
	}

	// Receive available SVID(s)
	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("Unable to receive SVID from stream: %v", err)
	}

	return resp, nil
}

// fetchX509SVID fetches the JWT SVID(s) for this workload
func fetchJWTSVID(ctx context.Context, timeout time.Duration, client workload.SpiffeWorkloadAPIClient) (*workload.JWTSVIDResponse, error) {
	// Set up the context for fetch call
	ctx, cancel := prepareContext(ctx, timeout)
	defer cancel()

	// Create the JWT SVID request. Audience is mandatory
	req := &workload.JWTSVIDRequest{
		Audience: []string{"spiffe://example.org/service-1"},
	}

	// Fetch the SVID from the workload API
	resp, err := client.FetchJWTSVID(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch JWT SVID: %v", err)
	}

	return resp, nil
}

// printX509SVIDs prints a x509SVIDResponse
func printX509SVIDs(x509Resp *workload.X509SVIDResponse) {
	log.Printf("Received %d X.509 SVID(s)", len(x509Resp.Svids))
	for i, v := range x509Resp.Svids {
		certs, err := x509.ParseCertificates(v.X509Svid)
		if err != nil {
			log.Fatalf("Unable to parse certificate: %v", err)
		}
		log.Printf("SVID %d is %q: \n%s\n", i, v.SpiffeId, string(pemutil.EncodeCertificates(certs)))
	}
}

// printJWTSVIDs prints a JWTSVIDResponse
func printJWTSVIDs(jwtResp *workload.JWTSVIDResponse) {
	log.Printf("Received %d JWT SVID(s)", len(jwtResp.Svids))
	for i, v := range jwtResp.Svids {
		log.Printf("SVID %d is %q: \n%s\n", i, v.SpiffeId, v.Svid)
	}
}

// prepareContext adds the security metadata header and timeout
func prepareContext(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	header := metadata.Pairs("workload.spiffe.io", "true")
	ctx = metadata.NewOutgoingContext(ctx, header)
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, func() {}
}
