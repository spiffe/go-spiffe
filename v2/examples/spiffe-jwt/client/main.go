package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	serverURL  = "https://localhost:8443"
	socketPath = "unix:///tmp/agent.sock"
)

func main() {
	// Time out the example after 30 seconds. This prevents the example from hanging if the workloads are not properly registered with SPIRE.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create client options to setup expected socket path,
	// as default sources will use value from environment variable `SPIFFE_ENDPOINT_SOCKET`
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create X509 source to fetch bundle certificate used to verify presented certificate from server
	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer x509Source.Close()

	// Create a `tls.Config` with configuration to allow TLS communication, and verify that presented certificate from server has SPIFFE ID `spiffe://example.org/server`
	serverID := spiffeid.Must("example.org", "server")
	tlsConfig := tlsconfig.TLSClientConfig(x509Source, tlsconfig.AuthorizeID(serverID))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		log.Fatalf("Unable to create request: %v", err)
	}

	// As default example is using server's ID,
	// It doesn't have to be an SPIFFE ID as long it follows JWT SVIDs the guidelines (https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md#32-audience)
	audience := serverID.String()
	args := os.Args
	if len(args) >= 2 {
		audience = args[1]
	}

	// Create a JWTSource to fetch SVIDs
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create JWTSource: %v", err)
	}
	defer jwtSource.Close()

	// Fetch JWT SVID and add it to `Authorization` header,
	// It is possible to fetch JWT SVID using `workloadapi.FetchJWTSVID`
	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", svid.Marshal()))

	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Unable to connect to %q: %v", serverURL, err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}
	log.Printf("%s", body)
}
