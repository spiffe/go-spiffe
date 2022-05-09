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
	// Set a timeout to prevent the request from hanging if this workload is not properly registered in SPIRE.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create an X509Source struct to fetch the trust bundle as needed to verify the X509-SVID presented by the server.
	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer x509Source.Close()

	serverID := spiffeid.RequireFromString("spiffe://example.org/server")

	// By default, this example uses the server's SPIFFE ID as the audience.
	// It doesn't have to be a SPIFFE ID as long as it follows the JWT-SVID guidelines (https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md#32-audience)
	audience := serverID.String()
	args := os.Args
	if len(args) >= 2 {
		audience = args[1]
	}

	// Create a JWTSource to fetch JWT-SVIDs
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create JWTSource: %v", err)
	}
	defer jwtSource.Close()

	// Fetch a JWT-SVID and set the `Authorization` header.
	// Alternatively, it is possible to fetch the JWT-SVID using `workloadapi.FetchJWTSVID`.
	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		log.Fatalf("Unable to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", svid.Marshal()))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.TLSClientConfig(
				x509Source,
				tlsconfig.AuthorizeID(serverID),
			),
		},
	}
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Unable to connect to %q: %v", serverURL, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Fatalf("%v", res.Status)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	log.Printf("%s", body)
}
