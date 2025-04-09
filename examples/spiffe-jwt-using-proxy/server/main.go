package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const socketPath = "unix:///tmp/agent.sock"

func index(w http.ResponseWriter, r *http.Request) {
	log.Println("Request received")
	_, _ = io.WriteString(w, "Success!!!")
}

type authenticator struct {
	// JWTSource used to verify the received token
	jwtSource *workloadapi.JWTSource
	// Expected audiences
	audiences []string
}

func (a *authenticator) authenticateClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fields := strings.Fields(req.Header.Get("Authorization"))
		if len(fields) != 2 || fields[0] != "Bearer" {
			log.Print("Malformed header")
			http.Error(w, "Invalid or unsupported authorization header", http.StatusUnauthorized)
			return
		}

		token := fields[1]

		_, err := jwtsvid.ParseAndValidate(token, a.jwtSource, a.audiences)
		if err != nil {
			log.Printf("Invalid token: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	// Create options to configure Sources to use SPIRE Agent's expected socket path.
	// By default, Sources uses the value of the `SPIFFE_ENDPOINT_SOCKET` environment variable,
	// so creating this is not required.
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create an X509Source for the server's TLS configuration.
	x509Source, err := workloadapi.NewX509Source(
		ctx,
		clientOptions,
	)
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer x509Source.Close()

	// Create a JWTSource to validate tokens provided by clients.
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create JWTSource: %w", err)
	}
	defer jwtSource.Close()

	// Add a handler to act as a middleware to validate the JWT-SVID presented by the client.
	auth := &authenticator{
		jwtSource: jwtSource,
		audiences: []string{"spiffe://example.org/server"},
	}
	http.Handle("/", auth.authenticateClient(http.HandlerFunc(index)))

	server := &http.Server{
		Addr:              ":8080",
		TLSConfig:         tlsconfig.TLSServerConfig(x509Source),
		ReadHeaderTimeout: time.Second * 10,
	}
	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}
