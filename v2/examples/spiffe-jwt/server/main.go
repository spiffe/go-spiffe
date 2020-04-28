package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"

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
	// JWT Source used to verify token
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

		// Parse and validate token against fetched bundle from jwtSource,
		// an alternative is using `workloadapi.ValidateJWTSVID` that will
		// attest against SPIRE on each call and validate token
		svid, err := jwtsvid.ParseAndValidate(token, a.jwtSource, a.audiences)
		if err != nil {
			log.Printf("Invalid token: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		req = req.WithContext(context.WithValue(req.Context(), "claims", svid.Claims)) //nolint:lint // setting to be string
		next.ServeHTTP(w, req)
	})
}

func main() {
	ctx := context.Background()

	// Create options to configure Sources to use expected socket path,
	// as default sources will use value environment variable `SPIFFE_ENDPOINT_SOCKET`
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// Create a X509Source using previously create workloadapi client
	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer x509Source.Close()

	// Create a `tls.Config` with configuration to allow TLS communication with client
	tlsConfig := tlsconfig.TLSServerConfig(x509Source)
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Create a JWTSource to validate provided tokens from clients
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create JWTSource: %v", err)
	}
	defer jwtSource.Close()

	// Add a middleware to validate presented JWT token
	auth := &authenticator{
		jwtSource: jwtSource,
		audiences: []string{"spiffe://example.org/server"},
	}
	http.Handle("/", auth.authenticateClient(http.HandlerFunc(index)))

	log.Fatal(server.ListenAndServeTLS("", ""))
}
