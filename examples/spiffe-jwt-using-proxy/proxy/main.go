package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const socketPath = "unix:///tmp/agent.sock"

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	remote, err := url.Parse("https://localhost:8080")
	if err != nil {
		return fmt.Errorf("unable to parse server URL: %w", err)
	}

	// Set a timeout to prevent the request from hanging if this workload is not properly registered in SPIRE.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create an X509Source struct to fetch a SPIFFE X.509-SVID automatically from the
	// Workload API, and use it to establish the TLS connection by presenting it
	// to the client.
	x509Source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
	)
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %w", err)
	}
	defer x509Source.Close()

	// Create a ReverseProxy using a TLSClient config that can connect only
	// to a server that presents an X.509-SVID having "spiffe://example.org/server"
	// as its SPIFFE ID.
	proxy := httputil.NewSingleHostReverseProxy(remote)
	transport := *(http.DefaultTransport.(*http.Transport)) //nolint
	transport.TLSClientConfig = tlsconfig.TLSClientConfig(
		x509Source, tlsconfig.AuthorizeID(spiffeid.RequireFromString("spiffe://example.org/server")),
	)
	proxy.Transport = &transport

	http.HandleFunc("/", handler(proxy))

	// Create an HTTP server using a TLS configuration that doesn't require
	// client certificates, because the proxy is not in charge of authenticating
	// the clients.
	server := &http.Server{
		Addr:              ":8443",
		TLSConfig:         tlsconfig.TLSServerConfig(x509Source),
		ReadHeaderTimeout: time.Second * 10,
	}
	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		p.ServeHTTP(w, r)
	}
}
