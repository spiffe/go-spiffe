package workloadapi_test

import (
	"context"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func ExampleFetchX509SVID() {
	svid, err := workloadapi.FetchX509SVID(context.TODO())
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the X509-SVID
	svid = svid
}

func ExampleFetchJWTSVID() {
	serverID, err := spiffeid.FromString("spiffe://example.org/server")
	if err != nil {
		// TODO: error handling
	}

	svid, err := workloadapi.FetchJWTSVID(context.TODO(), jwtsvid.Params{
		Audience: serverID.String(),
	})
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the JWT-SVID
	svid = svid
}

func ExampleValidateJWTSVID() {
	serverID, err := spiffeid.FromString("spiffe://example.org/server")
	if err != nil {
		// TODO: error handling
	}

	token := "TODO"
	svid, err := workloadapi.ValidateJWTSVID(context.TODO(), token, serverID.String())
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the JWT-SVID
	svid = svid
}

func ExampleNewJWTSource_parseAndValidate() {
	td, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: error handling
	}

	token := "TODO"
	audience := []string{spiffeid.RequireFromPath(td, "/server").String()}

	jwtSource, err := workloadapi.NewJWTSource(context.TODO())
	if err != nil {
		// TODO: error handling
	}
	defer jwtSource.Close()

	svid, err := jwtsvid.ParseAndValidate(token, jwtSource, audience)
	if err != nil {
		// TODO: error handling
	}

	// TODO: do something with the JWT-SVID
	svid = svid
}

func ExampleNewX509Source_mTLSServerConfig() {
	td, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: error handling
	}

	source, err := workloadapi.NewX509Source(context.Background())
	if err != nil {
		// TODO: handle error
	}
	defer source.Close()

	config := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(td))
	// TODO: use the config
	config = config
}

func ExampleNewBundleSource_federationHandler() {
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: handle error
	}

	bundleSource, err := workloadapi.NewBundleSource(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer bundleSource.Close()

	handler, err := federation.NewHandler(trustDomain, bundleSource)
	if err != nil {
		// TODO: handle error
	}

	server := http.Server{
		Addr:              ":8443",
		Handler:           handler,
		ReadHeaderTimeout: time.Second * 10, // TODO: set this appropriately
	}
	if err := server.ListenAndServeTLS("", ""); err != nil {
		// TODO: handle error
	}
}

func ExampleNewX509Source_federationHandlerSPIFFEAuth() {
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: handle error
	}

	// Create an X.509 source for obtaining the server X509-SVID
	x509Source, err := workloadapi.NewX509Source(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer x509Source.Close()

	// Create a bundle source for obtaining the bundle for the trust domain
	bundleSource, err := workloadapi.NewBundleSource(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	defer bundleSource.Close()

	handler, err := federation.NewHandler(trustDomain, bundleSource)
	if err != nil {
		// TODO: handle error
	}

	server := http.Server{
		Addr:              ":8443",
		Handler:           handler,
		ReadHeaderTimeout: time.Second * 10, // TODO: set this appropriately
		TLSConfig:         tlsconfig.TLSServerConfig(x509Source),
	}
	if err := server.ListenAndServeTLS("", ""); err != nil {
		// TODO: handle error
	}
}
