package spiffetls_test

import (
	"context"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func ExampleListen_mTLS() {
	td := spiffeid.RequireTrustDomainFromString("example.org")

	listener, err := spiffetls.Listen(context.TODO(), "tcp", ":8443", tlsconfig.AuthorizeMemberOf(td))
	if err != nil {
		// TODO: error handling
	}
	defer listener.Close()
}

func ExampleListen_mTLSCustomTLSConfigBase() {
	td := spiffeid.RequireTrustDomainFromString("example.org")

	baseConfig := &tls.Config{
		// TODO: set up custom configuration. Note that the spiffetls package
		// will override certificate and verification related fields.
		MinVersion: tls.VersionTLS12,
	}

	listener, err := spiffetls.Listen(context.TODO(), "tcp", ":8443", tlsconfig.AuthorizeMemberOf(td), spiffetls.WithListenTLSConfigBase(baseConfig))
	if err != nil {
		// TODO: error handling
	}
	defer listener.Close()
}
