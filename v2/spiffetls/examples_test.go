package spiffetls_test

import (
	"context"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

func ExampleListenMTLS() {
	listener, err := spiffetls.ListenMTLS(context.TODO(), "tcp", ":8443")
	if err != nil {
		// TODO: error handling
	}
	defer listener.Close()
}

func ExampleListenMTLS_customTLSConfigBase() {
	baseConfig := &tls.Config{
		// TODO: set up custom configuration. Note that the spiffetls package
		// will override certificate and verification related fields.
	}

	listener, err := spiffetls.ListenMTLS(context.TODO(), "tcp", ":8443", spiffetls.WithTLSConfigBase(baseConfig))
	if err != nil {
		// TODO: error handling
	}
	defer listener.Close()
}
