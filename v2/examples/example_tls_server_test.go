package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/tlsworkload"
)

func Example_tLSListener() {
	listener, err := tlsworkload.ListenTLS(context.TODO(), "tcp", ":8443")
	if err != nil {
		// TODO: handle error
	}
	defer listener.Close()
}
