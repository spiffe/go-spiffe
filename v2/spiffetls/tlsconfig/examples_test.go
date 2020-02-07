package tlsconfig_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func ExampleMTLSServerConfig_fileSource() {
	svid, err := x509svid.Load("svid.pem", "key.pem")
	if err != nil {
		// TODO: handle error
	}

	bundle, err := x509bundle.Load("example.org", "cacert.pem")
	if err != nil {
		// TODO: handle error
	}

	config := tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeMemberOf("example.org"))
	// TODO: use the config
	config = config
}

func ExampleMTLSServerConfig_workloadAPISource() {
	source, err := workloadapi.NewX509Source(context.Background())
	if err != nil {
		// TODO: handle error
	}
	defer source.Close()

	config := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf("example.org"))
	// TODO: use the config
	config = config
}
