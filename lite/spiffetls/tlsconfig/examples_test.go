package tlsconfig_test

import (
	"github.com/spiffe/go-spiffe/lite/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/lite/spiffeid"
	"github.com/spiffe/go-spiffe/lite/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/lite/svid/x509svid"
)

func ExampleMTLSServerConfig_fileSource() {
	td, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: error handling
	}

	svid, err := x509svid.Load("svid.pem", "key.pem")
	if err != nil {
		// TODO: handle error
	}

	bundle, err := x509bundle.Load(td, "cacert.pem")
	if err != nil {
		// TODO: handle error
	}

	config := tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeMemberOf(td))
	// TODO: use the config
	config = config
}
