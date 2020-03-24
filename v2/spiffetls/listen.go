package spiffetls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// ListenTLS creates a TLS listener accepting connections on the given network
// address using net.Listen. The server X509-SVID is obtained via the Workload
// API.
func ListenTLS(ctx context.Context, network, laddr string, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// NewTLSListener creates a TLS listener which accepts connections from an
// inner Listener and wraps each connection with tls.Server. The server
// X509-SVID is obtained via the Workload API.
func NewTLSListener(ctx context.Context, inner net.Listener, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// ListenMTLS creates an mTLS listener accepting connections on the given network
// address using net.Listen. The server X509-SVID is obtained via the Workload
// API along with X.509 bundles used to verify client X509-SVIDs. The client
// is authorized using the given authorizer.
func ListenMTLS(ctx context.Context, network, laddr string, authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// NewMTLSListener creates an mTLS listener which accepts connections from an
// inner Listener and wraps each connection with tls.Server. The server
// X509-SVID is obtained via the Workload API along with X.509 bundles used to
// verify client X509-SVIDs. The client is authorized using the given
// authorizer.
func NewMTLSListener(ctx context.Context, inner net.Listener, authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// ListenWebMTLS creates an mTLS listener accepting connections on the given
// network address using net.Listen. The certificate callback is used to
// obtain the server certificate. Client certificates are authenticated using
// X.509 bundles obtained via the Workload API. The client is authorized using
// the given authorizer.
func ListenWebMTLS(ctx context.Context, network, laddr string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// NewWebMTLSListener creates an mTLS listener which accepts connections from
// an inner Listener and wraps each connection with tls.Server. The certificate
// callback to obtain the server certificate. Client certificates are
// authenticated using X.509 bundles obtained via the Workload API. The client
// is authorized using the given authorizer.
func NewWebMTLSListener(ctx context.Context, inner net.Listener, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}
