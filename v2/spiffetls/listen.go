package spiffetls

import (
	"context"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// Listen creates an mTLS listener accepting connections on the given network
// address using net.Listen. The server X509-SVID is obtained via the Workload
// API along with X.509 bundles used to verify client X509-SVIDs. The client is
// authorized using the given authorizer.
//
// This function is the same as Listen using the MTLSServer mode.
func Listen(ctx context.Context, network, laddr string, authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// NewListener creates an mTLS listener which accepts connections from an inner
// Listener and wraps each connection with tls.Server. The server X509-SVID is
// obtained via the Workload API along with X.509 bundles used to verify client
// X509-SVIDs. The client is authorized using the given authorizer.
//
// This function is the same as NewListenerWithMode using the MTLSServer mode.
func NewListener(ctx context.Context, inner net.Listener, authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// ListenWithMode creates a TLS listener accepting connections on the given
// network address using net.Listen. The given mode controls the authentication
// and authorization exercised during the TLS handshake.
func ListenWithMode(ctx context.Context, network, laddr string, mode ListenMode, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}

// NewListenerWithMode creates a TLS listener which accepts connections from an
// inner Listener and wraps each connection with tls.Server. The given mode
// controls the authentication and authorization exercised during the TLS
// handshake.
func NewListenerWithMode(ctx context.Context, inner net.Listener, mode ListenMode, options ...ListenOption) (net.Listener, error) {
	panic("not implemented")
}
