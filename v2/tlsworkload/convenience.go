package tlsworkload

import (
	"context"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
)

// ListenTLS creates a TLS listener accepting connections on the given network
// address using net.Listen. It uses TLS configuration provided by the Workload
// API.
func ListenTLS(ctx context.Context, network, addr string, options ...Option) (net.Listener, error) {
	panic("not implemented")
}

// ListenMTLS creates an mTLS listener accepting connections on the given
// network address using net.Listen. It uses mTLS configuration provided by the
// Workload API. The peer is validatd using the Validator callback.
func ListenMTLS(ctx context.Context, network, addr string, validator spiffetls.Validator, options ...Option) (net.Listener, error) {
	panic("not implemented")
}

// Dial connects to the given network address using net.Dial and then
// initiates a TLS handshake using configuration provided by the Workload API.
// The peer is validated using the Validator callback.
func Dial(ctx context.Context, network, addr string, validator spiffetls.Validator, options ...Option) (net.Conn, error) {
	panic("not implemented")
}
