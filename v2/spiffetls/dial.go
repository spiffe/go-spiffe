package spiffetls

import (
	"context"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// Conn is a (m)TLS connection backed using materials obtained from the
// Workload API.
type Conn struct {
	*tls.Conn
}

// Close closes the connection. If the connection has been established using a
// new X.509 source (the default behavior), that source will also be closed.
func (c *Conn) Close() error {
	panic("not implemented")
}

// DialTLS creates a TLS connection. The server is authenticated using X.509
// bundles also obtained from the Workload API and authorized using the
// given authorizer.
func DialTLS(ctx context.Context, network, addr string, authorizer tlsconfig.Authorizer, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}

// DialMTLS creates an mTLS connection using an X509-SVID obtained from the
// Workload API. The server is authenticated using X.509 bundles also obtained
// from the Workload API. The server is authorized using the given authorizer.
func DialMTLS(ctx context.Context, network, addr string, authorizer tlsconfig.Authorizer, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}

// DialWebMTLS creates an mTLS connection to a server using an X509-SVID
// obtained from the Workload API. The server is authenticated using the system
// roots.
func DialWebMTLS(ctx context.Context, network, addr string, options ...DialOption) (*Conn, error) {
	panic("not implemented")
}
