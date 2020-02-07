package spiffetls

import (
	"context"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

// DialTLS dials an address and authenticates the server identity
func DialTLS(ctx context.Context, net, addr string, store spiffex509.RootStore, validator Validator) (*tls.Conn, error) {
	panic("not implemented")
}

// DialMTLS dials an address, presents a client identity, and authenticates the server identity
func DialMTLS(ctx context.Context, net, addr string, store PeerStore, validator Validator) (*tls.Conn, error) {
	panic("not implemented")
}
