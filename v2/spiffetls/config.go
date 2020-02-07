package spiffetls

import (
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

type SVIDStore interface {
	GetX509SVID() (*spiffex509.SVID, error)
}

type PeerStore interface {
	SVIDStore
	spiffex509.RootStore
}

// TLSClientConfig returns a client TLS configuration for SPIFFE authenticated TLS
func TLSClientConfig(store spiffex509.RootStore, validator Validator) *tls.Config {
	panic("not implemented")
}

// MTLSClientConfig returns a client TLS configuration for SPIFFE authenticated mTLS
func MTLSClientConfig(store PeerStore, validator Validator) *tls.Config {
	panic("not implemented")
}

// TLSServerConfig returns a server TLS configuration for SPIFFE authenticated TLS
func TLSServerConfig(store SVIDStore) *tls.Config {
	panic("not implemented")
}

// MTLSServerConfig returns a server TLS configuration for SPIFFE authenticated mTLS
func MTLSServerConfig(store PeerStore, validator Validator) *tls.Config {
	panic("not implemented")
}
