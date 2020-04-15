package spiffetls

import (
	"crypto/tls"
	"net"
)

// DialOption is an option for dialing. Option's are also DialOption's.
type DialOption interface{}

// WithDialTLSConfigBase provides a base TLS configuration to use. Fields
// related to certificates and verification will be overwritten by this package
// as necessary to facilitate SPIFFE authentication.
func WithDialTLSConfigBase(base *tls.Config) DialOption {
	panic("not implemented")
}

// WithDialer provides a net dialer to use. If unset, the standard net dialer
// will be used.
func WithDialer(dialer *net.Dialer) DialOption {
	panic("not implemented")
}

// ListenOption is an option for listening. Option's are also ListenOption's.
type ListenOption interface{}

// WithDialTLSConfigBase provides a base TLS configuration to use. Fields
// related to certificates and verification will be overwritten by this package
// as necessary to facilitate SPIFFE authentication.
func WithListenTLSConfigBase(base *tls.Config) ListenOption {
	panic("not implemented")
}
