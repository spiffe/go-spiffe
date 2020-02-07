package spiffetls

import (
	"crypto/tls"
	"net"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Option is a common option to both dialing and listening.
type Option interface{}

// WithX509Source provides an X.509 source to use to obtain materials from
// the Workload API. If unused, a new source will be created.
func WithX509Source(source ...workloadapi.X509Source) Option {
	panic("not implemented")
}

// WithX509SourceOptions provides options for creating a new X.509 source. This
// option is ignored if WithX509Source is used.
func WithX509SourceOptions(options ...workloadapi.X509SourceOption) Option {
	panic("not implemented")
}

// WithTLSConfigBase provides a base TLS configuration to use. Fields related
// to certificates and verification will be overwritten by this package as
// necessary to facilitate SPIFFE authentication.
func WithTLSConfigBase(base *tls.Config) Option {
	panic("not implemented")
}

// DialOption is an option for dialing. Option's are also DialOption's.
type DialOption interface{}

// WithDialer provides a net dialer to use. If unset, the standard net dialer
// will be used.
func WithDialer(dialer *net.Dialer) DialOption {
	panic("not implemented")
}

// ListenOption is an option for listening. Option's are also ListenOption's.
type ListenOption interface{}
