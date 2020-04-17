package spiffetls

import (
	"crypto/tls"
	"net"

	"github.com/zeebo/errs"
)

var spiffetlsErr = errs.Class("spiffetls")

// DialOption is an option for dialing. Option's are also DialOption's.
type DialOption interface {
	apply(*dialOption)
}

type dialOption struct {
	baseTLSConf *tls.Config
	dialer      *net.Dialer
}

func (o *dialOption) apply(other *dialOption) {
	if other.baseTLSConf == nil {
		other.baseTLSConf = o.baseTLSConf
	}
	if other.dialer == nil {
		other.dialer = o.dialer
	}
}

// WithDialTLSConfigBase provides a base TLS configuration to use. Fields
// related to certificates and verification will be overwritten by this package
// as necessary to facilitate SPIFFE authentication.
func WithDialTLSConfigBase(base *tls.Config) DialOption {
	return &dialOption{baseTLSConf: base}
}

// WithDialer provides a net dialer to use. If unset, the standard net dialer
// will be used.
func WithDialer(dialer *net.Dialer) DialOption {
	return &dialOption{dialer: dialer}
}

// ListenOption is an option for listening. Option's are also ListenOption's.
type ListenOption interface{}

// WithDialTLSConfigBase provides a base TLS configuration to use. Fields
// related to certificates and verification will be overwritten by this package
// as necessary to facilitate SPIFFE authentication.
func WithListenTLSConfigBase(base *tls.Config) ListenOption {
	panic("not implemented")
}
