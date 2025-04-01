package spiffetls

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// DialOption is an option for dialing. Option's are also DialOption's.
type DialOption interface {
	apply(*dialConfig)
}

type dialOption func(*dialConfig)

func (fn dialOption) apply(c *dialConfig) {
	fn(c)
}

type dialConfig struct {
	baseTLSConf *tls.Config
	dialer      *net.Dialer
	tlsOptions  []tlsconfig.Option
}

type listenOption func(*listenConfig)

type listenConfig struct {
	baseTLSConf *tls.Config
	tlsOptions  []tlsconfig.Option
}

func (fn listenOption) apply(c *listenConfig) {
	fn(c)
}

// WithDialTLSConfigBase provides a base TLS configuration to use. Fields
// related to certificates and verification will be overwritten by this package
// as necessary to facilitate SPIFFE authentication.
func WithDialTLSConfigBase(base *tls.Config) DialOption {
	return dialOption(func(c *dialConfig) {
		c.baseTLSConf = base
	})
}

// WithDialTLSOptions provides options to use for the TLS config.
func WithDialTLSOptions(opts ...tlsconfig.Option) DialOption {
	return dialOption(func(c *dialConfig) {
		c.tlsOptions = opts
	})
}

// WithDialer provides a net dialer to use. If unset, the standard net dialer
// will be used.
func WithDialer(dialer *net.Dialer) DialOption {
	return dialOption(func(c *dialConfig) {
		c.dialer = dialer
	})
}

// ListenOption is an option for listening. Option's are also ListenOption's.
type ListenOption interface {
	apply(*listenConfig)
}

// WithListenTLSConfigBase provides a base TLS configuration to use. Fields
// related to certificates and verification will be overwritten by this package
// as necessary to facilitate SPIFFE authentication.
func WithListenTLSConfigBase(base *tls.Config) ListenOption {
	return listenOption(func(c *listenConfig) {
		c.baseTLSConf = base
	})
}

// WithListenTLSOptions provides options to use when doing Server mTLS.
func WithListenTLSOptions(opts ...tlsconfig.Option) ListenOption {
	return listenOption(func(c *listenConfig) {
		c.tlsOptions = opts
	})
}

func wrapSpiffetlsErr(err error) error {
	return fmt.Errorf("spiffetls: %w", err)
}
