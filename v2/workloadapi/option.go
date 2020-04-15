package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
)

type clientOption struct {
	address     string
	dialOptions []grpc.DialOption
	log         logger.Logger
}

// ClientOption is an option used when creating a new Client.
type ClientOption interface {
	apply(*clientOption)
}

type funcClientOption func(*clientOption)

func (fn funcClientOption) apply(do *clientOption) {
	fn(do)
}

// WithAddr provides an address for the Workload API. The value of the
// SPIFFE_ENDPOINT_SOCKET environment variable will be used if the option
// is unused.
func WithAddr(addr string) ClientOption {
	return funcClientOption(func(c *clientOption) {
		c.address = addr
	})
}

// WithDialOptions provides extra GRPC dialing options when dialing the
// Workload API.
func WithDialOptions(options ...grpc.DialOption) ClientOption {
	return funcClientOption(func(c *clientOption) {
		c.dialOptions = append(c.dialOptions, options...)
	})
}

// WithLogger provides a logger to the Client.
func WithLogger(logger logger.Logger) ClientOption {
	return funcClientOption(func(c *clientOption) {
		c.log = logger
	})
}

// SourceOption are options that are shared among all option types.
type SourceOption interface {
	x509SourceOption()
	jwtSourceOption()
	bundleSourceOption()
}

// WithClient provides a Client for the source to use. If unset, a new Client
// will be created.
func WithClient(client *Client) SourceOption {
	panic("not implemented")
}

// WithClientOptions controls the options used to create a new Client for the
// source. This option will be ignored if WithClient is used.
func WithClientOptions(options ...ClientOption) SourceOption {
	panic("not implemented")
}

// X509SourceOption is an option for the X509Source. A SourceOption is also an
// X509SourceOption.
type X509SourceOption interface {
	x509SourceOption()
}

// WithDefaultX509SVIDPicker provides a function that is used to determine the
// default X509-SVID when more than one is provided by the Workload API. By
// default, the first X509-SVID in the list returned by the Workload API is
// used.
func WithDefaultX509SVIDPicker(picker func([]*x509svid.SVID) *x509svid.SVID) X509SourceOption {
	panic("not implemented")
}

// JWTSourceOption is an option for the JWTSource. A SourceOption is also a
// JWTSourceOption.
type JWTSourceOption interface {
	jwtSourceOption()
}

// BundleSourceOption is an option for the BundleSource. A SourceOption is also
// a BundleSourceOption.
type BundleSourceOption interface {
	bundleSourceOption()
}
