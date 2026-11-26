package brokerapi

import (
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

// ClientOption is an option used when creating a new Client.
//
// Experimental: subject to change.
type ClientOption interface {
	configureClient(*clientConfig)
}

// WithAddr provides the address of the Broker API. The address must be an
// RFC 3986 URI with a "unix", "tcp", or "dns" scheme, e.g.
// "unix:///run/spire/broker.sock", "tcp://broker.example.org:8443", or
// "dns:///broker.example.org:8443". A bare host:port address, e.g.
// "broker.example.org:8443", is treated as a DNS target.
//
// The value of the SPIFFE_BROKER_SOCKET environment variable will be used if
// the option is unused.
//
// Experimental: subject to change.
func WithAddr(addr string) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.address = addr
	})
}

// MTLSSource is a source of X509-SVIDs and X.509 bundles used to build the
// mTLS credentials for a Client.
//
// Experimental: subject to change.
type MTLSSource interface {
	x509svid.Source
	x509bundle.Source
}

// WithMTLSSource provides the source used to build the mTLS credentials for
// the Client. If unset, a new Workload API X.509 source is created with
// workloadapi.NewX509Source. The source is not closed by the Client.
//
// Experimental: subject to change.
func WithMTLSSource(source MTLSSource) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.mtlsSource = source
	})
}

// WithWorkloadAPISourceOptions provides options for the Workload API X.509
// source created when no source is provided with WithMTLSSource. These options
// are ignored if WithMTLSSource is used.
//
// Experimental: subject to change.
func WithWorkloadAPISourceOptions(options ...workloadapi.X509SourceOption) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.workloadAPISourceOptions = append(c.workloadAPISourceOptions, options...)
	})
}

// WithDialOptions provides extra gRPC dial options when connecting to the
// Broker API.
//
// Experimental: subject to change.
func WithDialOptions(options ...grpc.DialOption) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.dialOptions = append(c.dialOptions, options...)
	})
}

// WithLogger provides a logger to the Client.
//
// Experimental: subject to change.
func WithLogger(log logger.Logger) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.log = log
	})
}

// WithBackoffStrategy provides a custom backoff strategy that replaces the
// default backoff strategy (linear backoff) used when re-establishing streams.
//
// Experimental: subject to change.
func WithBackoffStrategy(backoffStrategy workloadapi.BackoffStrategy) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.backoffStrategy = backoffStrategy
	})
}

// X509SourceOption is an option for the X509Source.
//
// Experimental: subject to change.
type X509SourceOption interface {
	configureX509Source(*x509SourceConfig)
}

// WithDefaultX509SVIDPicker provides a function that is used to determine the
// default X509-SVID when more than one is provided by the Broker API. By
// default, the first X509-SVID in the list returned by the Broker API is used.
//
// Experimental: subject to change.
func WithDefaultX509SVIDPicker(picker func([]*x509svid.SVID) *x509svid.SVID) X509SourceOption {
	return withDefaultX509SVIDPicker{picker: picker}
}

// JWTSourceOption is an option for the JWTSource.
//
// Experimental: subject to change.
type JWTSourceOption interface {
	configureJWTSource(*jwtSourceConfig)
}

// WithDefaultJWTSVIDPicker provides a function that is used to determine the
// default JWT-SVID when more than one is provided by the Broker API. By
// default, the first JWT-SVID in the list returned by the Broker API is used.
//
// Experimental: subject to change.
func WithDefaultJWTSVIDPicker(picker func([]*jwtsvid.SVID) *jwtsvid.SVID) JWTSourceOption {
	return withDefaultJWTSVIDPicker{picker: picker}
}

type clientConfig struct {
	address                  string
	mtlsSource               MTLSSource
	workloadAPISourceOptions []workloadapi.X509SourceOption
	dialOptions              []grpc.DialOption
	log                      logger.Logger
	backoffStrategy          workloadapi.BackoffStrategy
}

type clientOption func(*clientConfig)

func (fn clientOption) configureClient(config *clientConfig) {
	fn(config)
}

type x509SourceConfig struct {
	picker func([]*x509svid.SVID) *x509svid.SVID
}

type jwtSourceConfig struct {
	picker func([]*jwtsvid.SVID) *jwtsvid.SVID
}

type withDefaultX509SVIDPicker struct {
	picker func([]*x509svid.SVID) *x509svid.SVID
}

func (o withDefaultX509SVIDPicker) configureX509Source(config *x509SourceConfig) {
	config.picker = o.picker
}

type withDefaultJWTSVIDPicker struct {
	picker func([]*jwtsvid.SVID) *jwtsvid.SVID
}

func (o withDefaultJWTSVIDPicker) configureJWTSource(config *jwtSourceConfig) {
	config.picker = o.picker
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		log:             logger.Null,
		backoffStrategy: defaultBackoffStrategy{},
	}
}
