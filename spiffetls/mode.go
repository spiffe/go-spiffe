package spiffetls

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type clientMode int

const (
	tlsClientMode clientMode = iota
	mtlsClientMode
	mtlsWebClientMode
)

type serverMode int

const (
	tlsServerMode serverMode = iota
	mtlsServerMode
	mtlsWebServerMode
)

// DialMode is a SPIFFE TLS dialing mode.
type DialMode interface {
	get() *dialMode
}

type dialMode struct {
	mode clientMode

	// sourceUnneeded is true when a X509Source is not required since
	// raw sources have already been provided, i.e. when the mode comes from
	// a *WithRawConfig method.
	sourceUnneeded bool

	authorizer tlsconfig.Authorizer

	source  *workloadapi.X509Source
	options []workloadapi.X509SourceOption

	bundle x509bundle.Source
	svid   x509svid.Source

	roots *x509.CertPool
}

type listenMode struct {
	mode serverMode

	// sourceUnneeded is true when a X509Source is not required since
	// raw sources have already been provided, i.e. when the mode comes from
	// a *WithRawConfig method.
	sourceUnneeded bool

	authorizer tlsconfig.Authorizer

	source  *workloadapi.X509Source
	options []workloadapi.X509SourceOption

	bundle x509bundle.Source
	svid   x509svid.Source

	cert *tls.Certificate
}

func (l *listenMode) get() *listenMode {
	return l
}

func (d *dialMode) get() *dialMode {
	return d
}

// TLSClient configures the dialing for TLS. The server X509-SVID is
// authenticated using X.509 bundles obtained via the Workload API. The
// authorizer is used to authorize the server X509-SVID.
func TLSClient(authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		mode:       tlsClientMode,
		authorizer: authorizer,
	}
}

// TLSClientWithSource configures the dialing for TLS. The server X509-SVID is
// authenticated using X.509 bundles obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the
// connection. The authorizer is used to authorize the server X509-SVID.
func TLSClientWithSource(authorizer tlsconfig.Authorizer, source *workloadapi.X509Source) DialMode {
	return &dialMode{
		mode:       tlsClientMode,
		authorizer: authorizer,
		source:     source,
	}
}

// TLSClientWithSourceOptions configures the dialing for TLS. The server
// X509-SVID is authenticated using X.509 bundles obtained via a new Workload
// API X.509 source created with the provided source options. The authorizer is
// used to authorize the server X509-SVID.
func TLSClientWithSourceOptions(authorizer tlsconfig.Authorizer, options ...workloadapi.X509SourceOption) DialMode {
	return &dialMode{
		mode:       tlsClientMode,
		authorizer: authorizer,
		options:    options,
	}
}

// TLSClientWithRawConfig configures the dialing for TLS. The server X509-SVID is
// authenticated using X.509 bundles obtained via the provided X.509 bundle
// source. The source must remain valid for the lifetime of the connection. The
// authorizer is used to authorize the server X509-SVID.
func TLSClientWithRawConfig(authorizer tlsconfig.Authorizer, bundle x509bundle.Source) DialMode {
	return &dialMode{
		mode:           tlsClientMode,
		sourceUnneeded: true,
		authorizer:     authorizer,
		bundle:         bundle,
	}
}

// MTLSClient configures the dialing for mutually authenticated TLS (mTLS). The
// client X509-SVID and the X.509 bundles used to authenticate the server
// X509-SVID are obtained via the Workload API. The authorizer is used to
// authorize the server X509-SVID.
func MTLSClient(authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		mode:       mtlsClientMode,
		authorizer: authorizer,
	}
}

// MTLSClientWithSource configures the dialing for mutually authenticated TLS
// (mTLS). The client X509-SVID and the X.509 bundles used to authenticate the
// server X509-SVID are obtained via the provided Workload API X.509 source.
// The source must remain valid for the lifetime of the connection. The
// authorizer is used to authorize the server X509-SVID.
func MTLSClientWithSource(authorizer tlsconfig.Authorizer, source *workloadapi.X509Source) DialMode {
	return &dialMode{
		mode:       mtlsClientMode,
		authorizer: authorizer,
		source:     source,
	}
}

// MTLSClientWithSourceOptions configures the dialing for mutually
// authenticated TLS (mTLS). The client X509-SVID and the X.509 bundles used to
// authenticate the server X509-SVID are obtained via a new Workload API X.509
// source created with the provided source options. The authorizer is used to
// authorize the server X509-SVID.
func MTLSClientWithSourceOptions(authorizer tlsconfig.Authorizer, options ...workloadapi.X509SourceOption) DialMode {
	return &dialMode{
		mode:       mtlsClientMode,
		authorizer: authorizer,
		options:    options,
	}
}

// MTLSClientWithRawConfig configures the dialing for mutually authenticated TLS
// (mTLS). The client X509-SVID and the X.509 bundles used to authenticate the
// server X509-SVID are obtained via the provided X509-SVID and X.509 bundle
// sources. The sources must remain valid for the lifetime of the connection.
// The authorizer is used to authorize the server X509-SVID.
func MTLSClientWithRawConfig(authorizer tlsconfig.Authorizer, svid x509svid.Source, bundle x509bundle.Source) DialMode {
	return &dialMode{
		mode:           mtlsClientMode,
		sourceUnneeded: true,
		authorizer:     authorizer,
		svid:           svid,
		bundle:         bundle,
	}
}

// MTLSWebClient configures the dialing for mutually authenticated TLS (mTLS).
// The client X509-SVID is obtained via the Workload API. The roots (or the
// system roots if nil) are used to authenticate the server certificate.
func MTLSWebClient(roots *x509.CertPool) DialMode {
	return &dialMode{
		mode:  mtlsWebClientMode,
		roots: roots,
	}
}

// MTLSWebClientWithSource configures the dialing for mutually authenticated
// TLS (mTLS). The client X509-SVID is obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the
// connection. The roots (or the system roots if nil) are used to authenticate
// the server certificate.
func MTLSWebClientWithSource(roots *x509.CertPool, source *workloadapi.X509Source) DialMode {
	return &dialMode{
		mode:   mtlsWebClientMode,
		source: source,
		roots:  roots,
	}
}

// MTLSWebClientWithSourceOptions configures the dialing for mutually
// authenticated TLS (mTLS). The client X509-SVID is obtained via a new
// Workload API X.509 source created with the provided source options. The
// roots (or the system roots if nil) are used to authenticate the server
// certificate.
func MTLSWebClientWithSourceOptions(roots *x509.CertPool, options ...workloadapi.X509SourceOption) DialMode {
	return &dialMode{
		mode:    mtlsWebClientMode,
		options: options,
		roots:   roots,
	}
}

// MTLSWebClientWithRawConfig configures the dialing for mutually authenticated
// TLS (mTLS). The client X509-SVID is obtained via the provided X509-SVID
// source. The source must remain valid for the lifetime of the connection. The
// roots (or the system roots if nil) are used to authenticate the server
// certificate.
func MTLSWebClientWithRawConfig(roots *x509.CertPool, svid x509svid.Source) DialMode {
	return &dialMode{
		mode:           mtlsWebClientMode,
		sourceUnneeded: true,
		svid:           svid,
		roots:          roots,
	}
}

// ListenMode is a SPIFFE TLS listening mode.
type ListenMode interface {
	get() *listenMode
}

// TLSServer configures the listener for TLS. The listener presents an
// X509-SVID obtained via the Workload API.
func TLSServer() ListenMode {
	return &listenMode{
		mode: tlsServerMode,
	}
}

// TLSServerWithSource configures the listener for TLS. The listener presents
// an X509-SVID obtained via the provided Workload API X.509 source. The source
// must remain valid for the lifetime of the listener.
func TLSServerWithSource(source *workloadapi.X509Source) ListenMode {
	return &listenMode{
		mode:   tlsServerMode,
		source: source,
	}
}

// TLSServerWithSourceOptions configures the listener for TLS. The listener
// presents an X509-SVID obtained via a new Workload API X.509 source created
// with the provided source options.
func TLSServerWithSourceOptions(options ...workloadapi.X509SourceOption) ListenMode {
	return &listenMode{
		mode:    tlsServerMode,
		options: options,
	}
}

// TLSServerWithRawConfig configures the listener for TLS. The listener presents
// an X509-SVID obtained via the provided X509-SVID source. The source must
// remain valid for the lifetime of the listener.
func TLSServerWithRawConfig(svid x509svid.Source) ListenMode {
	return &listenMode{
		mode:           tlsServerMode,
		sourceUnneeded: true,
		svid:           svid,
	}
}

// MTLSServer configures the listener for mutually authenticated TLS (mTLS).
// The listener presents an X509-SVID and authenticates client X509-SVIDs using
// X.509 bundles, both obtained via the Workload API. The authorizer is used to
// authorize client X509-SVIDs.
func MTLSServer(authorizer tlsconfig.Authorizer) ListenMode {
	return &listenMode{
		mode:       mtlsServerMode,
		authorizer: authorizer,
	}
}

// MTLSServerWithSource configures the listener for mutually authenticated TLS
// (mTLS). The listener presents an X509-SVID and authenticates client
// X509-SVIDs using X.509 bundles, both obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the listener.
// The authorizer is used to authorize client X509-SVIDs.
func MTLSServerWithSource(authorizer tlsconfig.Authorizer, source *workloadapi.X509Source) ListenMode {
	return &listenMode{
		mode:       mtlsServerMode,
		authorizer: authorizer,
		source:     source,
	}
}

// MTLSServerWithSourceOptions configures the listener for mutually
// authenticated TLS (mTLS). The listener presents an X509-SVID and
// authenticates client X509-SVIDs using X.509 bundles, both obtained via a new
// Workload API X.509 source created with the provided source options. The
// authorizer is used to authorize client X509-SVIDs.
func MTLSServerWithSourceOptions(authorizer tlsconfig.Authorizer, options ...workloadapi.X509SourceOption) ListenMode {
	return &listenMode{
		mode:       mtlsServerMode,
		authorizer: authorizer,
		options:    options,
	}
}

// MTLSServerWithRawConfig configures the listener for mutually authenticated TLS
// (mTLS). The listener presents an X509-SVID and authenticates client
// X509-SVIDs using X.509 bundles, both obtained via the provided X509-SVID and
// X.509 bundle sources. The sources must remain valid for the lifetime of the
// listener. The authorizer is used to authorize client X509-SVIDs.
func MTLSServerWithRawConfig(authorizer tlsconfig.Authorizer, svid x509svid.Source, bundle x509bundle.Source) ListenMode {
	return &listenMode{
		mode:           mtlsServerMode,
		sourceUnneeded: true,
		authorizer:     authorizer,
		svid:           svid,
		bundle:         bundle,
	}
}

// MTLSWebServer configures the listener for mutually authenticated TLS (mTLS).
// The listener presents an X.509 certificate and authenticates client
// X509-SVIDs using X.509 bundles obtained via the Workload API. The authorizer
// is used to authorize client X509-SVIDs.
func MTLSWebServer(authorizer tlsconfig.Authorizer, cert *tls.Certificate) ListenMode {
	return &listenMode{
		mode:       mtlsWebServerMode,
		cert:       cert,
		authorizer: authorizer,
	}
}

// MTLSWebServerWithSource configures the listener for mutually authenticated
// TLS (mTLS). The listener presents an X.509 certificate and authenticates
// client X509-SVIDs using X.509 bundles obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the listener.
// The authorizer is used to authorize client X509-SVIDs.
func MTLSWebServerWithSource(authorizer tlsconfig.Authorizer, cert *tls.Certificate, source *workloadapi.X509Source) ListenMode {
	return &listenMode{
		mode:       mtlsWebServerMode,
		cert:       cert,
		source:     source,
		authorizer: authorizer,
	}
}

// MTLSWebServerWithSourceOptions configures the listener for mutually
// authenticated TLS (mTLS). The listener presents an X.509 certificate and
// authenticates client X509-SVIDs using X.509 bundles, both obtained via a new
// Workload API X.509 source created with the provided source options. The
// authorizer is used to authorize client X509-SVIDs.
func MTLSWebServerWithSourceOptions(authorizer tlsconfig.Authorizer, cert *tls.Certificate, options ...workloadapi.X509SourceOption) ListenMode {
	return &listenMode{
		mode:       mtlsWebServerMode,
		cert:       cert,
		options:    options,
		authorizer: authorizer,
	}
}

// MTLSWebServerWithRawConfig configures the listener for mutually authenticated
// TLS (mTLS). The listener presents an X.509 certificate and authenticates
// client X509-SVIDs using X.509 bundles, both obtained via the provided X.509
// bundle source. The source must remain valid for the lifetime of the
// listener. The authorizer is used to authorize client X509-SVIDs.
func MTLSWebServerWithRawConfig(authorizer tlsconfig.Authorizer, cert *tls.Certificate, bundle x509bundle.Source) ListenMode {
	return &listenMode{
		mode:           mtlsWebServerMode,
		sourceUnneeded: true,
		authorizer:     authorizer,
		cert:           cert,
		bundle:         bundle,
	}
}
