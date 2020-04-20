package spiffetls

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type authMode int

const (
	typeTLSClient authMode = iota
	typeMTLSClient
	typeMTLSWebClient
)

// DialMode is a SPIFFE TLS dialing mode.
type DialMode interface {
	get() *dialMode
}

type dialMode struct {
	tlsType    authMode
	authorizer tlsconfig.Authorizer

	source  *workloadapi.X509Source
	options []workloadapi.X509SourceOption

	bundle x509bundle.Source
	svid   x509svid.Source

	roots *x509.CertPool
}

func (d *dialMode) get() *dialMode {
	return d
}

// TLSClient configures the dialing for TLS. The server X509-SVID is
// authenticated using X.509 bundles obtained via the Workload API. The
// authorizer is used to authorize the server X509-SVID.
func TLSClient(authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeTLSClient,
		authorizer: authorizer,
	}
}

// TLSClientWithSource configures the dialing for TLS. The server X509-SVID is
// authenticated using X.509 bundles obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the
// connection. The authorizer is used to authorize the server X509-SVID.
func TLSClientWithSource(source *workloadapi.X509Source, authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeTLSClient,
		authorizer: authorizer,
		source:     source,
	}
}

// TLSClientWithSourceOptions configures the dialing for TLS. The server
// X509-SVID is authenticated using X.509 bundles obtained via a new Workload
// API X.509 source created with the provided source options. The authorizer is
// used to authorize the server X509-SVID.
func TLSClientWithSourceOptions(options []workloadapi.X509SourceOption, authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeTLSClient,
		authorizer: authorizer,
		options:    options,
	}
}

// TLSClientWithConfig configures the dialing for TLS. The server X509-SVID is
// authenticated using X.509 bundles obtained via the provided X.509 bundle
// source. The source must remain valid for the lifetime of the connection. The
// authorizer is used to authorize the server X509-SVID.
func TLSClientWithConfig(bundle x509bundle.Source, authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeTLSClient,
		authorizer: authorizer,
		bundle:     bundle,
	}
}

// MTLSClient configures the dialing for mutually authenticated TLS (mTLS). The
// client X509-SVID and the X.509 bundles used to authenticate the server
// X509-SVID are obtained via the Workload API. The authorizer is used to
// authorize the server X509-SVID.
func MTLSClient(authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeMTLSClient,
		authorizer: authorizer,
	}
}

// MTLSClientWithSource configures the dialing for mutally authenticated TLS
// (mTLS). The client X509-SVID and the X.509 bundles used to authenticate the
// server X509-SVID are obtained via the provided Workload API X.509 source.
// The source must remain valid for the lifetime of the connection. The
// authorizer is used to authorize the server X509-SVID.
func MTLSClientWithSource(source *workloadapi.X509Source, authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeMTLSClient,
		authorizer: authorizer,
		source:     source,
	}
}

// MTLSClientWithSourceOptions configures the dialing for mutually
// authenticated TLS (mTLS). The client X509-SVID and the X.509 bundles used to
// authenticate the server X509-SVID are obtained via a new Workload API X.509
// source created with the provided source options. The authorizer is used to
// authorize the server X509-SVID.
func MTLSClientWithSourceOptions(options []workloadapi.X509SourceOption, authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeMTLSClient,
		authorizer: authorizer,
		options:    options,
	}
}

// MTLSClientWithConfig configures the dialing for mutually authenticated TLS
// (mTLS). The client X509-SVID and the X.509 bundles used to authenticate the
// server X509-SVID are obtained via the provided X509-SVID and X.509 bundle
// sources. The sources must remain valid for the lifetime of the connection.
// The authorizer is used to authorize the server X509-SVID.
func MTLSClientWithConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer tlsconfig.Authorizer) DialMode {
	return &dialMode{
		tlsType:    typeMTLSClient,
		authorizer: authorizer,
		svid:       svid,
		bundle:     bundle,
	}
}

// MTLSWebClient configures the dialing for mutually authenticated TLS (mTLS).
// The client X509-SVID is obtained via the Workload API. The roots (or the
// system roots if nil) are used to authenticate the server certificate.
func MTLSWebClient(roots *x509.CertPool) DialMode {
	return &dialMode{
		tlsType: typeMTLSWebClient,
		roots:   roots,
	}
}

// MTLSWebClientWithSource configures the dialing for mutually authenticated
// TLS (mTLS). The client X509-SVID is obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the
// connection. The roots (or the system roots if nil) are used to authenticate
// the server certificate.
func MTLSWebClientWithSource(source *workloadapi.X509Source, roots *x509.CertPool) DialMode {
	return &dialMode{
		tlsType: typeMTLSWebClient,
		source:  source,
		roots:   roots,
	}
}

// MTLSWebClientWithSourceOptions configures the dialing for mutually
// authenticated TLS (mTLS). The client X509-SVID is obtained via a new
// Workload API X.509 source created with the provided source options. The
// roots (or the system roots if nil) are used to authenticate the server
// certificate.
func MTLSWebClientWithSourceOptions(options []workloadapi.X509SourceOption, roots *x509.CertPool) DialMode {
	return &dialMode{
		tlsType: typeMTLSWebClient,
		options: options,
		roots:   roots,
	}
}

// MTLSWebClientWithConfig configures the dialing for mutually authenticated
// TLS (mTLS). The client X509-SVID is obtained via the provided X509-SVID
// source. The source must remain valid for the lifetime of the connection. The
// roots (or the system roots if nil) are used to authenticate the server
// certificate.
func MTLSWebClientWithConfig(svid x509svid.Source, roots *x509.CertPool) DialMode {
	return &dialMode{
		tlsType: typeMTLSWebClient,
		svid:    svid,
		roots:   roots,
	}
}

// ListenMode is a SPIFFE TLS listening mode.
type ListenMode interface {
}

// TLSServer configures the listener for TLS. The listener presents an
// X509-SVID obtained via the Workload API.
func TLSServer() ListenMode {
	panic("not implemented")
}

// TLSServerWithSource configures the listener for TLS. The listener presents
// an X509-SVID obtained via the provided Workload API X.509 source. The source
// must remain valid for the lifetime of the listener.
func TLSServerWithSource(source *workloadapi.X509Source) ListenMode {
	panic("not implemented")
}

// TLSServerWithSourceOptions configures the listener for TLS. The listener
// presents an X509-SVID obtained via a new Workload API X.509 source created
// with the provided source options.
func TLSServerWithSourceOptions(options []workloadapi.X509SourceOption) ListenMode {
	panic("not implemented")
}

// TLSServerWithConfig configures the listener for TLS. The listener presents
// an X509-SVID obtained via the provided X509-SVID source. The source must
// remain valid for the lifetime of the listener.
func TLSServerWithConfig(svid x509svid.Source) ListenMode {
	panic("not implemented")
}

// MTLSServer configures the listener for mutually authenticated TLS (mTLS).
// The listener presents an X509-SVID and authenticates client X509-SVIDs using
// X.509 bundles, both obtained via the Workload API. The authorizer is used to
// authorize client X509-SVIDs.
func MTLSServer(authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSServerWithSource configures the listener for mutually authenticated TLS
// (mTLS). The listener presents an X509-SVID and authenticates client
// X509-SVIDs using X.509 bundles, both obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the listener.
// The authorizer is used to authorize client X509-SVIDs.
func MTLSServerWithSource(source *workloadapi.X509Source, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSServerWithSourceOptions configures the listener for mutually
// authenticated TLS (mTLS). The listener presents an X509-SVID and
// authenticates client X509-SVIDs using X.509 bundles, both obtained via a new
// Workload API X.509 source created with the provided source options. The
// authorizer is used to authorize client X509-SVIDs.
func MTLSServerWithSourceOptions(options []workloadapi.X509SourceOption, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSServerWithConfig configures the listener for mutually authenticated TLS
// (mTLS). The listener presents an X509-SVID and authenticates client
// X509-SVIDs using X.509 bundles, both obtained via the provided X509-SVID and
// X.509 bundle sources. The sources must remain valid for the lifetime of the
// listener. The authorizer is used to authorize client X509-SVIDs.
func MTLSServerWithConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSWebServer configures the listener for mutually authenticated TLS (mTLS).
// The listener presents an X.509 certificate and authenticates client
// X509-SVIDs using X.509 bundles obtained via the Workload API. The authorizer
// is used to authorize client X509-SVIDs.
func MTLSWebServer(cert *tls.Certificate, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSWebServerWithSource configures the listener for mutually authenticated
// TLS (mTLS). The listener presents an X.509 certificate and authenticates
// client X509-SVIDs using X.509 bundles obtained via the provided Workload API
// X.509 source. The source must remain valid for the lifetime of the listener.
// The authorizer is used to authorize client X509-SVIDs.
func MTLSWebServerWithSource(cert *tls.Certificate, source *workloadapi.X509Source, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSWebServerWithSourceOptions configures the listener for mutually
// authenticated TLS (mTLS). The listener presents an X.509 certificate and
// authenticates client X509-SVIDs using X.509 bundles, both obtained via a new
// Workload API X.509 source created with the provided source options. The
// authorizer is used to authorize client X509-SVIDs.
func MTLSWebServerWithSourceOptions(cert *tls.Certificate, options []workloadapi.X509SourceOption, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}

// MTLSWebServerWithConfig configures the listener for mutually authenticated
// TLS (mTLS). The listener presents an X.509 certificate and authenticates
// client X509-SVIDs using X.509 bundles, both obtained via the provided X.509
// bundle source. The source must remain valid for the lifetime of the
// listener. The authorizer is used to authorize client X509-SVIDs.
func MTLSWebServerWithConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer tlsconfig.Authorizer) ListenMode {
	panic("not implemented")
}
