package spiffetls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Listen creates an mTLS listener accepting connections on the given network
// address using net.Listen. The server X509-SVID is obtained via the Workload
// API along with X.509 bundles used to verify client X509-SVIDs. The client is
// authorized using the given authorizer.
//
// This function is the same as ListenWithMode using the MTLSServer mode.
func Listen(ctx context.Context, network, laddr string, authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	return ListenWithMode(ctx, network, laddr, MTLSServer(authorizer), options...)
}

// NewListener creates an mTLS listener which accepts connections from an inner
// Listener and wraps each connection with tls.Server. The server X509-SVID is
// obtained via the Workload API along with X.509 bundles used to verify client
// X509-SVIDs. The client is authorized using the given authorizer.
//
// This function is the same as NewListenerWithMode using the MTLSServer mode.
func NewListener(ctx context.Context, inner net.Listener, authorizer tlsconfig.Authorizer, options ...ListenOption) (net.Listener, error) {
	return NewListenerWithMode(ctx, inner, MTLSServer(authorizer), options...)
}

// ListenWithMode creates a TLS listener accepting connections on the given
// network address using net.Listen. The given mode controls the authentication
// and authorization exercised during the TLS handshake.
func ListenWithMode(ctx context.Context, network, laddr string, mode ListenMode, options ...ListenOption) (net.Listener, error) {
	inner, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	l, err := NewListenerWithMode(ctx, inner, mode, options...)
	if err != nil {
		inner.Close()
		return nil, err
	}

	return l, nil
}

// NewListenerWithMode creates a TLS listener which accepts connections from an
// inner Listener and wraps each connection with tls.Server. The given mode
// controls the authentication and authorization exercised during the TLS
// handshake.
func NewListenerWithMode(ctx context.Context, inner net.Listener, mode ListenMode, options ...ListenOption) (_ net.Listener, err error) {
	m := mode.get()
	source := m.source
	if source == nil {
		source, err = workloadapi.NewX509Source(ctx, m.options...)
		// Close source if there is a failure after this point
		defer func() {
			if err != nil && source != nil {
				source.Close()
			}
		}()
		if err != nil {
			return nil, spiffetlsErr.New("cannot create X.509 source: %w", err)
		}
	}

	if m.bundle == nil {
		m.bundle = source
	}
	if m.svid == nil {
		m.svid = source
	}

	opt := &listenConfig{}
	for _, option := range options {
		option.apply(opt)
	}

	tlsConfig := &tls.Config{}
	if opt.baseTLSConf != nil {
		tlsConfig = opt.baseTLSConf
	}

	switch m.tlsType {
	case typeTLSServer:
		tlsconfig.HookTLSServerConfig(tlsConfig, m.svid)
	case typeMTLSServer:
		tlsconfig.HookMTLSServerConfig(tlsConfig, m.svid, m.bundle, m.authorizer)
	case typeMTLSWebServer:
		tlsconfig.HookMTLSWebServerConfig(tlsConfig, m.cert, m.bundle, m.authorizer)
	default:
		return nil, spiffetlsErr.New("unknown TLS hook type: %v", m.tlsType)
	}

	return tls.NewListener(inner, tlsConfig), nil
}
