package spiffetls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
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

	var sourceCloser io.Closer
	if !m.sourceUnneeded {
		source := m.source
		if source == nil {
			source, err = workloadapi.NewX509Source(ctx, m.options...)
			if err != nil {
				return nil, wrapSpiffetlsErr(fmt.Errorf("cannot create X.509 source: %w", err))
			}
			// Close source if there is a failure after this point
			defer func() {
				if err != nil {
					source.Close()
				}
			}()
			sourceCloser = source
		}
		m.bundle = source
		m.svid = source
	}

	opt := &listenConfig{}
	for _, option := range options {
		option.apply(opt)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12} // MinVersion is also set by the Hook methods, but just in case..
	if opt.baseTLSConf != nil {
		tlsConfig = opt.baseTLSConf
	}

	switch m.mode {
	case tlsServerMode:
		tlsconfig.HookTLSServerConfig(tlsConfig, m.svid, opt.tlsOptions...)
	case mtlsServerMode:
		tlsconfig.HookMTLSServerConfig(tlsConfig, m.svid, m.bundle, m.authorizer, opt.tlsOptions...)
	case mtlsWebServerMode:
		tlsconfig.HookMTLSWebServerConfig(tlsConfig, m.cert, m.bundle, m.authorizer)
	default:
		return nil, wrapSpiffetlsErr(fmt.Errorf("unknown server mode: %v", m.mode))
	}

	return &listener{
		inner:        tls.NewListener(inner, tlsConfig),
		sourceCloser: sourceCloser,
	}, nil
}

type listener struct {
	inner        net.Listener
	sourceCloser io.Closer
}

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// This is purely defensive. The TLS listeners return tls.Conn's by contract.
		conn.Close()
		return nil, wrapSpiffetlsErr(fmt.Errorf("unexpected conn type %T returned by TLS listener", conn))
	}
	return &serverConn{Conn: tlsConn}, nil
}

func (l *listener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *listener) Close() error {
	var group []error
	if l.sourceCloser != nil {
		group = append(group, l.sourceCloser.Close())
	}
	if err := l.inner.Close(); err != nil {
		group = append(group, wrapSpiffetlsErr(fmt.Errorf("unable to close TLS connection: %w", err)))
	}
	return errors.Join(group...)
}

type serverConn struct {
	*tls.Conn
}

// PeerID returns the peer SPIFFE ID on the connection. The handshake must have
// been completed. Note that in Go's TLS stack, the TLS 1.3 handshake may not
// complete until the first read from the connection.
func (c *serverConn) PeerID() (spiffeid.ID, error) {
	return PeerIDFromConnectionState(c.ConnectionState())
}
