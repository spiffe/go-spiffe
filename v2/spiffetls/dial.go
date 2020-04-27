package spiffetls

import (
	"context"
	"crypto/tls"
	"io"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zeebo/errs"
)

// Dial creates an mTLS connection using an X509-SVID obtained from the
// Workload API. The server is authenticated using X.509 bundles also obtained
// from the Workload API. The server is authorized using the given authorizer.
//
// This is the same as DialWithMode using the MTLSClient mode.
func Dial(ctx context.Context, network, addr string, authorizer tlsconfig.Authorizer, options ...DialOption) (net.Conn, error) {
	return DialWithMode(ctx, network, addr, MTLSClient(authorizer), options...)
}

// DialWithMode creates a TLS connection using the specified mode.
func DialWithMode(ctx context.Context, network, addr string, mode DialMode, options ...DialOption) (_ net.Conn, err error) {
	m := mode.get()

	var sourceCloser io.Closer
	if !m.sourceUnneeded {
		source := m.source
		if source == nil {
			source, err = workloadapi.NewX509Source(ctx, m.options...)
			if err != nil {
				return nil, spiffetlsErr.New("cannot create X.509 source: %w", err)
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

	opt := &dialConfig{}
	for _, option := range options {
		option.apply(opt)
	}

	tlsConfig := &tls.Config{}
	if opt.baseTLSConf != nil {
		tlsConfig = opt.baseTLSConf
	}

	switch m.mode {
	case tlsClientMode:
		tlsconfig.HookTLSClientConfig(tlsConfig, m.bundle, m.authorizer)
	case mtlsClientMode:
		tlsconfig.HookMTLSClientConfig(tlsConfig, m.svid, m.bundle, m.authorizer)
	case mtlsWebClientMode:
		tlsconfig.HookMTLSWebClientConfig(tlsConfig, m.svid, m.roots)
	default:
		return nil, spiffetlsErr.New("unknown client mode: %v", m.mode)
	}

	var conn *tls.Conn
	if opt.dialer != nil {
		conn, err = tls.DialWithDialer(opt.dialer, network, addr, tlsConfig)
	} else {
		conn, err = tls.Dial(network, addr, tlsConfig)
	}
	if err != nil {
		return nil, spiffetlsErr.New("unable to dial: %w", err)
	}

	return &clientConn{
		Conn:         conn,
		sourceCloser: sourceCloser,
	}, nil
}

type clientConn struct {
	*tls.Conn
	sourceCloser io.Closer
}

func (c *clientConn) Close() error {
	var group errs.Group
	if c.sourceCloser != nil {
		group.Add(c.sourceCloser.Close())
	}
	if err := c.Conn.Close(); err != nil {
		group.Add(spiffetlsErr.New("unable to close TLS connection: %w", err))
	}
	return group.Err()
}

// PeerID returns the peer SPIFFE ID on the connection. The handshake must have
// been completed. Note that in Go's TLS stack, the TLS 1.3 handshake may not
// complete until the first read from the connection.
func (c *clientConn) PeerID() (spiffeid.ID, error) {
	return peerIDFromConnectionState(c.Conn.ConnectionState())
}
