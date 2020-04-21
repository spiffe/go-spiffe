package spiffetls

import (
	"context"
	"crypto/tls"
	"io"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Conn is a (m)TLS connection backed using materials obtained from the
// Workload API.
type Conn struct {
	*tls.Conn
	source io.Closer
}

// Close closes the connection. If the connection has been established using a
// new X.509 source (the default behavior), that source will also be closed.
func (c *Conn) Close() error {
	if c.source != nil {
		c.source.Close()
	}
	if c.Conn == nil {
		return nil
	}
	if err := c.Conn.Close(); err != nil {
		return spiffetlsErr.New("unable to close TLS connection: %w", err)
	}
	return nil
}

// Dial creates an mTLS connection using an X509-SVID obtained from the
// Workload API. The server is authenticated using X.509 bundles also obtained
// from the Workload API. The server is authorized using the given authorizer.
//
// This is the same as DialWithMode using the MTLSClient mode.
func Dial(ctx context.Context, network, addr string, authorizer tlsconfig.Authorizer, options ...DialOption) (*Conn, error) {
	return DialWithMode(ctx, network, addr, MTLSClient(authorizer), options...)
}

// DialWithMode creates a TLS connection using the specified mode.
func DialWithMode(ctx context.Context, network, addr string, mode DialMode, options ...DialOption) (_ *Conn, err error) {
	m := mode.get()
	source := m.source
	if source == nil {
		source, err = workloadapi.NewX509Source(ctx, m.options...)
		// Close source if there is a failure after this point
		defer func() {
			if err != nil {
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

	opt := &dialConfig{}
	for _, option := range options {
		option.apply(opt)
	}

	tlsConfig := &tls.Config{}
	if opt.baseTLSConf != nil {
		tlsConfig = opt.baseTLSConf
	}

	switch m.tlsType {
	case typeTLSClient:
		tlsconfig.HookTLSClientConfig(tlsConfig, m.bundle, m.authorizer)
	case typeMTLSClient:
		tlsconfig.HookMTLSClientConfig(tlsConfig, m.svid, m.bundle, m.authorizer)
	case typeMTLSWebClient:
		tlsconfig.HookMTLSWebClientConfig(tlsConfig, m.svid, m.roots)
	default:
		return nil, spiffetlsErr.New("unknown TLS auth mode: %v", m.tlsType)
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

	// Do not store source if provided by caller
	if m.source != nil {
		source = nil
	}

	return &Conn{
		Conn:   conn,
		source: source,
	}, nil
}
