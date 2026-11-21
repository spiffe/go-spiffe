package tlsconfig_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionResumption(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	bundle := ca.X509Bundle()
	otherBundle := test.NewCA(t, td).X509Bundle()
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	webRoots, webCert := test.CreateWebCredentials(t)

	type pair func(p *resumptionPeers, server, client *tls.Config)
	mtls := func(p *resumptionPeers, server, client *tls.Config) {
		p.server.authenticates, p.client.authenticates = true, true
		tlsconfig.HookMTLSServerConfig(server, serverSVID, p.server.bundle(bundle, otherBundle), p.server.authorizer())
		tlsconfig.HookMTLSClientConfig(client, clientSVID, p.client.bundle(bundle, otherBundle), p.client.authorizer())
	}
	tlsOnly := func(p *resumptionPeers, server, client *tls.Config) {
		p.client.authenticates = true
		tlsconfig.HookTLSServerConfig(server, serverSVID)
		tlsconfig.HookTLSClientConfig(client, p.client.bundle(bundle, otherBundle), p.client.authorizer())
	}
	mtlsWeb := func(p *resumptionPeers, server, client *tls.Config) {
		p.server.authenticates = true
		tlsconfig.HookMTLSWebServerConfig(server, webCert, p.server.bundle(bundle, otherBundle), p.server.authorizer())
		tlsconfig.HookMTLSWebClientConfig(client, clientSVID, webRoots)
	}
	handBuilt := func(p *resumptionPeers, server, client *tls.Config) {
		p.server.authenticates, p.client.authenticates = true, true
		serverBundle, serverAuthz := p.server.bundle(bundle, otherBundle), p.server.authorizer()
		server.ClientAuth = tls.RequireAnyClientCert
		server.GetCertificate = tlsconfig.GetCertificate(serverSVID)
		server.VerifyConnection = tlsconfig.WrapVerifyConnection(server.VerifyConnection, serverBundle, serverAuthz)

		clientBundle, clientAuthz := p.client.bundle(bundle, otherBundle), p.client.authorizer()
		client.InsecureSkipVerify = true
		client.GetClientCertificate = tlsconfig.GetClientCertificate(clientSVID)
		client.VerifyConnection = tlsconfig.WrapVerifyConnection(client.VerifyConnection, clientBundle, clientAuthz)
	}

	testCases := []struct {
		name   string
		pair   pair
		revoke func(*resumptionPeers) // makes the next resumed handshake fail
		check  func(*testing.T, *resumptionPeers)
	}{
		{
			name:   "mTLS client authorizer rejects",
			pair:   mtls,
			revoke: func(p *resumptionPeers) { p.client.allow.Store(false) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 3, p.client.authCalls.Load()) },
		},
		{
			name:   "mTLS server authorizer rejects",
			pair:   mtls,
			revoke: func(p *resumptionPeers) { p.server.allow.Store(false) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 3, p.server.authCalls.Load()) },
		},
		{
			name:   "mTLS client bundle no longer trusts server",
			pair:   mtls,
			revoke: func(p *resumptionPeers) { p.client.distrust.Store(true) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 2, p.client.authCalls.Load()) },
		},
		{
			name:   "mTLS server bundle no longer trusts client",
			pair:   mtls,
			revoke: func(p *resumptionPeers) { p.server.distrust.Store(true) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 2, p.server.authCalls.Load()) },
		},
		{
			name:   "mTLS chained VerifyConnection fails",
			pair:   mtls,
			revoke: func(p *resumptionPeers) { p.client.failPrev.Store(true) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 3, p.client.prevCalls.Load()) },
		},
		{
			name:   "TLS client authorizer rejects",
			pair:   tlsOnly,
			revoke: func(p *resumptionPeers) { p.client.allow.Store(false) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 3, p.client.authCalls.Load()) },
		},
		{
			name:   "mTLS web server authorizer rejects",
			pair:   mtlsWeb,
			revoke: func(p *resumptionPeers) { p.server.allow.Store(false) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 3, p.server.authCalls.Load()) },
		},
		{
			name:   "hand-built client authorizer rejects",
			pair:   handBuilt,
			revoke: func(p *resumptionPeers) { p.client.allow.Store(false) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 3, p.client.authCalls.Load()) },
		},
		{
			name:   "hand-built server bundle no longer trusts client",
			pair:   handBuilt,
			revoke: func(p *resumptionPeers) { p.server.distrust.Store(true) },
			check:  func(t *testing.T, p *resumptionPeers) { assert.EqualValues(t, 2, p.server.authCalls.Load()) },
		},
	}

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, tc := range testCases {
			t.Run(tls.VersionName(version)+"/"+tc.name, func(t *testing.T) {
				var peers resumptionPeers
				peers.client.allow.Store(true)
				peers.server.allow.Store(true)

				serverConfig := &tls.Config{ //nolint:gosec // version is TLS 1.2 or 1.3
					MinVersion:       version,
					MaxVersion:       version,
					VerifyConnection: peers.server.prevVerifyConnection,
				}
				clientConfig := &tls.Config{ //nolint:gosec // version is TLS 1.2 or 1.3
					MinVersion:         version,
					MaxVersion:         version,
					ClientSessionCache: tls.NewLRUClientSessionCache(1),
					VerifyConnection:   peers.client.prevVerifyConnection,
				}
				tc.pair(&peers, serverConfig, clientConfig)

				ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
				require.NoError(t, err)
				t.Cleanup(func() { ln.Close() })
				go serveOneByte(ln)

				state, err := dialAndRead(ln.Addr().String(), clientConfig)
				require.NoError(t, err)
				require.False(t, state.DidResume)
				peers.assertCalls(t, 1)

				state, err = dialAndRead(ln.Addr().String(), clientConfig)
				require.NoError(t, err)
				require.True(t, state.DidResume)
				peers.assertCalls(t, 2)

				tc.revoke(&peers)
				_, err = dialAndRead(ln.Addr().String(), clientConfig)
				require.Error(t, err)
				tc.check(t, &peers)
			})
		}
	}
}

type resumptionPeer struct {
	allow         atomic.Bool
	distrust      atomic.Bool // bundle source returns a bundle from an unrelated CA
	failPrev      atomic.Bool
	authCalls     atomic.Int32
	prevCalls     atomic.Int32
	authenticates bool
}

func (p *resumptionPeer) authorizer() tlsconfig.Authorizer {
	return func(spiffeid.ID, [][]*x509.Certificate) error {
		p.authCalls.Add(1)
		if !p.allow.Load() {
			return errors.New("not allowed")
		}
		return nil
	}
}

func (p *resumptionPeer) bundle(trusted, untrusted *x509bundle.Bundle) x509bundle.Source {
	return bundleSourceFunc(func(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
		if p.distrust.Load() {
			return untrusted, nil
		}
		return trusted, nil
	})
}

func (p *resumptionPeer) prevVerifyConnection(tls.ConnectionState) error {
	p.prevCalls.Add(1)
	if p.failPrev.Load() {
		return errors.New("previous callback failed")
	}
	return nil
}

type resumptionPeers struct {
	client, server resumptionPeer
}

func (p *resumptionPeers) assertCalls(t *testing.T, n int32) {
	t.Helper()
	for _, peer := range []*resumptionPeer{&p.client, &p.server} {
		assert.Equal(t, n, peer.prevCalls.Load())
		if peer.authenticates {
			assert.Equal(t, n, peer.authCalls.Load())
		}
	}
}

type bundleSourceFunc func(spiffeid.TrustDomain) (*x509bundle.Bundle, error)

func (f bundleSourceFunc) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return f(td)
}

func serveOneByte(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = conn.Write([]byte{1})
		}()
	}
}

// dialAndRead reads a byte so TLS 1.3 session tickets and server-side
// handshake errors reach the client.
func dialAndRead(addr string, config *tls.Config) (tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		return tls.ConnectionState{}, err
	}
	return conn.ConnectionState(), nil
}
