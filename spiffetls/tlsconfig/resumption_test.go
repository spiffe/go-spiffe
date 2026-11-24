package tlsconfig_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
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
		name     string
		pair     pair
		revoke   func(*resumptionPeers)               // makes the next handshake fail
		counter  func(*resumptionPeers) *atomic.Int32 // compared across the failing handshake
		increase bool
	}{
		{
			name:     "mTLS client authorizer rejects",
			pair:     mtls,
			revoke:   func(p *resumptionPeers) { p.client.allow.Store(false) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.client.authCalls },
			increase: true,
		},
		{
			name:     "mTLS server authorizer rejects",
			pair:     mtls,
			revoke:   func(p *resumptionPeers) { p.server.allow.Store(false) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.server.authCalls },
			increase: true,
		},
		{
			name:     "mTLS client bundle no longer trusts server",
			pair:     mtls,
			revoke:   func(p *resumptionPeers) { p.client.distrust.Store(true) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.client.authCalls },
			increase: false,
		},
		{
			name:     "mTLS server bundle no longer trusts client",
			pair:     mtls,
			revoke:   func(p *resumptionPeers) { p.server.distrust.Store(true) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.server.authCalls },
			increase: false,
		},
		{
			name:     "mTLS chained VerifyConnection fails",
			pair:     mtls,
			revoke:   func(p *resumptionPeers) { p.client.failPrev.Store(true) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.client.prevCalls },
			increase: true,
		},
		{
			name:     "TLS client authorizer rejects",
			pair:     tlsOnly,
			revoke:   func(p *resumptionPeers) { p.client.allow.Store(false) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.client.authCalls },
			increase: true,
		},
		{
			name:     "mTLS web server authorizer rejects",
			pair:     mtlsWeb,
			revoke:   func(p *resumptionPeers) { p.server.allow.Store(false) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.server.authCalls },
			increase: true,
		},
		{
			name:     "hand-built client authorizer rejects",
			pair:     handBuilt,
			revoke:   func(p *resumptionPeers) { p.client.allow.Store(false) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.client.authCalls },
			increase: true,
		},
		{
			name:     "hand-built server bundle no longer trusts client",
			pair:     handBuilt,
			revoke:   func(p *resumptionPeers) { p.server.distrust.Store(true) },
			counter:  func(p *resumptionPeers) *atomic.Int32 { return &p.server.authCalls },
			increase: false,
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
				peers.assertCalls(t, 0)

				state, err = dialAndRead(ln.Addr().String(), clientConfig)
				require.NoError(t, err)
				require.True(t, state.DidResume)
				peers.assertCalls(t, 1)

				before := tc.counter(&peers).Load()
				tc.revoke(&peers)
				_, err = dialAndRead(ln.Addr().String(), clientConfig)
				require.Error(t, err)
				if tc.increase {
					assert.Greater(t, tc.counter(&peers).Load(), before)
				} else {
					assert.Equal(t, before, tc.counter(&peers).Load())
				}
			})
		}
	}
}

func TestHookRunsVerifyPeerCertificateAfterAuthorizer(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	bundle := ca.X509Bundle()

	var authorized atomic.Bool
	var calls atomic.Int32
	authorizer := func(spiffeid.ID, [][]*x509.Certificate) error {
		authorized.Store(true)
		return nil
	}
	clientConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}
	clientConfig.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error { //nolint:gosec // the hook below sets VerifyConnection
		calls.Add(1)
		if !authorized.Load() || len(raw) == 0 || len(chains) == 0 {
			return errors.New("called before authorization or without chains")
		}
		return nil
	}
	tlsconfig.HookMTLSClientConfig(clientConfig, ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client")), bundle, authorizer)
	addr := listen(t, tlsconfig.MTLSServerConfig(ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server")), bundle, tlsconfig.AuthorizeAny()))

	for range 2 {
		authorized.Store(false)
		_, err := dialAndRead(addr, clientConfig)
		require.NoError(t, err)
	}
	// Go does not call VerifyPeerCertificate on resumed sessions.
	require.Equal(t, int32(1), calls.Load())
}

func TestSessionResumptionAfterCARotation(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, serverRotates := range []bool{true, false} {
			name := tls.VersionName(version) + "/client rotates"
			if serverRotates {
				name = tls.VersionName(version) + "/server rotates"
			}
			t.Run(name, func(t *testing.T) {
				oldCA, newCA := test.NewCA(t, td), test.NewCA(t, td)
				both := x509bundle.FromX509Authorities(td, append(oldCA.X509Bundle().X509Authorities(), newCA.X509Bundle().X509Authorities()...))
				var serverTrust, clientTrust atomic.Pointer[x509bundle.Bundle]
				serverTrust.Store(both)
				clientTrust.Store(both)
				var serverSVID, clientSVID svidSource
				serverSVID.Store(oldCA.CreateX509SVID(serverID))
				clientSVID.Store(oldCA.CreateX509SVID(clientID))

				serverConfig := tlsconfig.MTLSServerConfig(&serverSVID, trustSource(&serverTrust), tlsconfig.AuthorizeAny())
				serverConfig.MinVersion, serverConfig.MaxVersion = version, version
				clientConfig := tlsconfig.MTLSClientConfig(&clientSVID, trustSource(&clientTrust), tlsconfig.AuthorizeAny())
				clientConfig.MinVersion, clientConfig.MaxVersion = version, version
				clientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
				addr := listen(t, serverConfig)

				_, err := dialAndRead(addr, clientConfig)
				require.NoError(t, err)

				// One side stops trusting the old CA. Its peer already holds a
				// new SVID, but the cached session still carries the old one.
				if serverRotates {
					serverTrust.Store(newCA.X509Bundle())
					clientSVID.Store(newCA.CreateX509SVID(clientID))
				} else {
					clientTrust.Store(newCA.X509Bundle())
					serverSVID.Store(newCA.CreateX509SVID(serverID))
					// Go clients drop a ticket whose resumption they rejected,
					// so only the first reconnect fails.
					_, err = dialAndRead(addr, clientConfig)
					require.Error(t, err)
				}

				state, err := dialAndRead(addr, clientConfig)
				require.NoError(t, err)
				require.False(t, state.DidResume)
			})
		}
	}
}

func TestSessionResumptionChainsTicketCallbacks(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")
	userExtra := []byte("user")

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			oldCA, newCA := test.NewCA(t, td), test.NewCA(t, td)
			both := x509bundle.FromX509Authorities(td, append(oldCA.X509Bundle().X509Authorities(), newCA.X509Bundle().X509Authorities()...))
			var serverTrust, clientTrust atomic.Pointer[x509bundle.Bundle]
			serverTrust.Store(both)
			clientTrust.Store(both)
			var clientSVID svidSource
			clientSVID.Store(oldCA.CreateX509SVID(clientID))

			var sawUserExtra, failUnwrap atomic.Bool
			serverConfig := &tls.Config{ //nolint:gosec // version is TLS 1.2 or 1.3
				MinVersion: version,
				MaxVersion: version,
			}
			serverConfig.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
				ss.Extra = append(ss.Extra, userExtra)
				return serverConfig.EncryptTicket(cs, ss)
			}
			serverConfig.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
				if failUnwrap.Load() {
					return nil, errors.New("unwrap failed")
				}
				ss, err := serverConfig.DecryptTicket(identity, cs)
				if ss != nil {
					sawUserExtra.Store(slices.ContainsFunc(ss.Extra, func(e []byte) bool { return bytes.Equal(e, userExtra) }))
				}
				return ss, err
			}
			tlsconfig.HookMTLSServerConfig(serverConfig, newCA.CreateX509SVID(serverID), trustSource(&serverTrust), tlsconfig.AuthorizeAny())

			clientConfig := tlsconfig.MTLSClientConfig(&clientSVID, trustSource(&clientTrust), tlsconfig.AuthorizeAny())
			clientConfig.MinVersion, clientConfig.MaxVersion = version, version
			clientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			addr := listen(t, serverConfig)

			_, err := dialAndRead(addr, clientConfig)
			require.NoError(t, err)
			state, err := dialAndRead(addr, clientConfig)
			require.NoError(t, err)
			require.True(t, state.DidResume)
			require.True(t, sawUserExtra.Load())

			serverTrust.Store(newCA.X509Bundle())
			clientSVID.Store(newCA.CreateX509SVID(clientID))
			state, err = dialAndRead(addr, clientConfig)
			require.NoError(t, err)
			require.False(t, state.DidResume)

			failUnwrap.Store(true)
			_, err = dialAndRead(addr, clientConfig)
			require.Error(t, err)
		})
	}
}

func TestSessionResumptionPeerCertificateExpires(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	bundle := ca.X509Bundle()
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, serverExpires := range []bool{true, false} {
			name := tls.VersionName(version) + "/client certificate expires"
			if serverExpires {
				name = tls.VersionName(version) + "/server certificate expires"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				notAfter := time.Now().Add(3 * time.Second)
				expiring := test.WithLifetime(time.Now().Add(-time.Minute), notAfter)
				serverSVID, clientSVID := ca.CreateX509SVID(serverID), ca.CreateX509SVID(clientID)
				if serverExpires {
					serverSVID = ca.CreateX509SVID(serverID, expiring)
				} else {
					clientSVID = ca.CreateX509SVID(clientID, expiring)
				}

				serverConfig := tlsconfig.MTLSServerConfig(serverSVID, bundle, tlsconfig.AuthorizeAny())
				serverConfig.MinVersion, serverConfig.MaxVersion = version, version
				clientConfig := tlsconfig.MTLSClientConfig(clientSVID, bundle, tlsconfig.AuthorizeAny())
				clientConfig.MinVersion, clientConfig.MaxVersion = version, version
				clientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
				addr := listen(t, serverConfig)

				_, err := dialAndRead(addr, clientConfig)
				require.NoError(t, err)
				state, err := dialAndRead(addr, clientConfig)
				require.NoError(t, err)
				require.True(t, state.DidResume)

				time.Sleep(time.Until(notAfter) + 1500*time.Millisecond)
				_, err = dialAndRead(addr, clientConfig)
				if serverExpires {
					require.ErrorContains(t, err, "certificate has expired")
				} else {
					require.ErrorContains(t, err, "bad certificate")
				}
			})
		}
	}
}

type svidSource struct {
	atomic.Pointer[x509svid.SVID]
}

func (s *svidSource) GetX509SVID() (*x509svid.SVID, error) {
	return s.Load(), nil
}

func trustSource(trust *atomic.Pointer[x509bundle.Bundle]) x509bundle.Source {
	return bundleSourceFunc(func(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
		return trust.Load(), nil
	})
}

func listen(t *testing.T, config *tls.Config) string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go serveOneByte(ln)
	return ln.Addr().String()
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

func (p *resumptionPeer) prevVerifyConnection(cs tls.ConnectionState) error {
	p.prevCalls.Add(1)
	if p.authenticates && len(cs.VerifiedChains) == 0 {
		return errors.New("no verified chains")
	}
	if p.failPrev.Load() {
		return errors.New("previous callback failed")
	}
	return nil
}

type resumptionPeers struct {
	client, server resumptionPeer
}

// assertCalls checks callback counts after one full handshake and the given
// number of resumed ones.
func (p *resumptionPeers) assertCalls(t *testing.T, resumed int32) {
	t.Helper()
	for _, peer := range []*resumptionPeer{&p.client, &p.server} {
		assert.Equal(t, 1+resumed, peer.prevCalls.Load())
		if peer.authenticates {
			assert.Equal(t, 1+resumed, peer.authCalls.Load())
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
