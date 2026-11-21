package tlsconfig_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionResumption(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			t.Run("client rejects on resume", func(t *testing.T) {
				testResumption(t, version, func(p *resumptionPeers) { p.client.allow.Store(false) })
			})
			t.Run("server rejects on resume", func(t *testing.T) {
				testResumption(t, version, func(p *resumptionPeers) { p.server.allow.Store(false) })
			})
		})
	}
}

type resumptionPeer struct {
	allow     atomic.Bool
	authCalls atomic.Int32
	prevCalls atomic.Int32
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

func (p *resumptionPeer) prevVerifyConnection(tls.ConnectionState) error {
	p.prevCalls.Add(1)
	return nil
}

type resumptionPeers struct {
	client, server resumptionPeer
}

func testResumption(t *testing.T, version uint16, revoke func(*resumptionPeers)) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	bundle := ca.X509Bundle()
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))

	var peers resumptionPeers
	peers.client.allow.Store(true)
	peers.server.allow.Store(true)

	serverConfig := &tls.Config{MinVersion: version, MaxVersion: version, VerifyConnection: peers.server.prevVerifyConnection} //nolint:gosec // version is TLS 1.2 or 1.3
	tlsconfig.HookMTLSServerConfig(serverConfig, serverSVID, bundle, peers.server.authorizer())

	clientConfig := &tls.Config{ //nolint:gosec // version is TLS 1.2 or 1.3
		MinVersion:         version,
		MaxVersion:         version,
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
		VerifyConnection:   peers.client.prevVerifyConnection,
	}
	tlsconfig.HookMTLSClientConfig(clientConfig, clientSVID, bundle, peers.client.authorizer())

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go serveOneByte(ln)

	// Full handshake: authenticated once per side, previous callback chained.
	state, err := dialAndRead(ln.Addr().String(), clientConfig)
	require.NoError(t, err)
	require.False(t, state.DidResume)
	assert.EqualValues(t, 1, peers.client.authCalls.Load())
	assert.EqualValues(t, 1, peers.server.authCalls.Load())
	assert.EqualValues(t, 1, peers.client.prevCalls.Load())
	assert.EqualValues(t, 1, peers.server.prevCalls.Load())

	// Resumed handshake: authenticated again on both sides.
	state, err = dialAndRead(ln.Addr().String(), clientConfig)
	require.NoError(t, err)
	require.True(t, state.DidResume)
	assert.EqualValues(t, 2, peers.client.authCalls.Load())
	assert.EqualValues(t, 2, peers.server.authCalls.Load())
	assert.EqualValues(t, 2, peers.client.prevCalls.Load())
	assert.EqualValues(t, 2, peers.server.prevCalls.Load())

	// Resumed handshake after the authorizer changes its mind must fail.
	revoke(&peers)
	_, err = dialAndRead(ln.Addr().String(), clientConfig)
	require.Error(t, err)
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
