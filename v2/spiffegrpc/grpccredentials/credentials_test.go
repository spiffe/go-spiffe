package grpccredentials_test

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestCredentials(t *testing.T) {
	webRoots, webCert := test.CreateWebCredentials(t)

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	bundle := ca.Bundle()
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	serverID := serverSVID.ID.String()
	clientID := clientSVID.ID.String()

	serverMTLS := grpccredentials.MTLSServerCredentials(serverSVID, bundle, tlsconfig.AuthorizeAny())
	clientMTLS := grpccredentials.MTLSClientCredentials(clientSVID, bundle, tlsconfig.AuthorizeAny())
	serverTLS := grpccredentials.TLSServerCredentials(serverSVID)
	clientTLS := grpccredentials.TLSClientCredentials(bundle, tlsconfig.AuthorizeAny())
	serverWeb := grpccredentials.MTLSWebServerCredentials(webCert, bundle, tlsconfig.AuthorizeAny())
	clientWeb := grpccredentials.MTLSWebClientCredentials(clientSVID, webRoots)

	t.Run("mTLS to mTLS", func(t *testing.T) {
		// Handshake will succeed.
		testCredentials(t, clientMTLS, serverMTLS, expectResult{
			Code:     codes.OK,
			ServerID: serverID,
			ClientID: clientID,
		})
	})

	t.Run("TLS to mTLS", func(t *testing.T) {
		// Handshake will fail since server requires client SVID
		testCredentials(t, clientTLS, serverMTLS, expectResult{
			Code: codes.Unavailable,
		})
	})

	t.Run("Web to mTLS", func(t *testing.T) {
		// Handshake will fail because client is doing hostname validation
		// against a server SVID
		testCredentials(t, clientWeb, serverMTLS, expectResult{
			Code:            codes.Unavailable,
			MessageContains: `cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs`,
		})
	})

	t.Run("mTLS to TLS", func(t *testing.T) {
		// Handshake will succeed, but the server won't pick up (or validate)
		// the client SVID.
		testCredentials(t, clientMTLS, serverTLS, expectResult{
			Code:     codes.OK,
			ServerID: serverID,
			ClientID: "",
		})
	})

	t.Run("TLS to TLS", func(t *testing.T) {
		// Handshake will succeed, but the server won't pick up (or validate)
		// the client SVID.
		testCredentials(t, clientTLS, serverTLS, expectResult{
			Code:     codes.OK,
			ServerID: serverID,
			ClientID: "",
		})
	})

	t.Run("Web to TLS", func(t *testing.T) {
		// Handshake will fail because client is doing hostname validation
		// against a server SVID
		testCredentials(t, clientWeb, serverTLS, expectResult{
			Code:            codes.Unavailable,
			MessageContains: `cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs`,
		})
	})

	t.Run("mTLS to Web", func(t *testing.T) {
		// Handshake will fail because client expects server SVID
		testCredentials(t, clientMTLS, serverWeb, expectResult{
			Code:            codes.Unavailable,
			MessageContains: `certificate contains no URI SAN`,
		})
	})

	t.Run("TLS to Web", func(t *testing.T) {
		// Handshake will fail because client expects server SVID
		testCredentials(t, clientTLS, serverWeb, expectResult{
			Code:            codes.Unavailable,
			MessageContains: `could not get leaf SPIFFE ID: certificate contains no URI SAN`,
		})
	})

	t.Run("Web to Web", func(t *testing.T) {
		// Handshake will succeed, but the server won't pick up (or validate)
		// the client SVID.
		testCredentials(t, clientWeb, serverWeb, expectResult{
			Code:     codes.OK,
			ServerID: "", // No server SVID for web server
			ClientID: clientID,
		})
	})
}

type expectResult struct {
	Code            codes.Code
	MessageContains string
	ClientID        string
	ServerID        string
}

func testCredentials(t *testing.T, clientCreds, serverCreds credentials.TransportCredentials, expect expectResult) {
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	server := grpc.NewServer(grpc.Creds(serverCreds))
	defer server.Stop()

	helloworld.RegisterGreeterServer(server, greeterServer{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.Serve(listener)
	}()

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	defer conn.Close()

	clientPeer := new(peer.Peer)
	var clientID string
	resp, err := helloworld.NewGreeterClient(conn).SayHello(ctx, &helloworld.HelloRequest{}, grpc.Peer(clientPeer))
	if err == nil {
		clientID = resp.Message
	}

	st := status.Convert(err)
	serverID, serverIDOK := grpccredentials.PeerIDFromPeer(clientPeer)

	assert.Equal(t, expect.ServerID != "", serverIDOK)

	assert.Equal(t, expect.Code, st.Code())
	assert.Contains(t, st.Message(), expect.MessageContains)
	assert.Equal(t, expect.ClientID, clientID)
	assert.Equal(t, expect.ServerID, serverID.String())
}

type greeterServer struct {
	helloworld.UnimplementedGreeterServer
}

func (s greeterServer) SayHello(ctx context.Context, in *helloworld.HelloRequest) (*helloworld.HelloReply, error) {
	peerID, _ := grpccredentials.PeerIDFromContext(ctx)
	return &helloworld.HelloReply{Message: peerID.String()}, nil
}
