package spiffe

import (
	"context"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/grpc_testing"
)

func TestTLSPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	log := spiffetest.NewLogger(t)

	domain1CA := spiffetest.NewCA(t)
	serverSVID, serverKey := domain1CA.CreateX509SVID("spiffe://domain1.test/server")

	domain2CA := spiffetest.NewCA(t)
	clientSVID, clientKey := domain2CA.CreateX509SVID("spiffe://domain2.test/client")

	serverWorkloadAPI := spiffetest.NewWorkloadAPI(t, &spiffetest.X509SVIDResponse{
		Bundle: domain1CA.Roots(),
		SVIDs: []spiffetest.X509SVID{
			{
				CertChain: serverSVID,
				Key:       serverKey,
			},
		},
		FederatedBundles: map[string][]*x509.Certificate{
			"spiffe://domain2.test": domain2CA.Roots(),
		},
	})
	defer serverWorkloadAPI.Stop()

	serverPeer, err := NewTLSPeer(WithLogger(log), WithWorkloadAPIAddr(serverWorkloadAPI.Addr()))
	require.NoError(t, err)
	defer serverPeer.Close()

	clientWorkloadAPI := spiffetest.NewWorkloadAPI(t, &spiffetest.X509SVIDResponse{
		Bundle: domain2CA.Roots(),
		SVIDs: []spiffetest.X509SVID{
			{
				CertChain: clientSVID,
				Key:       clientKey,
			},
		},
		FederatedBundles: map[string][]*x509.Certificate{
			"spiffe://domain1.test": domain1CA.Roots(),
		},
	})
	defer clientWorkloadAPI.Stop()

	clientPeer, err := NewTLSPeer(WithLogger(log), WithWorkloadAPIAddr(clientWorkloadAPI.Addr()))
	require.NoError(t, err)
	defer clientPeer.Close()

	listener, err := serverPeer.Listen(ctx, "tcp", "localhost:0", ExpectPeer("spiffe://domain2.test/client"))
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		require.NoError(t, err)
		io.Copy(conn, conn)
		conn.Close()
	}()

	conn, err := clientPeer.Dial(ctx, listener.Addr().Network(), listener.Addr().String(), ExpectPeer("spiffe://domain1.test/server"))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("HELLO"))
	require.NoError(t, err)

	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "HELLO", string(buf[:n]))
}

func TestTLSPeerGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	log := spiffetest.NewLogger(t)

	domain1CA := spiffetest.NewCA(t)
	serverSVID, serverKey := domain1CA.CreateX509SVID("spiffe://domain1.test/server")

	domain2CA := spiffetest.NewCA(t)
	clientSVID, clientKey := domain2CA.CreateX509SVID("spiffe://domain2.test/client")

	serverWorkloadAPI := spiffetest.NewWorkloadAPI(t, &spiffetest.X509SVIDResponse{
		Bundle: domain1CA.Roots(),
		SVIDs: []spiffetest.X509SVID{
			{
				CertChain: serverSVID,
				Key:       serverKey,
			},
		},
		FederatedBundles: map[string][]*x509.Certificate{
			"spiffe://domain2.test": domain2CA.Roots(),
		},
	})
	defer serverWorkloadAPI.Stop()

	serverPeer, err := NewTLSPeer(WithLogger(log), WithWorkloadAPIAddr(serverWorkloadAPI.Addr()))
	require.NoError(t, err)
	defer serverPeer.Close()

	clientWorkloadAPI := spiffetest.NewWorkloadAPI(t, &spiffetest.X509SVIDResponse{
		Bundle: domain2CA.Roots(),
		SVIDs: []spiffetest.X509SVID{
			{
				CertChain: clientSVID,
				Key:       clientKey,
			},
		},
		FederatedBundles: map[string][]*x509.Certificate{
			"spiffe://domain1.test": domain1CA.Roots(),
		},
	})
	defer clientWorkloadAPI.Stop()

	clientPeer, err := NewTLSPeer(WithLogger(log), WithWorkloadAPIAddr(clientWorkloadAPI.Addr()))
	require.NoError(t, err)
	defer clientPeer.Close()

	listener, err := serverPeer.Listen(ctx, "tcp", "localhost:0", ExpectPeer("spiffe://domain2.test/client"))
	require.NoError(t, err)
	defer listener.Close()

	server := grpc.NewServer()
	grpc_testing.RegisterTestServiceServer(server, testService{})
	go server.Serve(listener)

	conn, err := clientPeer.DialGRPC(ctx, listener.Addr().String(), ExpectPeer("spiffe://domain1.test/server"))
	require.NoError(t, err)
	defer conn.Close()

	client := grpc_testing.NewTestServiceClient(conn)
	_, err = client.EmptyCall(ctx, &grpc_testing.Empty{})
	require.NoError(t, err)
}

type testService struct {
	grpc_testing.TestServiceServer
}

func (testService) EmptyCall(ctx context.Context, req *grpc_testing.Empty) (*grpc_testing.Empty, error) {
	return &grpc_testing.Empty{}, nil
}
