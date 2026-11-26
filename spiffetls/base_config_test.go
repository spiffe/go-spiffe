package spiffetls_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestTLSConfigBaseReuse(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	bundle := ca.X509Bundle()
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	base := &tls.Config{MinVersion: tls.VersionTLS12}

	roundTrip := func(listenMode spiffetls.ListenMode, dialMode spiffetls.DialMode) {
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		ln, err := spiffetls.NewListenerWithMode(context.Background(), inner, listenMode, spiffetls.WithListenTLSConfigBase(base))
		require.NoError(t, err)
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				_, _ = conn.Write([]byte{1})
				conn.Close()
			}
		}()

		conn, err := spiffetls.DialWithMode(context.Background(), "tcp", ln.Addr().String(), dialMode, spiffetls.WithDialTLSConfigBase(base))
		require.NoError(t, err)
		defer conn.Close()
		_, err = io.ReadFull(conn, make([]byte, 1))
		require.NoError(t, err)
	}

	roundTrip(spiffetls.MTLSServerWithRawConfig(tlsconfig.AuthorizeAny(), svid, bundle),
		spiffetls.MTLSClientWithRawConfig(tlsconfig.AuthorizeAny(), svid, bundle))
	roundTrip(spiffetls.TLSServerWithRawConfig(svid),
		spiffetls.TLSClientWithRawConfig(tlsconfig.AuthorizeAny(), bundle))

	require.Equal(t, &tls.Config{MinVersion: tls.VersionTLS12}, base)
}
