package spiffetls_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

const (
	defaultListenProtocol = "tcp"
	defaultListenLAddr    = "localhost:0"
)

var (
	td       = spiffeid.RequireTrustDomainFromString("example.org")
	clientID = spiffeid.RequireFromString("spiffe://example.org/client-workload")
	serverID = spiffeid.RequireFromString("spiffe://example.org/server-workload")
	testMsg  = "Hello!\n"
)

func TestListenAndDial(t *testing.T) {
	// Common CA for client and server SVIDs
	ca := test.NewCA(t, td)

	// Start two fake workload API servers called "A" and "B"
	// Workload API Server A provides identities to the server workload
	wlAPIServerA := fakeworkloadapi.New(t)
	defer wlAPIServerA.Stop()
	setWorkloadAPIResponse(ca, wlAPIServerA, serverID)

	// Workload API Server B provides identities to the client workload
	wlAPIServerB := fakeworkloadapi.New(t)
	defer wlAPIServerB.Stop()
	setWorkloadAPIResponse(ca, wlAPIServerB, clientID)

	// Create custom workload API sources for the server
	wlCtx, wlCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer wlCancel()
	wlAPIClientA, err := workloadapi.New(wlCtx, workloadapi.WithAddr(wlAPIServerA.Addr()))
	require.NoError(t, err)
	wlAPISourceA, err := workloadapi.NewX509Source(wlCtx, workloadapi.WithClient(wlAPIClientA))
	require.NoError(t, err)

	// Create custom workload API sources for the client
	wlAPIClientB, err := workloadapi.New(wlCtx, workloadapi.WithAddr(wlAPIServerB.Addr()))
	require.NoError(t, err)
	wlAPISourceB, err := workloadapi.NewX509Source(wlCtx, workloadapi.WithClient(wlAPIClientB))
	require.NoError(t, err)

	// Create custom SVID and bundle source (not backed by workload API)
	bundleSource := ca.X509Bundle()
	svidSource := ca.CreateX509SVID(clientID)

	// Create web credentials
	webCertPool, webCert := test.CreateWebCredentials(t)

	// Flag used to detect if an external dialer was actually used
	externalDialerUsed := false

	// Buffer used to detect if a base TLS config was actually used
	externalTLSConfBuffer := &bytes.Buffer{}

	// Test Table
	tests := []struct {
		name string

		dialMode   spiffetls.DialMode
		dialOption []spiffetls.DialOption

		listenMode   spiffetls.ListenMode
		listenOption []spiffetls.ListenOption

		defaultWlAPIAddr    string
		dialErr             string
		listenErr           string
		listenLAddr         string
		listenProtocol      string
		serverConnPeerIDErr string
		clientConnPeerIDErr string
		usesExternalDialer  bool
		usesBaseTLSConfig   bool
	}{
		// Failure Scenarios
		{
			name:             "Wrong workload API server socket",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			defaultWlAPIAddr: "wrong-socket-path",
			dialErr:          "spiffetls: cannot create X.509 source: workload endpoint socket URI must have a tcp:// or unix:// scheme",
			listenErr:        "spiffetls: cannot create X.509 source: workload endpoint socket URI must have a tcp:// or unix:// scheme",
		},
		{
			name:             "No server listening",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
			dialErr:          "spiffetls: unable to dial: dial tcp: missing address",
		},
		{
			name:           "Invalid server protocol",
			listenProtocol: "invalid",
			listenMode:     spiffetls.TLSServerWithSource(wlAPISourceA),
			listenErr:      "listen invalid: unknown network invalid",
		},
		{
			name:           "Missing server port",
			listenProtocol: "tcp",
			listenLAddr:    "invalid",
			listenMode:     spiffetls.TLSServerWithSource(wlAPISourceA),
			listenErr:      "listen tcp: address invalid: missing port in address",
		},
		{
			name:           "Invalid server source",
			listenProtocol: "tcp",
			listenErr:      "spiffetls: cannot create X.509 source: workload endpoint socket address is not configured",
			listenMode:     spiffetls.TLSServer(),
		},

		// Dial Option / Listen Option Scenarios
		{
			name:                "TLSClient dials using TLS base config",
			dialMode:            spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:          spiffetls.TLSServerWithSource(wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    wlAPIServerB.Addr(),
			usesBaseTLSConfig:   true,
			dialOption: []spiffetls.DialOption{
				spiffetls.WithDialTLSConfigBase(&tls.Config{
					KeyLogWriter: externalTLSConfBuffer,
				}),
			},
		},
		{
			name:                "TLSClient dials using external dialer",
			dialMode:            spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:          spiffetls.TLSServerWithSource(wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    wlAPIServerB.Addr(),
			usesExternalDialer:  true,
			dialOption: []spiffetls.DialOption{
				spiffetls.WithDialer(&net.Dialer{
					Control: func(network, addr string, c syscall.RawConn) error {
						externalDialerUsed = true
						return nil
					},
				}),
			},
		},
		{
			name:       "TLSServer with ListenOption",
			dialMode:   spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode: spiffetls.TLSServerWithSource(wlAPISourceA),
			listenOption: []spiffetls.ListenOption{
				spiffetls.WithListenTLSConfigBase(&tls.Config{
					KeyLogWriter: externalTLSConfBuffer,
				}),
			},
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    wlAPIServerB.Addr(),
		},

		// Defaults Scenarios
		{
			name:                "TLSClient succeeds",
			dialMode:            spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:          spiffetls.TLSServerWithSource(wlAPISourceA),
			defaultWlAPIAddr:    wlAPIServerB.Addr(),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:                "TLSClient succeeds with Dial",
			listenMode:          spiffetls.TLSServerWithSource(wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    wlAPIServerB.Addr(),
		},
		{
			name:             "MTLSClient succeeds",
			dialMode:         spiffetls.MTLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:       spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), wlAPISourceA),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
		},
		{
			name:                "MTLSWebClient / MTLSWebServer succeeds",
			dialMode:            spiffetls.MTLSWebClient(webCertPool),
			listenMode:          spiffetls.MTLSWebServer(tlsconfig.AuthorizeID(clientID), webCert),
			defaultWlAPIAddr:    wlAPIServerB.Addr(),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},

		// *WithSource Scenario
		{
			name:                "TLSClientWithSource / TLSServerWithSource succeeds",
			dialMode:            spiffetls.TLSClientWithSource(tlsconfig.AuthorizeID(serverID), wlAPISourceB),
			listenMode:          spiffetls.TLSServerWithSource(wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:       "MTLSClientWithSource / MTLSServerWithSource succeeds",
			dialMode:   spiffetls.MTLSClientWithSource(tlsconfig.AuthorizeID(serverID), wlAPISourceB),
			listenMode: spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), wlAPISourceA),
		},
		{
			name:                "MTLSWebClientWithSource / MTLSWebServerWithSource succeeds",
			dialMode:            spiffetls.MTLSWebClientWithSource(webCertPool, wlAPISourceB),
			listenMode:          spiffetls.MTLSWebServerWithSource(tlsconfig.AuthorizeID(clientID), webCert, wlAPISourceA),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},

		// *WithSourceOptions Scenario
		{
			name:                "TLSClientWithSourceOptions / TLSServerWithSourceOptions succeeds",
			dialMode:            spiffetls.TLSClientWithSourceOptions(tlsconfig.AuthorizeID(serverID), workloadapi.WithClient(wlAPIClientB)),
			listenMode:          spiffetls.TLSServerWithSourceOptions(workloadapi.WithClientOptions(workloadapi.WithAddr(wlAPIServerA.Addr()))),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:       "MTLSClientWithSourceOptions / MTLSServerWithSourceOptions succeeds",
			dialMode:   spiffetls.MTLSClientWithSourceOptions(tlsconfig.AuthorizeID(serverID), workloadapi.WithClient(wlAPIClientB)),
			listenMode: spiffetls.MTLSServerWithSourceOptions(tlsconfig.AuthorizeID(clientID), workloadapi.WithClientOptions(workloadapi.WithAddr(wlAPIServerA.Addr()))),
		},
		{
			name:                "MTLSWebClientWithSourceOptions / MTLSWebServerWithSourceOptions succeeds",
			dialMode:            spiffetls.MTLSWebClientWithSourceOptions(webCertPool, workloadapi.WithClient(wlAPIClientB)),
			listenMode:          spiffetls.MTLSWebServerWithSourceOptions(tlsconfig.AuthorizeID(clientID), webCert, workloadapi.WithClientOptions(workloadapi.WithAddr(wlAPIServerA.Addr()))),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},

		// *WithRawConfig Scenario
		{
			name:                "TLSClientWithRawConfig / TLSServerWithRawConfig succeeds",
			dialMode:            spiffetls.TLSClientWithRawConfig(tlsconfig.AuthorizeID(serverID), bundleSource),
			listenMode:          spiffetls.TLSServerWithRawConfig(wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:       "MTLSClientWithRawConfig / MTLSServerWithRawConfig succeeds",
			dialMode:   spiffetls.MTLSClientWithRawConfig(tlsconfig.AuthorizeID(serverID), svidSource, bundleSource),
			listenMode: spiffetls.MTLSServerWithRawConfig(tlsconfig.AuthorizeID(clientID), wlAPISourceA, bundleSource),
		},
		{
			name:                "MTLSWebClientWithRawConfig / MTLSWebServerWithRawConfig succeeds",
			dialMode:            spiffetls.MTLSWebClientWithRawConfig(webCertPool, svidSource),
			listenMode:          spiffetls.MTLSWebServerWithRawConfig(tlsconfig.AuthorizeID(clientID), webCert, bundleSource),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},
	}

	testClose(t, spiffetls.TLSServerWithSource(wlAPISourceA), spiffetls.TLSClientWithSource(tlsconfig.AuthorizeID(serverID), wlAPISourceB))

	for _, test := range tests {
		test := test

		if test.defaultWlAPIAddr != "" {
			require.NoError(t, os.Setenv("SPIFFE_ENDPOINT_SOCKET", test.defaultWlAPIAddr))
		} else {
			require.NoError(t, os.Unsetenv("SPIFFE_ENDPOINT_SOCKET"))
		}

		t.Run(test.name, func(t *testing.T) {
			// Start listening
			listenCtx, cancelListenCtx := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelListenCtx()

			var wg sync.WaitGroup
			var listener net.Listener
			var listenAddr string
			listenDataCh := make(chan string, 1)
			listenErrCh := make(chan error, 1)
			if test.listenLAddr == "" {
				test.listenLAddr = defaultListenLAddr
			}
			if test.listenProtocol == "" {
				test.listenProtocol = defaultListenProtocol
			}
			if test.listenMode != nil {
				listener, err = spiffetls.ListenWithMode(listenCtx, test.listenProtocol, test.listenLAddr, test.listenMode, test.listenOption...)
				if test.listenErr != "" {
					require.Error(t, err)
					require.EqualError(t, err, test.listenErr)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, listener)
				defer listener.Close()

				listenAddr = listener.Addr().String()
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := listener.Accept()
					if err != nil {
						listenErrCh <- err
						return
					}
					defer conn.Close()

					data, err := bufio.NewReader(conn).ReadString('\n')
					if err != nil {
						listenErrCh <- err
						return
					}
					listenDataCh <- data

					// Test serverConn.PeerID()
					spiffeID, err := spiffetls.PeerIDFromConn(conn)
					if test.serverConnPeerIDErr == "" {
						require.NoError(t, err)
						require.Equal(t, clientID, spiffeID)
					} else {
						require.EqualError(t, err, test.serverConnPeerIDErr)
					}
				}()
			} else {
				// Test Listen function
				listener, err = spiffetls.Listen(listenCtx, test.listenProtocol, test.listenLAddr, tlsconfig.AuthorizeID(clientID))
				if test.listenErr != "" {
					require.Error(t, err)
					require.EqualError(t, err, test.listenErr)
				}
			}

			// Start dialing
			dialCtx, cancelDialCtx := context.WithTimeout(context.Background(), time.Second*10)
			defer cancelDialCtx()

			dialConnCh := make(chan net.Conn, 1)
			dialErrCh := make(chan error, 1)
			externalDialerUsed = false
			externalTLSConfBuffer.Reset()
			wg.Add(1)
			go func() {
				defer wg.Done()
				var conn net.Conn
				var err error
				if test.dialMode == nil {
					// Test Dial function
					conn, err = spiffetls.Dial(dialCtx, "tcp", listenAddr, tlsconfig.AuthorizeID(serverID))
				} else {
					conn, err = spiffetls.DialWithMode(dialCtx, "tcp", listenAddr, test.dialMode, test.dialOption...)
				}
				if len(test.listenOption) > 0 {
					require.NotEmpty(t, externalTLSConfBuffer.Len())
				}
				if err != nil {
					dialErrCh <- err
					return
				}
				dialConnCh <- conn
			}()

			// Assertions
			defer wg.Wait()
			for {
				select {
				case dialConn := <-dialConnCh:
					require.NotNil(t, dialConn)
					defer dialConn.Close()

					if test.usesExternalDialer {
						require.True(t, externalDialerUsed)
					}
					if test.usesBaseTLSConfig {
						require.NotEmpty(t, externalTLSConfBuffer.Len())
					}

					// Test clientConn.PeerID()
					spiffeID, err := spiffetls.PeerIDFromConn(dialConn)
					if test.clientConnPeerIDErr == "" {
						require.NoError(t, err)
						require.Equal(t, serverID, spiffeID)
					} else {
						require.Error(t, err)
					}

					fmt.Fprint(dialConn, testMsg)

				case data := <-listenDataCh:
					require.Equal(t, testMsg, data)
					return

				case err := <-listenErrCh:
					t.Fatalf("Listener failed: %v\n", err)

				case err := <-dialErrCh:
					if test.dialErr != "" {
						require.EqualError(t, err, test.dialErr)
						return
					}
					require.NoError(t, err)

				case err := <-dialCtx.Done():
					t.Fatalf("Dial context timed out: %v", err)

				case err := <-listenCtx.Done():
					t.Fatalf("Listen context timed out: %v", err)
				}
			}
		})
	}
}

// testClose tests closing connections and listener
func testClose(t *testing.T, listenMode spiffetls.ListenMode, dialMode spiffetls.DialMode) {
	listenCtx, cancelListenCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelListenCtx()
	listener, err := spiffetls.ListenWithMode(listenCtx, defaultListenProtocol, defaultListenLAddr, listenMode)
	require.NoError(t, err)

	go func() {
		conn, err := listener.Accept()
		require.NoError(t, err)

		_, err = io.Copy(conn, conn)
		require.NoError(t, err)

		conn.Close()
	}()

	dialCtx, cancelDialCtx := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelDialCtx()
	conn, err := spiffetls.DialWithMode(dialCtx, "tcp", listener.Addr().String(), dialMode)
	require.NoError(t, err)

	// Test writing data to the connection
	dataString := "test data"
	n, err := conn.Write([]byte(dataString))
	require.NoError(t, err)
	require.Equal(t, len(dataString), n)

	// Close connection
	require.NoError(t, conn.Close())

	// If the connection was really closed, this should fail
	_, err = conn.Write([]byte(dataString))
	require.EqualError(t, err, "tls: use of closed connection")

	// Connection has been closed already, expect error
	require.EqualError(t, conn.Close(), "spiffetls: unable to close TLS connection: tls: use of closed connection")

	// Close listener
	require.NoError(t, listener.Close())

	// If the listener was really closed, this should fail
	_, err = listener.Accept()
	require.Error(t, err)

	// Listener has been closed already, expect error
	require.Contains(t, listener.Close().Error(), "use of closed network connection")
}

func setWorkloadAPIResponse(ca *test.CA, s *fakeworkloadapi.WorkloadAPI, spiffeID spiffeid.ID) {
	s.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{ca.CreateX509SVID(spiffeID)},
	})
}
