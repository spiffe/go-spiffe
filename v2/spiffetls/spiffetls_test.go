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
	"github.com/stretchr/testify/assert"
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

type testEnv struct {
	ca           *test.CA
	wlAPISourceA *workloadapi.X509Source
	wlAPISourceB *workloadapi.X509Source
	wlAPIClientA *workloadapi.Client
	wlAPIClientB *workloadapi.Client
	wlAPIServerA *fakeworkloadapi.WorkloadAPI
	wlAPIServerB *fakeworkloadapi.WorkloadAPI
	wlCancel     context.CancelFunc
	err          error
}

type listenAndDialCase struct {
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
}

func TestListenAndDial(t *testing.T) {
	testEnv, cleanup := setupTestEnv(t)
	defer cleanup()

	// Create custom SVID and bundle source (not backed by workload API)
	bundleSource := testEnv.ca.X509Bundle()
	svidSource := testEnv.ca.CreateX509SVID(clientID)

	// Create web credentials
	webCertPool, webCert := test.CreateWebCredentials(t)

	// Flag used to detect if an external dialer was actually used
	externalDialerUsed := false

	// Buffer used to detect if a base TLS config was actually used
	externalTLSConfBuffer := &bytes.Buffer{}

	// Test Table
	tests := []listenAndDialCase{
		// Failure Scenarios
		{
			name:             "No server listening",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			defaultWlAPIAddr: testEnv.wlAPIServerB.Addr(),
			dialErr:          "spiffetls: unable to dial: dial tcp: missing address",
		},
		{
			name:           "Invalid server protocol",
			listenProtocol: "invalid",
			listenMode:     spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			listenErr:      "listen invalid: unknown network invalid",
		},
		{
			name:           "Missing server port",
			listenProtocol: "tcp",
			listenLAddr:    "invalid",
			listenMode:     spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
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
			listenMode:          spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    testEnv.wlAPIServerB.Addr(),
			usesBaseTLSConfig:   true,
			dialOption: []spiffetls.DialOption{
				spiffetls.WithDialTLSConfigBase(&tls.Config{
					MinVersion:   tls.VersionTLS12,
					KeyLogWriter: externalTLSConfBuffer,
				}),
			},
		},
		{
			name:                "TLSClient dials using external dialer",
			dialMode:            spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:          spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    testEnv.wlAPIServerB.Addr(),
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
			listenMode: spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			listenOption: []spiffetls.ListenOption{
				spiffetls.WithListenTLSConfigBase(&tls.Config{
					MinVersion:   tls.VersionTLS12,
					KeyLogWriter: externalTLSConfBuffer,
				}),
			},
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    testEnv.wlAPIServerB.Addr(),
		},

		// Defaults Scenarios
		{
			name:                "TLSClient succeeds",
			dialMode:            spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:          spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			defaultWlAPIAddr:    testEnv.wlAPIServerB.Addr(),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:                "TLSClient succeeds with Dial",
			listenMode:          spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
			defaultWlAPIAddr:    testEnv.wlAPIServerB.Addr(),
		},
		{
			name:             "MTLSClient succeeds",
			dialMode:         spiffetls.MTLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:       spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), testEnv.wlAPISourceA),
			defaultWlAPIAddr: testEnv.wlAPIServerB.Addr(),
		},
		{
			name:                "MTLSWebClient / MTLSWebServer succeeds",
			dialMode:            spiffetls.MTLSWebClient(webCertPool),
			listenMode:          spiffetls.MTLSWebServer(tlsconfig.AuthorizeID(clientID), webCert),
			defaultWlAPIAddr:    testEnv.wlAPIServerB.Addr(),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},

		// *WithSource Scenario
		{
			name:                "TLSClientWithSource / TLSServerWithSource succeeds",
			dialMode:            spiffetls.TLSClientWithSource(tlsconfig.AuthorizeID(serverID), testEnv.wlAPISourceB),
			listenMode:          spiffetls.TLSServerWithSource(testEnv.wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:       "MTLSClientWithSource / MTLSServerWithSource succeeds",
			dialMode:   spiffetls.MTLSClientWithSource(tlsconfig.AuthorizeID(serverID), testEnv.wlAPISourceB),
			listenMode: spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), testEnv.wlAPISourceA),
		},
		{
			name:                "MTLSWebClientWithSource / MTLSWebServerWithSource succeeds",
			dialMode:            spiffetls.MTLSWebClientWithSource(webCertPool, testEnv.wlAPISourceB),
			listenMode:          spiffetls.MTLSWebServerWithSource(tlsconfig.AuthorizeID(clientID), webCert, testEnv.wlAPISourceA),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},

		// *WithSourceOptions Scenario
		{
			name:                "TLSClientWithSourceOptions / TLSServerWithSourceOptions succeeds",
			dialMode:            spiffetls.TLSClientWithSourceOptions(tlsconfig.AuthorizeID(serverID), workloadapi.WithClient(testEnv.wlAPIClientB)),
			listenMode:          spiffetls.TLSServerWithSourceOptions(workloadapi.WithClientOptions(workloadapi.WithAddr(testEnv.wlAPIServerA.Addr()))),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:       "MTLSClientWithSourceOptions / MTLSServerWithSourceOptions succeeds",
			dialMode:   spiffetls.MTLSClientWithSourceOptions(tlsconfig.AuthorizeID(serverID), workloadapi.WithClient(testEnv.wlAPIClientB)),
			listenMode: spiffetls.MTLSServerWithSourceOptions(tlsconfig.AuthorizeID(clientID), workloadapi.WithClientOptions(workloadapi.WithAddr(testEnv.wlAPIServerA.Addr()))),
		},
		{
			name:                "MTLSWebClientWithSourceOptions / MTLSWebServerWithSourceOptions succeeds",
			dialMode:            spiffetls.MTLSWebClientWithSourceOptions(webCertPool, workloadapi.WithClient(testEnv.wlAPIClientB)),
			listenMode:          spiffetls.MTLSWebServerWithSourceOptions(tlsconfig.AuthorizeID(clientID), webCert, workloadapi.WithClientOptions(workloadapi.WithAddr(testEnv.wlAPIServerA.Addr()))),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},

		// *WithRawConfig Scenario
		{
			name:                "TLSClientWithRawConfig / TLSServerWithRawConfig succeeds",
			dialMode:            spiffetls.TLSClientWithRawConfig(tlsconfig.AuthorizeID(serverID), bundleSource),
			listenMode:          spiffetls.TLSServerWithRawConfig(testEnv.wlAPISourceA),
			serverConnPeerIDErr: "spiffetls: no peer certificates",
		},
		{
			name:       "MTLSClientWithRawConfig / MTLSServerWithRawConfig succeeds",
			dialMode:   spiffetls.MTLSClientWithRawConfig(tlsconfig.AuthorizeID(serverID), svidSource, bundleSource),
			listenMode: spiffetls.MTLSServerWithRawConfig(tlsconfig.AuthorizeID(clientID), testEnv.wlAPISourceA, bundleSource),
		},
		{
			name:                "MTLSWebClientWithRawConfig / MTLSWebServerWithRawConfig succeeds",
			dialMode:            spiffetls.MTLSWebClientWithRawConfig(webCertPool, svidSource),
			listenMode:          spiffetls.MTLSWebServerWithRawConfig(tlsconfig.AuthorizeID(clientID), webCert, bundleSource),
			clientConnPeerIDErr: "spiffetls: no URI SANs",
		},
	}
	tests = append(tests, listenAndDialCasesOS()...)

	for _, test := range tests {
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
				listener, err := spiffetls.ListenWithMode(listenCtx, test.listenProtocol, test.listenLAddr, test.listenMode, test.listenOption...)
				if test.listenErr != "" {
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
						assert.NoError(t, err)
						assert.Equal(t, clientID, spiffeID)
					} else {
						assert.EqualError(t, err, test.serverConnPeerIDErr)
					}
				}()
			} else {
				// Test Listen function
				_, err := spiffetls.Listen(listenCtx, test.listenProtocol, test.listenLAddr, tlsconfig.AuthorizeID(clientID))
				if test.listenErr != "" {
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
					assert.NotEmpty(t, externalTLSConfBuffer.Len())
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

func TestClose(t *testing.T) {
	testEnv, cleanup := setupTestEnv(t)
	defer cleanup()

	listenCtx, cancelListenCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelListenCtx()
	listener, err := spiffetls.ListenWithMode(listenCtx, defaultListenProtocol, defaultListenLAddr, spiffetls.TLSServerWithSource(testEnv.wlAPISourceA))
	require.NoError(t, err)

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		require.NoError(t, err)
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	dialCtx, cancelDialCtx := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelDialCtx()
	conn, err := spiffetls.DialWithMode(dialCtx, "tcp", listener.Addr().String(), spiffetls.TLSClientWithSource(tlsconfig.AuthorizeID(serverID), testEnv.wlAPISourceB))
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
	require.Error(t, err)

	// Connection has been closed already, expect error
	require.Error(t, conn.Close())

	// Close listener
	require.NoError(t, listener.Close())

	// If the listener was really closed, this should fail
	_, err = listener.Accept()
	require.Error(t, err)

	// Listener has been closed already, expect error
	require.Error(t, listener.Close())
}

func setWorkloadAPIResponse(ca *test.CA, s *fakeworkloadapi.WorkloadAPI, spiffeID spiffeid.ID) {
	s.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{ca.CreateX509SVID(spiffeID)},
	})
}

func setupTestEnv(t *testing.T) (*testEnv, func()) {
	testEnv := &testEnv{}

	cleanup := func() {
		if testEnv.wlAPIClientA != nil {
			testEnv.wlAPIClientA.Close()
		}

		if testEnv.wlAPIClientB != nil {
			testEnv.wlAPIClientB.Close()
		}

		if testEnv.wlAPIServerA != nil {
			testEnv.wlAPIServerA.Stop()
		}

		if testEnv.wlAPIServerB != nil {
			testEnv.wlAPIServerB.Stop()
		}

		if testEnv.wlCancel != nil {
			testEnv.wlCancel()
		}

		if testEnv.err != nil {
			t.Fatal(testEnv.err)
		}
	}

	// Common CA for client and server SVIDs
	testEnv.ca = test.NewCA(t, td)

	// Start two fake workload API servers called "A" and "B"
	// Workload API Server A provides identities to the server workload
	testEnv.wlAPIServerA = fakeworkloadapi.New(t)
	setWorkloadAPIResponse(testEnv.ca, testEnv.wlAPIServerA, serverID)

	// Workload API Server B provides identities to the client workload
	testEnv.wlAPIServerB = fakeworkloadapi.New(t)
	setWorkloadAPIResponse(testEnv.ca, testEnv.wlAPIServerB, clientID)

	// Create custom workload API sources for the server
	wlCtx, wlCancel := context.WithTimeout(context.Background(), time.Second*5)
	testEnv.wlCancel = wlCancel
	testEnv.wlAPIClientA, testEnv.err = workloadapi.New(wlCtx, workloadapi.WithAddr(testEnv.wlAPIServerA.Addr()))
	if testEnv.err != nil {
		cleanup()
	}
	testEnv.wlAPISourceA, testEnv.err = workloadapi.NewX509Source(wlCtx, workloadapi.WithClient(testEnv.wlAPIClientA))
	if testEnv.err != nil {
		cleanup()
	}

	// Create custom workload API sources for the client
	testEnv.wlAPIClientB, testEnv.err = workloadapi.New(wlCtx, workloadapi.WithAddr(testEnv.wlAPIServerB.Addr()))
	if testEnv.err != nil {
		cleanup()
	}

	testEnv.wlAPISourceB, testEnv.err = workloadapi.NewX509Source(wlCtx, workloadapi.WithClient(testEnv.wlAPIClientB))
	if testEnv.err != nil {
		cleanup()
	}

	return testEnv, cleanup
}
