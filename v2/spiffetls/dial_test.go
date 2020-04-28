package spiffetls_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

var (
	clientID = spiffeid.RequireFromString("spiffe://example.org/client-workload")
	serverID = spiffeid.RequireFromString("spiffe://example.org/server-workload")
	testMsg  = "Hello!\n"
)

func TestDialWithMode(t *testing.T) {
	// Common CA for client and server SVIDs
	ca := test.NewCA(t)

	// Start two fake workload API servers called "A" and "B"
	// Workload API Server A provides identities to the server workload
	wlAPIServerA := fakeworkloadapi.NewWorkloadAPI(t)
	defer wlAPIServerA.Stop()
	setWorkloadAPIResponse(ca, wlAPIServerA, serverID.String())

	// Workload API Server B provides identities to the client workload
	wlAPIServerB := fakeworkloadapi.NewWorkloadAPI(t)
	defer wlAPIServerB.Stop()
	setWorkloadAPIResponse(ca, wlAPIServerB, clientID.String())

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
	bundleSource := x509bundle.FromX509Authorities(clientID.TrustDomain(), ca.Roots())
	clientSVID, clientSigner := ca.CreateX509SVID(clientID.String())
	clientKey, err := x509.MarshalPKCS8PrivateKey(clientSigner)
	require.NoError(t, err)
	svidSource, err := x509svid.ParseRaw(clientSVID[0].Raw, clientKey)
	require.NoError(t, err)

	// Create web credentials
	webCertPool, webCert := test.CreateWebCredentials(t)

	// Test Table
	tests := []struct {
		name string

		dialMode   spiffetls.DialMode
		dialOption []spiffetls.DialOption

		listenMode   spiffetls.ListenMode
		listenOption []spiffetls.ListenOption

		defaultWlAPIAddr string
		expErrContains   string
	}{
		// Failiures Scenarios
		{
			name:             "Wrong workload API server socket",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			defaultWlAPIAddr: "wrong-socket-path",
			expErrContains:   "cannot create X.509 source",
		},
		{
			name:             "No server listening",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
			expErrContains:   "unable to dial",
		},

		// Dial Option Scenarios
		{
			name:             "TLSClient dials using TLS base config",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:       spiffetls.TLSServerWithSource(wlAPISourceA),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
			dialOption: []spiffetls.DialOption{
				spiffetls.WithDialTLSConfigBase(&tls.Config{
					MinVersion: tls.VersionTLS13,
				}),
			},
		},
		{
			name:             "TLSClient dials using external dialer",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:       spiffetls.TLSServerWithSource(wlAPISourceA),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
			dialOption: []spiffetls.DialOption{
				spiffetls.WithDialer(&net.Dialer{}),
			},
		},

		// Defaults Scenarios
		{
			name:             "TLSClient succeeds",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:       spiffetls.TLSServerWithSource(wlAPISourceA),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
		},
		{
			name:             "MTLSClient succeeds",
			dialMode:         spiffetls.MTLSClient(tlsconfig.AuthorizeID(serverID)),
			listenMode:       spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), wlAPISourceA),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
		},
		{
			name:             "MTLSWebClient succeeds",
			dialMode:         spiffetls.MTLSWebClient(webCertPool),
			listenMode:       spiffetls.MTLSWebServerWithSource(tlsconfig.AuthorizeID(clientID), webCert, wlAPISourceA),
			defaultWlAPIAddr: wlAPIServerB.Addr(),
		},

		// *WithSource Scenario
		{
			name:       "TLSClientWithSource succeeds",
			dialMode:   spiffetls.TLSClientWithSource(tlsconfig.AuthorizeID(serverID), wlAPISourceB),
			listenMode: spiffetls.TLSServerWithSource(wlAPISourceA),
		},
		{
			name:       "MTLSClientWithSource succeeds",
			dialMode:   spiffetls.MTLSClientWithSource(tlsconfig.AuthorizeID(serverID), wlAPISourceB),
			listenMode: spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), wlAPISourceA),
		},
		{
			name:       "MTLSWebClient  succeeds",
			dialMode:   spiffetls.MTLSWebClientWithSource(webCertPool, wlAPISourceB),
			listenMode: spiffetls.MTLSWebServerWithSource(tlsconfig.AuthorizeID(clientID), webCert, wlAPISourceA),
		},

		// *WithSourceOptions Scenario
		{
			name:       "TLSClientWithSource succeeds",
			dialMode:   spiffetls.TLSClientWithSourceOptions(tlsconfig.AuthorizeID(serverID), workloadapi.WithClient(wlAPIClientB)),
			listenMode: spiffetls.TLSServerWithSource(wlAPISourceA),
		},
		{
			name:       "MTLSClientWithSource succeeds",
			dialMode:   spiffetls.MTLSClientWithSourceOptions(tlsconfig.AuthorizeID(serverID), workloadapi.WithClient(wlAPIClientB)),
			listenMode: spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), wlAPISourceA),
		},
		{
			name:       "MTLSWebClient  succeeds",
			dialMode:   spiffetls.MTLSWebClientWithSourceOptions(webCertPool, workloadapi.WithClient(wlAPIClientB)),
			listenMode: spiffetls.MTLSWebServerWithSource(tlsconfig.AuthorizeID(clientID), webCert, wlAPISourceA),
		},

		// *WithRawConfig Scenario
		{
			name:       "TLSClientWithSource succeeds",
			dialMode:   spiffetls.TLSClientWithRawConfig(tlsconfig.AuthorizeID(serverID), bundleSource),
			listenMode: spiffetls.TLSServerWithSource(wlAPISourceA),
		},
		{
			name:       "MTLSClientWithSource succeeds",
			dialMode:   spiffetls.MTLSClientWithRawConfig(tlsconfig.AuthorizeID(serverID), svidSource, bundleSource),
			listenMode: spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), wlAPISourceA),
		},
		{
			name:       "MTLSWebClient  succeeds",
			dialMode:   spiffetls.MTLSWebClientWithRawConfig(webCertPool, svidSource),
			listenMode: spiffetls.MTLSWebServerWithSource(tlsconfig.AuthorizeID(clientID), webCert, wlAPISourceA),
		},
	}

	for _, test := range tests {
		test := test

		err := os.Setenv("SPIFFE_ENDPOINT_SOCKET", test.defaultWlAPIAddr)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			// Start listening
			listenCtx, cancelListenCtx := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelListenCtx()

			var listener net.Listener
			var listenAddr string
			listenDoneCh := make(chan struct{})
			listenDataCh := make(chan string)
			listenErrCh := make(chan error)
			if test.listenMode != nil {
				listener, err = spiffetls.ListenWithMode(listenCtx, "tcp", "localhost:0", test.listenMode)
				require.NoError(t, err)
				require.NotNil(t, listener)
				defer listener.Close()

				listenAddr = listener.Addr().String()

				go func() {
					for {
						select {
						case <-listenDoneCh:
							return
						default:
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
						}
					}
				}()
			}

			// Start dialing
			dialCtx, cancelDialCtx := context.WithTimeout(context.Background(), time.Second*10)
			defer cancelDialCtx()

			dialConnCh := make(chan net.Conn)
			dialErrCh := make(chan error)
			go func() {
				conn, err := spiffetls.DialWithMode(dialCtx, "tcp", listenAddr, test.dialMode, test.dialOption...)
				if err != nil {
					dialErrCh <- err
					return
				}
				dialConnCh <- conn
			}()

			// Assertions
			for {
				select {
				case dialConn := <-dialConnCh:
					require.NotNil(t, dialConn)
					defer dialConn.Close()

					fmt.Fprint(dialConn, testMsg)
					close(listenDoneCh)

				case data := <-listenDataCh:
					require.Equal(t, testMsg, data)
					return

				case err := <-listenErrCh:
					t.Fatalf("Listener failed: %v\n", err)

				case err := <-dialErrCh:
					if test.expErrContains != "" {
						require.Contains(t, err.Error(), test.expErrContains)
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

func setWorkloadAPIResponse(ca *test.CA, s *fakeworkloadapi.WorkloadAPI, spiffeID string) {
	svid, key := ca.CreateX509SVID(spiffeID)
	s.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.Roots(),
		SVIDs: []fakeworkloadapi.X509SVID{
			{
				CertChain: svid,
				Key:       key,
			},
		},
	})
}
