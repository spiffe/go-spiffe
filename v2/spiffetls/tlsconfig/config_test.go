package tlsconfig_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTLSClientConfig(t *testing.T) {
	// Create trust domain and bundle
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)

	// Call TLSClientConfig
	config := tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookTLSClientConfig(t *testing.T) {
	// Create trust domain and bundle
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)

	// Create test config
	config := createTestTlsConfig()

	// Call HookTLSClientConfig
	tlsconfig.HookTLSClientConfig(config, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestMTLSClientConfig(t *testing.T) {
	// Create trust domain, bundle and svid
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}

	// Call TLSClientConfig
	config := tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSClientConfig(t *testing.T) {
	// Create trust domain and bundle
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}

	// Create test config
	config := createTestTlsConfig()

	// Call HookTLSClientConfig
	tlsconfig.HookMTLSClientConfig(config, svid, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestMTLSWebClientConfig(t *testing.T) {
	// Create svid
	svid := &x509svid.SVID{}

	// Call TLSClientConfig
	config := tlsconfig.MTLSWebClientConfig(svid)

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.Nil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSWebClientConfig(t *testing.T) {
	// Create svid
	svid := &x509svid.SVID{}

	// Create test config
	config := createTestTlsConfig()

	// Call HookTLSClientConfig
	tlsconfig.HookMTLSWebClientConfig(config, svid)

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.Nil(t, config.VerifyPeerCertificate)
}

func TestTLSServerConfig(t *testing.T) {
	// Create SVID
	svid := &x509svid.SVID{}

	// Call TLSClientConfig
	config := tlsconfig.TLSServerConfig(svid)

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.Nil(t, config.VerifyPeerCertificate)
}

func TestHookTLSServerConfig(t *testing.T) {
	// Create SVID
	svid := &x509svid.SVID{}

	// Create test config
	config := createTestTlsConfig()

	// Call HookTLSClientConfig
	tlsconfig.HookTLSServerConfig(config, svid)

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.Nil(t, config.VerifyPeerCertificate)
}

func TestMTLSServerConfig(t *testing.T) {
	// Create trust domain, bundle and svid
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}

	// Call TLSClientConfig
	config := tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.RequireAndVerifyClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSServerConfig(t *testing.T) {
	// Create trust domain and bundle
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}

	// Create test config
	config := createTestTlsConfig()

	// Call HookTLSClientConfig
	tlsconfig.HookMTLSServerConfig(config, svid, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.RequireAndVerifyClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestMTLSWebServerConfig(t *testing.T) {
	// Create trust domain, bundle and tls certificate
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	tlsCert := &tls.Certificate{Certificate: [][]byte{[]byte("body")}}

	// Call TLSClientConfig
	config := tlsconfig.MTLSWebServerConfig(tlsCert, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Equal(t, []tls.Certificate{*tlsCert}, config.Certificates)
	assert.Equal(t, tls.RequireAndVerifyClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSWebServerConfig(t *testing.T) {
	// Create trust domain, bundle and tls certificate
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	tlsCert := &tls.Certificate{Certificate: [][]byte{[]byte("body")}}

	// Create test config
	config := createTestTlsConfig()

	// Call HookTLSClientConfig
	tlsconfig.HookMTLSWebServerConfig(config, tlsCert, bundle, tlsconfig.AuthorizeAny())

	// Expected AuthFields
	assert.Equal(t, []tls.Certificate{*tlsCert}, config.Certificates)
	assert.Equal(t, tls.RequireAndVerifyClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestGetCertificate(t *testing.T) {
	testCases := []struct {
		name          string
		source        *fakeSource
		err           string
		expectedCerts [][]byte
	}{
		{
			name: "success",
			source: &fakeSource{
				err: nil,
				svid: &x509svid.SVID{
					ID: spiffeid.Must("test.domain", "host"),
					Certificates: []*x509.Certificate{
						{Raw: []byte("body")},
					},
				},
			},
			expectedCerts: [][]byte{[]byte("body")},
		},
		{
			name: "source return error",
			source: &fakeSource{
				err: errors.New("some error"),
			},
			err: "some error",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			getCertificate := tlsconfig.GetCertificate(testCase.source)
			require.NotNil(t, getCertificate)

			//  Execute getCertificate
			tlsCert, err := getCertificate(&tls.ClientHelloInfo{})
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				require.Nil(t, tlsCert)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expectedCerts, tlsCert.Certificate)
		})
	}
}

func createTestTlsConfig() *tls.Config {
	tlsCert := tls.Certificate{Certificate: [][]byte{[]byte("body")}}
	return &tls.Config{
		Certificates: []tls.Certificate{
			tlsCert,
		},
		NameToCertificate: map[string]*tls.Certificate{"cert": &tlsCert},
		GetCertificate: func(info *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
			return nil, nil
		},
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (certificate *tls.Certificate, err error) {
			return nil, nil
		},
		VerifyPeerCertificate: nil,
		RootCAs:               x509.NewCertPool(),
		ClientAuth:            tls.RequestClientCert,
	}
}

func TestGetClientCertificate(t *testing.T) {
	testCases := []struct {
		name          string
		source        *fakeSource
		err           string
		expectedCerts [][]byte
	}{
		{
			name: "success",
			source: &fakeSource{
				err: nil,
				svid: &x509svid.SVID{
					ID: spiffeid.Must("test.domain", "host"),
					Certificates: []*x509.Certificate{
						{Raw: []byte("body")},
					},
				},
			},
			expectedCerts: [][]byte{[]byte("body")},
		},
		{
			name: "source return error",
			source: &fakeSource{
				err: errors.New("some error"),
			},
			err: "some error",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			getClientCertificate := tlsconfig.GetClientCertificate(testCase.source)
			require.NotNil(t, getClientCertificate)

			//  Execute getCertificate
			tlsCert, err := getClientCertificate(&tls.CertificateRequestInfo{})
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				require.Nil(t, tlsCert)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expectedCerts, tlsCert.Certificate)
		})
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)
	require.NotNil(t, bundle1)
	svid1, signer := ca1.CreateX509SVID(td.NewID("host").String())
	require.NotNil(t, svid1)
	require.NotNil(t, signer)

	var svid1Raw [][]byte
	for _, cert := range svid1 {
		svid1Raw = append(svid1Raw, cert.Raw)
	}

	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)

	testCases := []struct {
		name       string
		authorizer tlsconfig.Authorizer
		bundle     x509bundle.Source
		err        string
		raw        [][]byte
	}{
		{
			name:       "success",
			authorizer: tlsconfig.AuthorizeAny(),
			bundle:     bundle1,
			raw:        svid1Raw,
		},
		{
			name:       "parse and validation fails",
			authorizer: tlsconfig.AuthorizeAny(),
			bundle:     bundle2,
			err:        `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
			raw:        svid1Raw,
		},
		{
			name:       "authorizer fails",
			authorizer: tlsconfig.AuthorizeMemberOf(td2),
			bundle:     bundle1,
			err:        `unexpected trust domain "domain1.test"`,
			raw:        svid1Raw,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			verifyPeerCertificate := tlsconfig.VerifyPeerCertificate(testCase.bundle, testCase.authorizer)
			require.NotNil(t, verifyPeerCertificate)

			err := verifyPeerCertificate(testCase.raw, [][]*x509.Certificate{})
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestWrapVerifyPeerCertificate(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)
	require.NotNil(t, bundle1)
	svid1, _ := ca1.CreateX509SVID(td.NewID("host").String())
	require.NotNil(t, svid1)

	var svid1Raw [][]byte
	for _, cert := range svid1 {
		svid1Raw = append(svid1Raw, cert.Raw)
	}

	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)

	wrapped := func([][]byte, [][]*x509.Certificate) error {
		return errors.New("wrapped called")
	}

	testCases := []struct {
		name       string
		authorizer tlsconfig.Authorizer
		bundle     x509bundle.Source
		err        string
		raw        [][]byte
		wrapped    func([][]byte, [][]*x509.Certificate) error
	}{
		{
			name:       "no wrapped",
			authorizer: tlsconfig.AuthorizeAny(),
			bundle:     bundle1,
			raw:        svid1Raw,
		},
		{
			name:       "parse and validation fails",
			authorizer: tlsconfig.AuthorizeAny(),
			bundle:     bundle2,
			err:        `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
			raw:        svid1Raw,
			wrapped:    wrapped,
		},
		{
			name:       "authorizer fails",
			authorizer: tlsconfig.AuthorizeMemberOf(td2),
			bundle:     bundle1,
			err:        `unexpected trust domain "domain1.test"`,
			raw:        svid1Raw,
			wrapped:    wrapped,
		},
		{
			name:       "wrapped is called",
			authorizer: tlsconfig.AuthorizeAny(),
			bundle:     bundle1,
			err:        "wrapped called",
			raw:        svid1Raw,
			wrapped:    wrapped,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			verifyPeerCertificate := tlsconfig.WrapVerifyPeerCertificate(testCase.wrapped, testCase.bundle, testCase.authorizer)
			require.NotNil(t, verifyPeerCertificate)

			err := verifyPeerCertificate(testCase.raw, [][]*x509.Certificate{})
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestTlsHandshake(t *testing.T) {
	// Create Bundle1
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)
	require.NotNil(t, bundle1)

	// Create SVID
	svid1ID := td.NewID("server")
	svid1Certs, key1 := ca1.CreateX509SVID(svid1ID.String())
	require.NotNil(t, svid1Certs)
	require.NotNil(t, key1)
	serverSVID := &x509svid.SVID{
		ID:           svid1ID,
		Certificates: svid1Certs,
		PrivateKey:   key1,
	}

	// Create Bundle2
	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)
	require.NotNil(t, bundle2)

	testCases := []struct {
		name         string
		serverConfig *tls.Config
		clientConfig *tls.Config
		err          string
	}{
		{
			name:         "success",
			serverConfig: tlsconfig.TLSServerConfig(serverSVID),
			clientConfig: tlsconfig.TLSClientConfig(bundle1, tlsconfig.AuthorizeAny()),
		},
		{
			name:         "invalid trust domain",
			serverConfig: tlsconfig.TLSServerConfig(serverSVID),
			clientConfig: tlsconfig.TLSClientConfig(bundle1, tlsconfig.AuthorizeMemberOf(td2)),
			err:          `unexpected trust domain "domain1.test"`,
		},
		{
			name:         "invalid bundle",
			serverConfig: tlsconfig.TLSServerConfig(serverSVID),
			clientConfig: tlsconfig.TLSClientConfig(bundle2, tlsconfig.AuthorizeMemberOf(td)),
			err:          `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testConnection(t, testCase.serverConfig, testCase.clientConfig, testCase.err)
		})
	}
}

func TestMTLSHandshake(t *testing.T) {
	// Create Bundle1
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)
	require.NotNil(t, bundle1)

	// Create Server SVID
	svid1ID := td.NewID("server")
	svid1Certs, key1 := ca1.CreateX509SVID(svid1ID.String())
	require.NotNil(t, svid1Certs)
	require.NotNil(t, key1)
	serverSVID := &x509svid.SVID{
		ID:           svid1ID,
		Certificates: append(svid1Certs, ca1.Roots()...),
		PrivateKey:   key1,
	}

	// Create Client SVID
	//svid2ID := td.NewID("client")
	//svid2Certs, key2 := ca1.CreateX509SVID(svid2ID.String())
	//require.NotNil(t, svid1Certs)
	//require.NotNil(t, key1)
	//clientSVID := &x509svid.SVID{
	//	ID:           svid2ID,
	//	Certificates: svid2Certs,
	//	PrivateKey:   key2,
	//}

	// Create Bundle2
	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)
	require.NotNil(t, bundle2)

	testCases := []struct {
		name         string
		serverConfig *tls.Config
		clientConfig *tls.Config
		err          string
	}{
		{
			name:         "success",
			serverConfig: tlsconfig.MTLSServerConfig(serverSVID, bundle1, tlsconfig.AuthorizeAny()),
			clientConfig: tlsconfig.MTLSClientConfig(serverSVID, bundle1, tlsconfig.AuthorizeAny()),
		},
		//{
		//	name:         "invalid trust domain",
		//	serverConfig: tlsconfig.TLSServerConfig(serverSVID),
		//	clientConfig: tlsconfig.TLSClientConfig(bundle1, tlsconfig.AuthorizeMemberOf(td2)),
		//	err:          `unexpected trust domain "domain1.test"`,
		//},
		//{
		//	name:         "invalid bundle",
		//	serverConfig: tlsconfig.TLSServerConfig(serverSVID),
		//	clientConfig: tlsconfig.TLSClientConfig(bundle2, tlsconfig.AuthorizeMemberOf(td)),
		//	err:          `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
		//},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testConnection(t, testCase.serverConfig, testCase.clientConfig, testCase.err)
		})
	}
}

func testConnection(t testing.TB, serverConfig *tls.Config, clientConfig *tls.Config, expectedErr string) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		require.NoError(t, err)
		defer conn.Close()

		r := bufio.NewReader(conn)

		msg, err := r.ReadString('\n')
		if err == nil {
			_, _ = conn.Write([]byte(msg + "done!\n"))
		}

	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if expectedErr != "" {
		if conn != nil {
			conn.Close()
		}
		require.EqualError(t, err, expectedErr)
		return
	}

	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("connection\n"))
	require.NoError(t, err)

	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	require.NoError(t, err)
	require.Contains(t, string(buf), "connection\ndone!\n")
}

type fakeSource struct {
	err  error
	svid *x509svid.SVID
}

func (f *fakeSource) GetX509SVID() (*x509svid.SVID, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.svid, nil
}
