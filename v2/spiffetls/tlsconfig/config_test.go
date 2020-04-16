package tlsconfig_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"strings"
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

func TestTLSClientConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)

	config := tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeAny())

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookTLSClientConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	base := createBaseTLSConfig()
	config := createTestTLSConfig(base)

	tlsconfig.HookTLSClientConfig(config, bundle, tlsconfig.AuthorizeAny())

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
	assertUnrelatedFieldsUntouched(t, base, config)
}

func TestMTLSClientConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}

	config := tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeAny())

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSClientConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}
	base := createBaseTLSConfig()
	config := createTestTLSConfig(base)

	tlsconfig.HookMTLSClientConfig(config, svid, bundle, tlsconfig.AuthorizeAny())

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.True(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
	assertUnrelatedFieldsUntouched(t, base, config)
}

func TestMTLSWebClientConfig(t *testing.T) {
	svid := &x509svid.SVID{}
	roots := x509.NewCertPool()

	config := tlsconfig.MTLSWebClientConfig(svid, roots)

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Equal(t, roots, config.RootCAs)
	assert.Nil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSWebClientConfig(t *testing.T) {
	svid := &x509svid.SVID{}
	base := createBaseTLSConfig()
	config := createTestTLSConfig(base)
	roots := x509.NewCertPool()

	tlsconfig.HookMTLSWebClientConfig(config, svid, roots)

	// Expected AuthFields
	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.NotNil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Equal(t, roots, config.RootCAs)
	assert.Nil(t, config.VerifyPeerCertificate)
	assertUnrelatedFieldsUntouched(t, base, config)
}

func TestTLSServerConfig(t *testing.T) {
	svid := &x509svid.SVID{}

	config := tlsconfig.TLSServerConfig(svid)

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.Nil(t, config.VerifyPeerCertificate)
}

func TestHookTLSServerConfig(t *testing.T) {
	svid := &x509svid.SVID{}
	base := createBaseTLSConfig()
	config := createTestTLSConfig(base)

	tlsconfig.HookTLSServerConfig(config, svid)

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.Nil(t, config.VerifyPeerCertificate)
	assertUnrelatedFieldsUntouched(t, base, config)
}

func TestMTLSServerConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}

	config := tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeAny())

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.RequireAnyClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSServerConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	svid := &x509svid.SVID{}
	base := createBaseTLSConfig()
	config := createTestTLSConfig(base)

	tlsconfig.HookMTLSServerConfig(config, svid, bundle, tlsconfig.AuthorizeAny())

	assert.Nil(t, config.Certificates)
	assert.Equal(t, tls.RequireAnyClientCert, config.ClientAuth)
	assert.NotNil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
	assertUnrelatedFieldsUntouched(t, base, config)
}

func TestMTLSWebServerConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	tlsCert := &tls.Certificate{Certificate: [][]byte{[]byte("body")}}

	config := tlsconfig.MTLSWebServerConfig(tlsCert, bundle, tlsconfig.AuthorizeAny())

	assert.Equal(t, []tls.Certificate{*tlsCert}, config.Certificates)
	assert.Equal(t, tls.RequireAnyClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
}

func TestHookMTLSWebServerConfig(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("test.domain")
	bundle := x509bundle.New(trustDomain)
	tlsCert := &tls.Certificate{Certificate: [][]byte{[]byte("body")}}
	base := createBaseTLSConfig()
	config := createTestTLSConfig(base)

	tlsconfig.HookMTLSWebServerConfig(config, tlsCert, bundle, tlsconfig.AuthorizeAny())

	assert.Equal(t, []tls.Certificate{*tlsCert}, config.Certificates)
	assert.Equal(t, tls.RequireAnyClientCert, config.ClientAuth)
	assert.Nil(t, config.GetCertificate)
	assert.Nil(t, config.GetClientCertificate)
	assert.False(t, config.InsecureSkipVerify)
	assert.Nil(t, config.NameToCertificate) //nolint:staticcheck // setting to nil is OK
	assert.Nil(t, config.RootCAs)
	assert.NotNil(t, config.VerifyPeerCertificate)
	assertUnrelatedFieldsUntouched(t, base, config)
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

	svid1, _ := ca1.CreateX509SVID(td.NewID("host").String())

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

	svid1, _ := ca1.CreateX509SVID(td.NewID("host").String())

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

func TestTLSHandshake(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)

	svid1ID := td.NewID("server")
	svid1Certs, key1 := ca1.CreateX509SVID(svid1ID.String())
	serverSVID := &x509svid.SVID{
		ID:           svid1ID,
		Certificates: svid1Certs,
		PrivateKey:   key1,
	}

	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)

	testCases := []struct {
		name         string
		serverConfig *tls.Config
		clientConfig *tls.Config
		clientErr    string
		serverErr    string
	}{
		{
			name:         "success",
			serverConfig: tlsconfig.TLSServerConfig(serverSVID),
			clientConfig: tlsconfig.TLSClientConfig(bundle1, tlsconfig.AuthorizeAny()),
		},
		{
			name:         "authentication fails",
			serverConfig: tlsconfig.TLSServerConfig(serverSVID),
			clientConfig: tlsconfig.TLSClientConfig(bundle1, tlsconfig.AuthorizeMemberOf(td2)),
			clientErr:    `unexpected trust domain "domain1.test"`,
			serverErr:    "remote error: tls: bad certificate",
		},
		{
			name:         "handshake fails",
			serverConfig: tlsconfig.TLSServerConfig(serverSVID),
			clientConfig: tlsconfig.TLSClientConfig(bundle2, tlsconfig.AuthorizeMemberOf(td)),
			clientErr:    `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
			serverErr:    "remote error: tls: bad certificate",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testConnection(t, testCase.serverConfig, testCase.clientConfig, testCase.serverErr, testCase.clientErr)
		})
	}
}

func TestMTLSHandshake(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)

	svid1ID := td.NewID("server")
	svid1Certs, key1 := ca1.CreateX509SVID(svid1ID.String())
	serverSVID := &x509svid.SVID{
		ID:           svid1ID,
		Certificates: svid1Certs,
		PrivateKey:   key1,
	}

	svid2ID := td.NewID("client")
	svid2Certs, key2 := ca1.CreateX509SVID(svid2ID.String())
	clientSVID := &x509svid.SVID{
		ID:           svid2ID,
		Certificates: svid2Certs,
		PrivateKey:   key2,
	}

	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)

	testCases := []struct {
		name         string
		serverConfig *tls.Config
		clientConfig *tls.Config
		serverErr    string
		clientErr    string
	}{
		{
			name:         "success",
			serverConfig: tlsconfig.MTLSServerConfig(serverSVID, bundle1, tlsconfig.AuthorizeAny()),
			clientConfig: tlsconfig.MTLSClientConfig(clientSVID, bundle1, tlsconfig.AuthorizeAny()),
		},
		{
			name:         "client authentication fails",
			serverConfig: tlsconfig.MTLSServerConfig(serverSVID, bundle1, tlsconfig.AuthorizeAny()),
			clientConfig: tlsconfig.MTLSClientConfig(clientSVID, bundle1, tlsconfig.AuthorizeMemberOf(td2)),
			clientErr:    `unexpected trust domain "domain1.test"`,
			serverErr:    "remote error: tls: bad certificate",
		},
		{
			name:         "client handshake fails",
			serverConfig: tlsconfig.MTLSServerConfig(serverSVID, bundle1, tlsconfig.AuthorizeAny()),
			clientConfig: tlsconfig.MTLSClientConfig(clientSVID, bundle2, tlsconfig.AuthorizeAny()),
			clientErr:    `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
			serverErr:    "remote error: tls: bad certificate",
		},
		{
			name:         "server authentication",
			serverConfig: tlsconfig.MTLSServerConfig(serverSVID, bundle1, tlsconfig.AuthorizeMemberOf(td2)),
			clientConfig: tlsconfig.MTLSClientConfig(clientSVID, bundle1, tlsconfig.AuthorizeAny()),
			clientErr:    "remote error: tls: bad certificate",
			serverErr:    `unexpected trust domain "domain1.test"`,
		},
		{
			name:         "server handshake fails",
			serverConfig: tlsconfig.MTLSServerConfig(serverSVID, bundle2, tlsconfig.AuthorizeAny()),
			clientConfig: tlsconfig.MTLSClientConfig(clientSVID, bundle1, tlsconfig.AuthorizeAny()),
			clientErr:    "remote error: tls: bad certificate",
			serverErr:    `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testConnection(t, testCase.serverConfig, testCase.clientConfig, testCase.serverErr, testCase.clientErr)
		})
	}
}

func TestMTLSWebHandshake(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t)
	bundle1 := ca1.Bundle(td)

	svid1ID := td.NewID("server")
	svid1Certs, _ := ca1.CreateX509SVID(svid1ID.String())

	roots, tlsCert := createWebCredentials(t)
	roots2 := x509.NewCertPool()
	roots2.AddCert(svid1Certs[0])

	svid2ID := td.NewID("client")
	svid2Certs, key2 := ca1.CreateX509SVID(svid2ID.String())
	clientSVID := &x509svid.SVID{
		ID:           svid2ID,
		Certificates: svid2Certs,
		PrivateKey:   key2,
	}

	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(td2)

	testCases := []struct {
		name         string
		clientConfig *tls.Config
		clientErr    string
		serverConfig *tls.Config
		serverErr    string
	}{
		{
			name:         "success",
			clientConfig: tlsconfig.MTLSWebClientConfig(clientSVID, roots),
			serverConfig: tlsconfig.MTLSWebServerConfig(tlsCert, bundle1, tlsconfig.AuthorizeAny()),
		},
		{
			name:         "server authentication fails",
			clientConfig: tlsconfig.MTLSWebClientConfig(clientSVID, roots),
			clientErr:    "remote error: tls: bad certificate",
			serverConfig: tlsconfig.MTLSWebServerConfig(tlsCert, bundle1, tlsconfig.AuthorizeMemberOf(td2)),
			serverErr:    `unexpected trust domain "domain1.test"`,
		},
		{
			name:         "server handshake fails",
			clientConfig: tlsconfig.MTLSWebClientConfig(clientSVID, roots),
			clientErr:    "remote error: tls: bad certificate",
			serverConfig: tlsconfig.MTLSWebServerConfig(tlsCert, bundle2, tlsconfig.AuthorizeMemberOf(td2)),
			serverErr:    `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
		},
		{
			name:         "client no valid certificate",
			clientConfig: tlsconfig.MTLSWebClientConfig(clientSVID, roots2),
			clientErr:    "x509: certificate signed by unknown authority",
			serverConfig: tlsconfig.MTLSWebServerConfig(tlsCert, bundle1, tlsconfig.AuthorizeAny()),
			serverErr:    "remote error: tls: bad certificate",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testConnection(t, testCase.serverConfig, testCase.clientConfig, testCase.serverErr, testCase.clientErr)
		})
	}
}

func createWebCredentials(t testing.TB) (*x509.CertPool, *tls.Certificate) {
	now := time.Now()
	serial := test.NewSerial(t)

	rootKey := test.NewEC256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("CA %x", serial),
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
	}
	rootCert := test.CreateCertificate(t, tmpl, tmpl, rootKey.Public(), rootKey)
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	childKey := test.NewEC256Key(t)
	tmpl = &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		},
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	childCert := test.CreateCertificate(t, tmpl, rootCert, childKey.Public(), rootKey)
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{childCert.Raw},
		PrivateKey:  childKey,
	}

	return certPool, tlsCert
}

func testConnection(t testing.TB, serverConfig *tls.Config, clientConfig *tls.Config, serverErr string, clientErr string) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	defer ln.Close()

	errCh := make(chan error, 1)
	defer func() {
		err := <-errCh
		if serverErr != "" {
			require.EqualError(t, err, serverErr)
			return
		}
		require.NoError(t, err)
	}()
	go func() {
		errCh <- func() error {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()

			buf := make([]byte, 1)
			if _, err = conn.Read(buf); err != nil {
				return err
			}

			_, err = conn.Write([]byte{2})
			return err
		}()
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	// Only expecting errors on client when a remote error is expected on server side
	if clientErr != "" && serverErr == "remote error: tls: bad certificate" {
		if conn != nil {
			conn.Close()
		}
		require.EqualError(t, err, clientErr)
		return
	}

	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{1})
	require.NoError(t, err)

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if clientErr != "" {
		require.EqualError(t, err, clientErr)
		return
	}
	require.NoError(t, err)
	require.Equal(t, buf, []byte{2})
}

func createTestTLSConfig(base *tls.Config) *tls.Config {
	tlsCert := tls.Certificate{Certificate: [][]byte{[]byte("body")}}
	return &tls.Config{
		Rand:                        base.Rand,
		Time:                        base.Time,
		GetConfigForClient:          base.GetConfigForClient,
		NextProtos:                  base.NextProtos,
		ServerName:                  base.ServerName,
		ClientCAs:                   base.ClientCAs,
		CipherSuites:                base.CipherSuites,
		PreferServerCipherSuites:    base.PreferServerCipherSuites, //nolint:gosec // setting to true is OK, for this test
		SessionTicketsDisabled:      base.SessionTicketsDisabled,
		SessionTicketKey:            base.SessionTicketKey,
		ClientSessionCache:          base.ClientSessionCache,
		MinVersion:                  base.MinVersion,
		MaxVersion:                  base.MaxVersion,
		CurvePreferences:            base.CurvePreferences,
		DynamicRecordSizingDisabled: base.DynamicRecordSizingDisabled,
		Renegotiation:               base.Renegotiation,
		KeyLogWriter:                base.KeyLogWriter,
		// Auth fields
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
		InsecureSkipVerify:    false,
		ClientAuth:            tls.RequestClientCert,
	}
}

func createBaseTLSConfig() *tls.Config {
	return &tls.Config{
		Rand: strings.NewReader("my rand"),
		Time: time.Now().Add(-time.Minute).UTC,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (config *tls.Config, err error) {
			return nil, nil
		},
		NextProtos:                  []string{"nextProtos"},
		ServerName:                  "Server1",
		ClientCAs:                   x509.NewCertPool(),
		CipherSuites:                []uint16{12},
		PreferServerCipherSuites:    true, //nolint:gosec // setting to true is OK, for this test
		SessionTicketsDisabled:      true,
		SessionTicketKey:            [32]byte{32},
		ClientSessionCache:          tls.NewLRUClientSessionCache(32),
		MinVersion:                  999, //nolint:gosec // setting to 999 is OK, for this test
		MaxVersion:                  999,
		CurvePreferences:            []tls.CurveID{tls.CurveP256},
		DynamicRecordSizingDisabled: true,
		Renegotiation:               32,
		KeyLogWriter:                &bytes.Buffer{},
	}
}

func assertUnrelatedFieldsUntouched(t testing.TB, base, wrapped *tls.Config) {
	assert.Equal(t, base.Rand, wrapped.Rand)
	assert.NotNil(t, wrapped.Time)
	assert.NotNil(t, wrapped.GetConfigForClient)
	assert.Equal(t, base.NextProtos, wrapped.NextProtos)
	assert.Equal(t, base.ServerName, wrapped.ServerName)
	assert.Equal(t, base.ClientCAs, wrapped.ClientCAs)
	assert.Equal(t, base.CipherSuites, wrapped.CipherSuites)
	assert.Equal(t, base.PreferServerCipherSuites, wrapped.PreferServerCipherSuites)
	assert.Equal(t, base.SessionTicketsDisabled, wrapped.SessionTicketsDisabled)
	assert.Equal(t, base.SessionTicketKey, wrapped.SessionTicketKey)
	assert.Equal(t, base.ClientSessionCache, wrapped.ClientSessionCache)
	assert.Equal(t, base.MinVersion, wrapped.MinVersion)
	assert.Equal(t, base.MaxVersion, wrapped.MaxVersion)
	assert.Equal(t, base.CurvePreferences, wrapped.CurvePreferences)
	assert.Equal(t, base.DynamicRecordSizingDisabled, wrapped.DynamicRecordSizingDisabled)
	assert.Equal(t, base.Renegotiation, wrapped.Renegotiation)
	assert.Equal(t, base.KeyLogWriter, wrapped.KeyLogWriter)
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
