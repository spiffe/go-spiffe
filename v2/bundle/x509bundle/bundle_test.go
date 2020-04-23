package x509bundle_test

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	bundle := x509bundle.New(spiffeid.RequireTrustDomainFromString("example.org"))
	require.NotNil(t, bundle)
	assert.Len(t, bundle.X509Authorities(), 0)
	assert.Equal(t, spiffeid.RequireTrustDomainFromString("example.org"), bundle.TrustDomain())
}

func TestFromX509Authorities(t *testing.T) {
	x509Cert1 := &x509.Certificate{
		Raw: []byte("CERT 1"),
	}
	x509Cert2 := &x509.Certificate{
		Raw: []byte("CERT 2"),
	}

	x509Authorities := []*x509.Certificate{x509Cert1, x509Cert2}
	b := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.org"), x509Authorities)
	require.NotNil(t, b)
	assert.Equal(t, b.X509Authorities(), x509Authorities)
}

func TestLoad_Succeeds(t *testing.T) {
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example.org"), "testdata/certs.pem")
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Len(t, bundle.X509Authorities(), 2)
}

func TestLoad_Fails(t *testing.T) {
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example.org"), "testdata/non-existent-file.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "x509bundle: unable to load X.509 bundle file")
	assert.Nil(t, bundle)
}

func TestRead_Succeeds(t *testing.T) {
	file, err := os.Open("testdata/certs.pem")
	require.NoError(t, err)
	defer file.Close()

	bundle, err := x509bundle.Read(spiffeid.RequireTrustDomainFromString("example.org"), file)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Len(t, bundle.X509Authorities(), 2)
}

func TestRead_Fails(t *testing.T) {
	file, err := os.Open("testdata/certs.pem")
	require.NoError(t, err)

	// Close file prematurely to cause an error while reading
	file.Close()

	bundle, err := x509bundle.Read(spiffeid.RequireTrustDomainFromString("example.org"), file)
	require.Error(t, err)
	require.Contains(t, err.Error(), "x509bundle: unable to read")
	assert.Nil(t, bundle)
}

func TestParse(t *testing.T) {
	tests := []struct {
		name              string
		trustDomain       spiffeid.TrustDomain
		path              string
		expNumAuthorities int
		expErrContains    string
	}{
		{
			name:              "Parse multiple certificates should succeed",
			path:              "testdata/certs.pem",
			expNumAuthorities: 2,
		},
		{
			name:              "Parse single certificate should succeed",
			path:              "testdata/cert.pem",
			expNumAuthorities: 1,
		},
		{
			name:           "Parse empty bytes should fail",
			path:           "testdata/empty.pem",
			expErrContains: "x509bundle: no certificates found",
		},
		{
			name:           "Parse non-PEM bytes should fail",
			path:           "testdata/not-pem.pem",
			expErrContains: "x509bundle: cannot parse certificate: no PEM data found while decoding block",
		},
		{
			name:           "Parse should fail if no certificate block is is found",
			path:           "testdata/key.pem",
			expErrContains: "x509bundle: no certificates found",
		},
		{
			name:           "Parse a corrupted certificate should fail",
			path:           "testdata/corrupted.pem",
			expErrContains: "x509bundle: cannot parse certificate",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fileBytes, err := ioutil.ReadFile(test.path)
			require.NoError(t, err)

			bundle, err := x509bundle.Parse(spiffeid.RequireTrustDomainFromString("example.org"), fileBytes)
			if test.expErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expErrContains)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, bundle)
			assert.Len(t, bundle.X509Authorities(), test.expNumAuthorities)
		})
	}
}

func TestX509AuthorityCRUD(t *testing.T) {
	// Load bundle1, which contains a single certificate
	bundle1, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example-1.org"), "testdata/cert.pem")
	require.NoError(t, err)
	assert.Len(t, bundle1.X509Authorities(), 1)

	// Load bundle2, which contains 2 certificates
	// The first certificate is the same than the one used in bundle1
	bundle2, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example-2.org"), "testdata/certs.pem")
	require.NoError(t, err)
	assert.Len(t, bundle2.X509Authorities(), 2)
	assert.True(t, bundle2.HasX509Authority(bundle1.X509Authorities()[0]))

	// Adding a new authority increases the x509Authorities slice length
	bundle1.AddX509Authority(bundle2.X509Authorities()[1])
	assert.Len(t, bundle1.X509Authorities(), 2)
	assert.True(t, bundle1.HasX509Authority(bundle2.X509Authorities()[0]))
	assert.True(t, bundle1.HasX509Authority(bundle2.X509Authorities()[1]))

	// If the authority already exist, it should not be added again
	bundle1.AddX509Authority(bundle2.X509Authorities()[0])
	bundle1.AddX509Authority(bundle2.X509Authorities()[1])
	assert.Len(t, bundle1.X509Authorities(), 2)
	assert.True(t, bundle1.HasX509Authority(bundle2.X509Authorities()[0]))
	assert.True(t, bundle1.HasX509Authority(bundle2.X509Authorities()[1]))

	// Removing an authority, decreases the authority slice length
	cert := bundle1.X509Authorities()[0]
	bundle1.RemoveX509Authority(cert)
	assert.Len(t, bundle1.X509Authorities(), 1)
	assert.False(t, bundle1.HasX509Authority(cert))

	// If the authority does not exist, it should keep its size
	bundle1.RemoveX509Authority(cert)
	assert.Len(t, bundle1.X509Authorities(), 1)
	assert.False(t, bundle1.HasX509Authority(cert))
}

func TestMarshal(t *testing.T) {
	// Load a bundle to marshal
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example.org"), "testdata/certs.pem")
	require.NoError(t, err)

	// Marshal the bundle
	pemBytes, err := bundle.Marshal()
	require.NoError(t, err)
	require.NotNil(t, pemBytes)

	// Load original bytes for comparison
	expBytes, err := ioutil.ReadFile("testdata/certs.pem")
	require.NoError(t, err)

	//Assert the marshalled bundle is equal to the one loaded
	assert.Equal(t, expBytes, pemBytes)
}

func TestGetX509BundleForTrustDomain_Succeeds(t *testing.T) {
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example.org"), "testdata/certs.pem")
	require.NoError(t, err)

	b, err := bundle.GetX509BundleForTrustDomain(spiffeid.RequireTrustDomainFromString("example.org"))
	require.NoError(t, err)
	require.NotNil(t, b)
	require.Equal(t, bundle, b)
}

func TestGetX509BundleForTrustDomain_Fails(t *testing.T) {
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("example.org"), "testdata/certs.pem")
	require.NoError(t, err)

	b, err := bundle.GetX509BundleForTrustDomain(spiffeid.RequireTrustDomainFromString("another-td.org"))
	require.Error(t, err)
	require.Contains(t, err.Error(), `x509bundle: no X.509 bundle found for trust domain: "another-td.org"`)
	require.Nil(t, b)
}
