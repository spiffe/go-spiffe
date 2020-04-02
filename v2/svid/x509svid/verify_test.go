package x509svid_test

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	ca1 := test.NewCA(t)
	leaf1, _ := ca1.CreateX509SVID("spiffe://domain1.test/workload")
	leaf1NoURI := removeURIs(leaf1[0])
	leaf1DupUris := dupURIs(leaf1[0])
	leaf1IsCA := setIsCA(leaf1[0])
	leaf1WithCertSign := appendKeyUsage(leaf1[0], x509.KeyUsageCertSign)
	leaf1WithCRLSign := appendKeyUsage(leaf1[0], x509.KeyUsageCRLSign)
	bundle1 := ca1.Bundle(spiffeid.RequireTrustDomainFromString("spiffe://domain1.test"))

	ca2 := test.NewCA(t)
	bundle2 := ca2.Bundle(spiffeid.RequireTrustDomainFromString("spiffe://domain2.test"))

	// bad leaf cert... invalid spiffe ID
	leafBad, _ := ca1.CreateX509SVID("sparfe://domain1.test/workload")
	// bad set of roots... sets roots for ca2 under domain1.test
	bundleBad := ca2.Bundle(spiffeid.RequireTrustDomainFromString("spiffe://domain1.test"))

	testCases := []struct {
		name       string
		chain      []*x509.Certificate
		bundle     x509bundle.Source
		expectedID spiffeid.ID
		err        string
	}{
		{
			name:   "empty chain",
			bundle: bundle1,
			err:    "x509svid: empty certificates chain",
		},
		{
			name:   "empty bundle",
			chain:  leaf1,
			err:    "x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: \"domain1.test\"",
			bundle: &x509bundle.Bundle{},
		},
		{
			name:  "nil bundle",
			chain: leaf1,
			err:   "x509svid: bundleSource is required",
		},
		{
			name:   "no roots",
			chain:  leaf1,
			err:    "x509svid: could not verify leaf certificate: x509: certificate signed by unknown authority",
			bundle: x509bundle.New(spiffeid.RequireTrustDomainFromString("domain1.test")),
		},
		{
			name:   "no roots for leaf cert domain",
			chain:  leaf1,
			bundle: bundle2,
			err:    `x509svid: could not get X509 bundle: x509bundle: no X.509 bundle found for trust domain: "domain1.test"`,
		},
		{
			name:   "bad leaf cert id",
			chain:  leafBad,
			bundle: bundle1,
			err:    "x509svid: could not get leaf SPIFFE ID: spiffeid: invalid scheme",
		},
		{
			name:   "verification fails",
			chain:  leaf1,
			bundle: bundleBad,
			err:    "x509svid: could not verify leaf certificate: x509: certificate signed by unknown authority",
		},
		{
			name:   "no URI SAN",
			chain:  leaf1NoURI,
			bundle: bundle1,
			err:    "x509svid: could not get leaf SPIFFE ID: certificate contains no URI SAN",
		},
		{
			name:   "more than one URI SAN",
			chain:  leaf1DupUris,
			bundle: bundle1,
			err:    "x509svid: could not get leaf SPIFFE ID: certificate contains more than one URI SAN",
		},
		{
			name:   "leaf is CA",
			chain:  leaf1IsCA,
			bundle: bundle1,
			err:    "x509svid: leaf certificate with CA flag set to true",
		},
		{
			name:   "leaf has KeyUsageCertSign",
			chain:  leaf1WithCertSign,
			bundle: bundle1,
			err:    "x509svid: leaf certificate with KeyCertSign key usage",
		},
		{
			name:   "leaf has KeyUsageCRLSign",
			chain:  leaf1WithCRLSign,
			bundle: bundle1,
			err:    "x509svid: leaf certificate with KeyCrlSign key usage",
		},
		{
			name:   "success",
			chain:  leaf1,
			bundle: bundle1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase // alias loop var as it is used in the closure
		t.Run(testCase.name, func(t *testing.T) {
			_, verifiedChains, err := x509svid.Verify(testCase.chain, testCase.bundle)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, verifiedChains)
		})
	}
}

func TestParseAndVerify(t *testing.T) {
	ca1 := test.NewCA(t)
	leaf1, _ := ca1.CreateX509SVID("spiffe://domain1.test/workload")
	bundle1 := ca1.Bundle(spiffeid.RequireTrustDomainFromString("spiffe://domain1.test"))

	rawLeaf := leaf1[0].Raw
	_, verifiedChains, err := x509svid.ParseAndVerify([][]byte{rawLeaf}, bundle1)
	require.NoError(t, err)
	require.NotNil(t, verifiedChains)

	// We modify some byte to make the parsing fail.
	rawLeaf[0] = 0x27
	_, verifiedChains, err = x509svid.ParseAndVerify([][]byte{rawLeaf}, bundle1)
	require.Contains(t, err.Error(), "x509svid: unable to parse certificate")
	require.Nil(t, verifiedChains)
}

func removeURIs(cert *x509.Certificate) []*x509.Certificate {
	c := *cert
	c.URIs = []*url.URL{}
	return []*x509.Certificate{&c}
}

func dupURIs(cert *x509.Certificate) []*x509.Certificate {
	c := *cert
	c.URIs = append(c.URIs, c.URIs...)
	return []*x509.Certificate{&c}
}

func setIsCA(cert *x509.Certificate) []*x509.Certificate {
	c := *cert
	c.IsCA = true
	return []*x509.Certificate{&c}
}

func appendKeyUsage(cert *x509.Certificate, ku x509.KeyUsage) []*x509.Certificate {
	c := *cert
	c.KeyUsage |= ku
	return []*x509.Certificate{&c}
}
