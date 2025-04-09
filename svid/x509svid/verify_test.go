package x509svid_test

import (
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	td1 := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t, td1)
	leaf1 := ca1.CreateX509SVID(spiffeid.RequireFromPath(td1, "/workload")).Certificates
	leaf1NoURI := removeURIs(leaf1[0])
	leaf1DupUris := dupURIs(leaf1[0])
	leaf1IsCA := setIsCA(leaf1[0])
	leaf1WithCertSign := appendKeyUsage(leaf1[0], x509.KeyUsageCertSign)
	leaf1WithCRLSign := appendKeyUsage(leaf1[0], x509.KeyUsageCRLSign)
	bundle1 := ca1.X509Bundle()

	td2 := spiffeid.RequireTrustDomainFromString("spiffe://domain2.test")
	ca2 := test.NewCA(t, td2)
	bundle2 := ca2.X509Bundle()

	// bad leaf cert... invalid spiffe ID
	leafBad, _ := ca1.CreateX509Certificate(test.WithURIs(&url.URL{Scheme: "sparfe", Host: "domain1.test", Path: "/workload"}))
	// bad set of roots... sets roots for ca2 under domain1.test
	bundleBad := spiffebundle.FromX509Authorities(td1, bundle2.X509Authorities())

	testCases := []struct {
		name       string
		chain      []*x509.Certificate
		bundle     x509bundle.Source
		opts       []x509svid.VerifyOption
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
			err:    `x509svid: could not get leaf SPIFFE ID: scheme is missing or invalid`,
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
			name:   "with time",
			chain:  leaf1,
			bundle: bundle1,
			opts:   []x509svid.VerifyOption{x509svid.WithTime(leaf1[0].NotAfter.Add(time.Second))},
			err:    "x509svid: could not verify leaf certificate: x509: certificate has expired",
		},
		{
			name:   "success",
			chain:  leaf1,
			bundle: bundle1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, verifiedChains, err := x509svid.Verify(testCase.chain, testCase.bundle, testCase.opts...)
			if testCase.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, verifiedChains)
		})
	}
}

func TestParseAndVerify(t *testing.T) {
	td1 := spiffeid.RequireTrustDomainFromString("domain1.test")
	ca1 := test.NewCA(t, td1)
	leaf1 := ca1.CreateX509SVID(spiffeid.RequireFromPath(td1, "/workload")).Certificates
	bundle1 := ca1.X509Bundle()

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
