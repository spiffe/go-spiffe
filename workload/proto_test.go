package workload

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/require"
)

func TestProtoToX509SVIDs(t *testing.T) {
	domain1CA := spiffetest.NewCA(t)
	domain1Inter := domain1CA.CreateCA()
	domain1Bundle := domain1CA.Roots()

	// Create an SVID with the intermediate. It should return two certs in the
	// chain; one for the svid, and one for the intermediate.
	svidChain, svidKey := domain1Inter.CreateX509SVID("spiffe://domain1.test/workload")
	require.Len(t, svidChain, 2)
	svids := []spiffetest.X509SVID{
		{
			CertChain: svidChain,
			Key:       svidKey,
		},
	}

	domain2CA := spiffetest.NewCA(t)
	domain3CA := spiffetest.NewCA(t)

	testCases := []struct {
		name string
		resp *spiffetest.X509SVIDResponse
		err  string
	}{
		{
			name: "no svids",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
			},
			err: "workload response contains no svids",
		},
		{
			name: "bad federated bundle",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs:  svids,
				FederatedBundles: map[string][]*x509.Certificate{
					"spiffe://baddomain.test": {{Raw: []byte{0}}},
				},
			},
			err: `failed to parse bundle for federated domain "spiffe://baddomain.test": asn1: syntax error: truncated tag or length`,
		},
		{
			name: "federated bundle with no certs",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs:  svids,
				FederatedBundles: map[string][]*x509.Certificate{
					"spiffe://baddomain.test": {},
				},
			},
			err: `no certificates in bundle for federated domain "spiffe://baddomain.test"`,
		},
		{
			name: "svid has bad certs",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs: []spiffetest.X509SVID{
					{
						CertChain: []*x509.Certificate{{Raw: []byte{0}}},
						Key:       svidKey,
					},
				},
			},
			err: `failed to parse svid entry 0 for spiffe id "": asn1: syntax error: truncated tag or length`,
		},
		{
			name: "svid has no certs",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs: []spiffetest.X509SVID{
					{
						Key: svidKey,
					},
				},
			},
			err: `failed to parse svid entry 0 for spiffe id "": no certificates found`,
		},
		{
			name: "svid has no private key",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs: []spiffetest.X509SVID{
					{
						CertChain: svidChain,
					},
				},
			},
			err: `failed to parse svid entry 0 for spiffe id "spiffe://domain1.test/workload": failed to parse private key: asn1: syntax error: sequence truncated`,
		},
		{
			name: "svid has empty bundle",
			resp: &spiffetest.X509SVIDResponse{
				SVIDs: svids,
			},
			err: `failed to parse svid entry 0 for spiffe id "spiffe://domain1.test/workload": no certificates in trust bundle`,
		},
		{
			name: "svid has bad bundle",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: []*x509.Certificate{{Raw: []byte{0}}},
				SVIDs:  svids,
			},
			err: `failed to parse svid entry 0 for spiffe id "spiffe://domain1.test/workload": failed to parse trust bundle: asn1: syntax error: truncated tag or length`,
		},
		{
			name: "success",
			resp: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs:  svids,
				FederatedBundles: map[string][]*x509.Certificate{
					"spiffe://domain2.test": domain2CA.Roots(),
					"spiffe://domain3.test": domain3CA.Roots(),
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			out, err := protoToX509SVIDs(testCase.resp.ToProto(t))
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)

			// CRL is always NIL for now
			require.Nil(t, out.CRL, 1)

			require.Len(t, out.SVIDs, len(testCase.resp.SVIDs))
			for i, svidOut := range out.SVIDs {
				svidIn := testCase.resp.SVIDs[i]
				require.Equal(t, svidIn.Key, svidOut.PrivateKey)
				require.Equal(t, svidIn.CertChain, svidOut.Certificates)
				require.Equal(t, testCase.resp.Bundle, svidOut.TrustBundle)
				require.Equal(t, svidIn.CertChain[0].URIs[0].String(), svidOut.SPIFFEID)
				require.Equal(t, testCase.resp.FederatedBundles, svidOut.FederatedTrustBundles)
				require.Len(t, svidOut.FederatedTrustBundlePools, len(testCase.resp.FederatedBundles))
			}
		})
	}
}
