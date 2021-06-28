package spiffe

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/require"
)

func TestVerifyPeerCertificate(t *testing.T) {
	ca1 := spiffetest.NewCA(t)
	peer1, _ := ca1.CreateX509SVID("spiffe://domain1.test/workload")
	roots1 := map[string]*x509.CertPool{
		"spiffe://domain1.test": ca1.RootsPool(),
	}

	ca2 := spiffetest.NewCA(t)
	roots2 := map[string]*x509.CertPool{
		"spiffe://domain2.test": ca2.RootsPool(),
	}

	// bad peer... invalid spiffe ID
	peerBad, _ := ca1.CreateX509SVID("sparfe://domain1.test/workload")
	// bad set of roots... sets roots for ca2 under domain1.test
	rootsBad := map[string]*x509.CertPool{
		"spiffe://domain1.test": ca2.RootsPool(),
	}

	testCases := []struct {
		name   string
		chain  []*x509.Certificate
		roots  map[string]*x509.CertPool
		expect ExpectPeerFunc
		err    string
	}{
		{
			name:   "empty chain",
			roots:  roots1,
			expect: ExpectAnyPeer(),
			err:    "no peer certificates",
		},
		{
			name:   "no roots",
			chain:  peer1,
			expect: ExpectAnyPeer(),
			err:    "at least one trust domain root is required",
		},
		{
			name:  "no expect peer callback",
			chain: peer1,
			roots: roots1,
			err:   "expectPeerFn callback is required",
		},
		{
			name:   "no roots for peer domain",
			chain:  peer1,
			roots:  roots2,
			expect: ExpectAnyPeer(),
			err:    `no roots for peer trust domain "spiffe://domain1.test"`,
		},
		{
			name:   "fails peer id expectation",
			chain:  peer1,
			roots:  roots1,
			expect: ExpectPeer("spiffe://domain2.test/workload"),
			err:    `unexpected peer ID "spiffe://domain1.test/workload": expected "spiffe://domain2.test/workload"`,
		},
		{
			name:   "bad peer id",
			chain:  peerBad,
			roots:  roots1,
			expect: ExpectAnyPeer(),
			err:    "invalid SPIFFE ID \"sparfe://domain1.test/workload\": invalid scheme",
		},
		{
			name:   "verification fails",
			chain:  peer1,
			roots:  rootsBad,
			expect: ExpectAnyPeer(),
			err:    "x509: certificate signed by unknown authority",
		},
		{
			name:   "success",
			chain:  peer1,
			roots:  roots1,
			expect: ExpectAnyPeer(),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			verifiedChains, err := VerifyPeerCertificate(testCase.chain, testCase.roots, testCase.expect)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, verifiedChains)
		})
	}
}
