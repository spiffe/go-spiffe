package spiffe

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/require"
)

func TestVerifyPeerCertificateAttributes(t *testing.T) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name        string
		certificate *x509.Certificate
		err         string
	}{
		{
			name: "ca certificate",
			certificate: &x509.Certificate{
				IsCA: true,
			},
			err: "cannot validate peer which is a CA",
		},
		{
			name: "certificate with KeyCertSign",
			certificate: &x509.Certificate{
				KeyUsage: x509.KeyUsageCertSign,
			},
			err: "cannot validate peer with KeyCertSign key usage",
		},
		{
			name: "ca certificate",
			certificate: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
			},
			err: "cannot validate peer with KeyCrlSign key usage",
		},
		{
			name: "valid certificate",
			certificate: &x509.Certificate{
				SerialNumber: spiffetest.NewSerial(t),
				Subject: pkix.Name{
					CommonName: fmt.Sprintf("CA %x", serial),
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour),
				URIs: []*url.URL{
					{Scheme: "spiffe", Host: "domain1.com", Path: "/workload"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			err := verifyPeerCertificateAttributes(testCase.certificate)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

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
			err:    `unexpected peer ID "spiffe://domain1.test/workload"`,
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

func TestGetSpiffeIDFromCertificate(t *testing.T) {
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
		name     string
		spiffeID string
		chain    []*x509.Certificate
		roots    map[string]*x509.CertPool
		err      string
	}{
		{
			name:     "empty chain",
			roots:    roots1,
			spiffeID: "",
			err:      "no peer certificates",
		},
		{
			name:  "no roots",
			chain: peer1,
			err:   "at least one trust domain root is required",
		},
		{
			name:     "no roots for peer domain",
			chain:    peer1,
			roots:    roots2,
			spiffeID: "",
			err:      `no roots for peer trust domain "spiffe://domain1.test"`,
		},
		{
			name:     "root as peer",
			chain:    ca1.Roots(),
			roots:    roots1,
			spiffeID: "",
			err:      "cannot validate peer which is a CA",
		},
		{
			name:     "bad peer id",
			chain:    peerBad,
			roots:    roots1,
			spiffeID: "",
			err:      "invalid SPIFFE ID \"sparfe://domain1.test/workload\": invalid scheme",
		},
		{
			name:     "verification fails",
			chain:    peer1,
			roots:    rootsBad,
			spiffeID: "",
			err:      "x509: certificate signed by unknown authority",
		},
		{
			name:     "success",
			chain:    peer1,
			spiffeID: "spiffe://domain1.test/workload",
			roots:    roots1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			spiffeID, err := GetSpiffeIDFromX509(testCase.chain, testCase.roots)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				require.Empty(t, spiffeID)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.spiffeID, spiffeID)
		})
	}
}
