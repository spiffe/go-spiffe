package spiffex509

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// RootStore is an interface used to locate the public key for a signed JWT-SVID
type RootStore interface {
	GetX509RootsForTrustDomain(trustDomain spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

// ParseAndVerify parses the x509 certificates
func VerifyChain(svidChain []*x509.Certificate, roots RootStore) (*SVID, error) {
	panic("not implemented")
}

// ParseAndVerifyChain parses and verifies chain of certificates
func ParseAndVerifyChain(svidChain [][]byte, roots RootStore) (*SVID, error) {
	panic("not implemented")
}
