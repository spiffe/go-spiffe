package spiffex509

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// RootStore is an interface used to locate the set of X.509 roots for a
// trust domain.
type RootStore interface {
	// GetX509RootsForTrustDomain returns the roots for the given trust domain
	// or an error if the roots do not exist
	GetX509RootsForTrustDomain(trustDomain spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

// VerifyChain verifies the given X509-SVID chain using the root store.
func VerifyChain(svidCerts []*x509.Certificate, roots RootStore) (*SVID, error) {
	panic("not implemented")
}

// ParseAndVerifyChain parses the and verifies the given X509-SVID chain using
// the root store.
func ParseAndVerifyChain(certs [][]byte, roots RootStore) (*SVID, error) {
	panic("not implemented")
}
