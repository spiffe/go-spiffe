package spiffex509

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Roots represents a set of X.509 roots, keyed by trust domain.
type Roots struct{}

// NewRoots returns an empty set of roots.
func NewRoots() *Roots {
	panic("not implemented")
}

// Insert inserts or replaces the X.509 roots for the given trust domain.
func (r *Roots) Insert(trustDomain spiffeid.TrustDomain, rootCerts []*x509.Certificate) {
	panic("not implemented")
}

// Remove removes the X.509 roots for the given trust domain. It returns true
// if the trust domain had roots in the set to remove.
func (r *Roots) Remove(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

// Has returns true if the trust domain has roots in the set.
func (r *Roots) Has(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

// GetX509RootsForTrustDomain returns the roots for the given trust domain or
// an error if the roots do not exist, conforming to the RootStore interface.
func (r *Roots) GetX509RootsForTrustDomain(trustDomain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	panic("not implemented")
}
