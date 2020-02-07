package x509bundle

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Set is a set of bundles, keyed by trust domain.
type Set struct{}

// NewSet creates a new, empty set.
func NewSet(bundles ...*Bundle) *Set {
	panic("not implemented")
}

// Add add a new bundle into the set. If a bundle already exists for the
// trust domain, the existing bundle is replaced.
func (s *Set) Add(bundle *Bundle) {
	panic("not implemented")
}

// Remove removes the bundle given by the trust domain.
func (s *Set) Remove(trustDomain spiffeid.TrustDomain) {
	panic("not implemented")
}

// Has returns true if there is a bundle for the given trust domain.
func (s *Set) Has(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the Source interface.
func (s *Set) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	panic("not implemented")
}
