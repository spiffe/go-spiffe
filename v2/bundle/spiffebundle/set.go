package spiffebundle

import (
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Set is a set of bundles, keyed by trust domain.
type Set struct{}

// NewSet creates a new set initialized with the given bundles.
func NewSet(bundles ...*Bundle) *Set {
	panic("not implemented")
}

// Add adds a new bundle into the set. If a bundle already exists for the
// trust domain, the existing bundle is replaced.
func (s *Set) Add(bundle *Bundle) {
	panic("not implemented")
}

// Remove removes the bundle for the given trust domain.
func (s *Set) Remove(trustDomain spiffeid.TrustDomain) {
	panic("not implemented")
}

// Has returns true if there is a bundle for the given trust domain.
func (s *Set) Has(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the Source interface.
func (s *Set) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	panic("not implemented")
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *Set) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	panic("not implemented")
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
func (s *Set) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	panic("not implemented")
}
