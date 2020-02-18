package spiffebundle

import (
	"crypto"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Set is a set of bundles, keyed by trust domain.
type Set struct{}

// NewSet creates a new, empty set.
func NewSet() *Set {
	panic("not implemented")
}

// Insert inserts a new bundle into the set. If a bundle already exists for the
// trust domain, the existing bundle is replaced.
func (set *Set) Insert(trustDomain spiffeid.TrustDomain, bundle *Bundle) {
	panic("not implemented")
}

// Remove removes the bundle specified by the trust domain. True is returned
// if the bundle is present (and removed), otherwise false.
func (set *Set) Remove(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

// Has returns true if there is a bundle for the specified trust domain.
func (set *Set) Has(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

// GetX509RootsForTrustDomain gets the X509 roots for the specified trust
// domain. It implements the spiffex509.RootStore interface.
func (set *Set) GetX509RootsForTrustDomain(trustDomain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	panic("not implemented")
}

// GetJWTKeyForTrustDomain returns the JWT key for the specified key ID in the
// trust domain. It implements the spiffejwt.KeyStore interface.
func (set *Set) GetJWTKeyForTrustDomain(trustDomain spiffeid.TrustDomain, keyID string) (crypto.PublicKey, error) {
	panic("not implemented")
}
