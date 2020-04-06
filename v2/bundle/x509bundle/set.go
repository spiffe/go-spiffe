package x509bundle

import (
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Set is a set of bundles, keyed by trust domain.
type Set struct {
	mtx     sync.RWMutex
	bundles map[spiffeid.TrustDomain]*Bundle
}

// NewSet creates a new set initialized with the given bundles.
func NewSet(bundles ...*Bundle) *Set {
	bundlesMap := make(map[spiffeid.TrustDomain]*Bundle)

	for _, b := range bundles {
		if b != nil {
			bundlesMap[b.trustDomain] = b
		}
	}

	return &Set{
		bundles: bundlesMap,
	}
}

// Add adds a new bundle into the set. If a bundle already exists for the
// trust domain, the existing bundle is replaced.
func (s *Set) Add(bundle *Bundle) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if bundle != nil {
		s.bundles[bundle.trustDomain] = bundle
	}
}

// Remove removes the bundle for the given trust domain.
func (s *Set) Remove(trustDomain spiffeid.TrustDomain) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	delete(s.bundles, trustDomain)
}

// Has returns true if there is a bundle for the given trust domain.
func (s *Set) Has(trustDomain spiffeid.TrustDomain) bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	_, ok := s.bundles[trustDomain]
	return ok
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the Source interface.
func (s *Set) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	bundle, ok := s.bundles[trustDomain]
	if !ok {
		return nil, x509bundleErr.New("no X.509 bundle for trust domain %q", trustDomain)
	}

	return bundle, nil
}
