package workloadapi

import (
	"context"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

var bundlesourceErr = errs.Class("bundlesource")

// BundleSource is a source of SPIFFE bundles maintained via the Workload API.
type BundleSource struct {
	watcher *watcher

	mtx     sync.RWMutex
	bundles *spiffebundle.Set

	closeMtx sync.RWMutex
	closed   bool
}

// NewBundleSource creates a new BundleSource. It blocks until the initial
// update has been received from the Workload API.
func NewBundleSource(ctx context.Context, options ...BundleSourceOption) (_ *BundleSource, err error) {
	config := &bundleSourceConfig{}
	for _, option := range options {
		option.configureBundleSource(config)
	}

	s := &BundleSource{
		// Initialize the bundle set so that the merge code below has something
		// valid to merge into.
		bundles: spiffebundle.NewSet(),
	}

	s.watcher, err = newWatcher(ctx, config.watcher, s.setX509Context, s.setJWTBundles)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the BundleSource (i.e. not provided via the WithClient option).
func (s *BundleSource) Close() error {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the spiffebundle.Source interface.
func (s *BundleSource) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	return s.getBundles().GetBundleForTrustDomain(trustDomain)
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *BundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	return s.getBundles().GetX509BundleForTrustDomain(trustDomain)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
func (s *BundleSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	return s.getBundles().GetJWTBundleForTrustDomain(trustDomain)
}

func (s *BundleSource) getBundles() *spiffebundle.Set {
	s.mtx.RLock()
	bundles := s.bundles
	s.mtx.RUnlock()
	return bundles
}

func (s *BundleSource) setX509Context(x509Context *X509Context) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	newBundles := x509Context.Bundles.Bundles()

	// Add/replace the X.509 content in the SPIFFE bundles. Track the trust
	// domains represented in the new X.509 context so we can determine if
	// which existing bundles need their X.509 content removed.
	trustDomains := make(map[spiffeid.TrustDomain]struct{}, len(newBundles))
	for _, newBundle := range newBundles {
		trustDomains[newBundle.TrustDomain()] = struct{}{}
		existingBundle, ok := s.bundles.Get(newBundle.TrustDomain())
		if !ok {
			s.bundles.Add(spiffebundle.FromX509Bundle(newBundle))
			continue
		}
		existingBundle.SetX509Roots(newBundle.X509Roots())
	}

	// Remove the X.509 content from bundles that are no longer returned
	// with the X.509 context. If the bundle is then empty, remove the bundle
	// from the set.
	for _, existingBundle := range s.bundles.Bundles() {
		if _, ok := trustDomains[existingBundle.TrustDomain()]; ok {
			continue
		}
		existingBundle.SetX509Roots(nil)
		if existingBundle.Empty() {
			s.bundles.Remove(existingBundle.TrustDomain())
		}
	}
}

func (s *BundleSource) setJWTBundles(bundles *jwtbundle.Set) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	newBundles := bundles.Bundles()

	// Add/replace the X.509 content in the SPIFFE bundles. Track the trust
	// domains represented in the new X.509 context so we can determine if
	// which existing bundles need their X.509 content removed.
	trustDomains := make(map[spiffeid.TrustDomain]struct{}, len(newBundles))
	for _, newBundle := range newBundles {
		trustDomains[newBundle.TrustDomain()] = struct{}{}
		existingBundle, ok := s.bundles.Get(newBundle.TrustDomain())
		if !ok {
			s.bundles.Add(spiffebundle.FromJWTBundle(newBundle))
			continue
		}
		existingBundle.SetJWTKeys(newBundle.JWTKeys())
	}

	// Remove the X.509 content from bundles that are no longer returned
	// with the X.509 context. If the bundle is then empty, remove the bundle
	// from the set.
	for _, existingBundle := range s.bundles.Bundles() {
		if _, ok := trustDomains[existingBundle.TrustDomain()]; ok {
			continue
		}
		existingBundle.SetJWTKeys(nil)
		if existingBundle.Empty() {
			s.bundles.Remove(existingBundle.TrustDomain())
		}
	}
}

func (s *BundleSource) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return bundlesourceErr.New("source is closed")
	}
	return nil
}
