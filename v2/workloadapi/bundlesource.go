package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// BundleSource is a source of SPIFFE bundles maintained via the Workload API.
type BundleSource struct {
}

// NewBundleSource creates a new BundleSource. It blocks until the initial
// update has been received from the Workload API.
func NewBundleSource(ctx context.Context, options ...BundleSourceOption) (*BundleSource, error) {
	panic("not implemented")
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return ErrClosed after Close has been called.
func (s *BundleSource) Close() error {
	panic("not implemented")
}

// GetBundles returns all the bundles.
func (s *BundleSource) GetBundles() (*spiffebundle.Set, error) {
	panic("not implemented")
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the spiffebundle.Source interface.
func (s *BundleSource) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	panic("not implemented")
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *BundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	panic("not implemented")
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
func (s *BundleSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	panic("not implemented")
}
