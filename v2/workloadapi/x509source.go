package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Source is a source of X509-SVIDs and X.509 bundles maintained via the
// Workload API.
type X509Source struct {
}

// NewX509Source creates a new X509Source. It blocks until the initial update
// has been received from the Workload API.
func NewX509Source(ctx context.Context, options ...X509SourceOption) (*X509Source, error) {
	panic("not implemented")
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return ErrClosed after Close has been called.
func (s *X509Source) Close() {
	panic("not implemented")
}

// GetX509SVID returns an X509-SVID from the source. It implements the
// x509svid.Source interface.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	panic("not implemented")
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *X509Source) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	panic("not implemented")
}
