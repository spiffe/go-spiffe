package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// JWTSource is a source of JWT-SVID and JWT bundles maintained via the
// Workload API.
type JWTSource struct {
}

// NewJWTSource creates a new JWTSource. It blocks until the initial update
// has been received from the Workload API.
func NewJWTSource(ctx context.Context, options ...JWTSourceOption) (*JWTSource, error) {
	panic("not implemented")
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return ErrClosed after Close has been called.
func (s *JWTSource) Close() {
	panic("not implemented")
}

// FetchJWTSVID fetches a JWT-SVID from the source with the given parameters.
// It implements the jwtsvid.Source interface.
func (s *JWTSource) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	panic("not implemented")
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
func (s *JWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	panic("not implemented")
}
