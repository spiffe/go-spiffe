package workloadapi

import "github.com/spiffe/go-spiffe/v2/spiffeid"

// JWTSVIDOptions conveys extra options when fetching JWT-SVIDs
type JWTSVIDOption interface{}

// WithSubject requests a specific SPIFFE ID for the subject of the JWT-SVID
func WithSubject(id spiffeid.ID) JWTSVIDOption {
	panic("not implemented")
}

// WithExtraAudiences requests extra audiences on the JWT-SVID
func WithExtraAudiences(audiences ...string) JWTSVIDOption {
	panic("not implemented")
}
