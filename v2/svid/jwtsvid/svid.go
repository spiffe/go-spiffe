package jwtsvid

import (
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SVID represents a JWT-SVID.
type SVID struct {
	ID spiffeid.ID

	// TODO: denormalize values for things like expiration and issuance
	// so the token claims don't have to be interpreted
}

// ParseAndValidate parses and validates a JWT-SVID token and returns the
// JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
func ParseAndValidate(token string, bundles jwtbundle.Source, audience []string) (*SVID, error) {
	panic("not implemented")
}

// Marshal returns the JWT-SVID marshaled to a string. The returned value is
// the same token value originally passed to ParseAndValidate.
func (svid *SVID) Marshal() string {
	panic("not implemented")
}
