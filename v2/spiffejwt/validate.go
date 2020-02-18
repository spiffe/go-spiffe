package spiffejwt

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Validator validates a JWT-SVID using the provided SPIFFE ID and claims.
type Validator func(id spiffeid.ID, claims map[string]interface{}) error

// AllowAny allows any SPIFFE ID.
func AllowAny() Validator {
	return AdaptValidator(spiffeid.AllowAny())
}

// AllowID allows a specific SPIFFE ID.
func AllowID(allowed spiffeid.ID) Validator {
	return AdaptValidator(spiffeid.AllowID(allowed))
}

// AllowIDs allows any SPIFFE ID in the given list of IDs.
func AllowIDs(allowed ...spiffeid.ID) Validator {
	return AdaptValidator(spiffeid.AllowIDs(allowed...))
}

// AllowIn allows any SPIFFE ID in the given trust domain.
func AllowIn(allowed spiffeid.TrustDomain) Validator {
	return AdaptValidator(spiffeid.AllowIn(allowed))
}

// AdaptValidator adapts any spiffeid.Validator for use as a Validator which
// ignores the JWT-SVID claims.
func AdaptValidator(validator spiffeid.Validator) Validator {
	return Validator(func(actual spiffeid.ID, claims map[string]interface{}) error {
		return validator(actual)
	})
}
