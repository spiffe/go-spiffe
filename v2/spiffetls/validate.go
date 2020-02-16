package spiffetls

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Validator is a callback used to verify a SPIFFE ID provided in an
// X509-SVID during the TLS handshake
type Validator func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error

// AllowAny allows any SPIFFE ID
func AllowAny() Validator {
	return AdaptValidator(spiffeid.AllowAny())
}

// AllowID allows a specific SPIFFE ID
func AllowID(allowed spiffeid.ID) Validator {
	return AdaptValidator(spiffeid.AllowID(allowed))
}

// AllowIDs allows any SPIFFE ID in the given list of IDs
func AllowIDs(allowed ...spiffeid.ID) Validator {
	return AdaptValidator(spiffeid.AllowIDs(allowed...))
}

// AllowIn allows any SPIFFE ID in the given trust domain
func AllowIn(allowed spiffeid.TrustDomain) Validator {
	return AdaptValidator(spiffeid.AllowIn(allowed))
}

// AdaptValidator adapts any spiffeid.Validator for use as a Validator which
// ignores the verified chains.
func AdaptValidator(validator spiffeid.Validator) Validator {
	return Validator(func(actual spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		return validator(actual)
	})
}
