package spiffetls

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Validator is a callback used to verify a SPIFFE ID provided in an
// X509-SVID during the TLS handshake
type Validator func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error

func AllowAny() Validator {
	return AdaptValidator(spiffeid.AllowAny())
}

func AllowID(allowed spiffeid.ID) Validator {
	return AdaptValidator(spiffeid.AllowID(allowed))
}

func AllowIDIn(allowed ...spiffeid.ID) Validator {
	return AdaptValidator(spiffeid.AllowIDIn(allowed...))
}

func AllowTrustDomain(allowed spiffeid.TrustDomain) Validator {
	return AdaptValidator(spiffeid.AllowTrustDomain(allowed))
}

func AdaptValidator(validator spiffeid.Validator) Validator {
	return Validator(func(actual spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		return validator(actual)
	})
}
