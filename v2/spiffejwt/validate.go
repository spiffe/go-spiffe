package spiffejwt

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type Validator func(id spiffeid.ID, claims map[string]interface{}) error

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
	return Validator(func(actual spiffeid.ID, claims map[string]interface{}) error {
		return validator(actual)
	})
}
