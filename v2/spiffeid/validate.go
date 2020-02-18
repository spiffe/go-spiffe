package spiffeid

import "fmt"

// Validator is use to validate a SPIFFE ID.
type Validator func(ID) error

// AllowAny allows any SPIFFE ID.
func AllowAny() Validator {
	return Validator(func(actual ID) error {
		return nil
	})
}

// AllowID allows a specific SPIFFE ID.
func AllowID(allowed ID) Validator {
	return Validator(func(actual ID) error {
		if actual != allowed {
			return fmt.Errorf("unexpected ID %q", actual)
		}
		return nil
	})
}

// AllowIDs allows any SPIFFE ID in the given list of IDs.
func AllowIDs(allowed ...ID) Validator {
	set := make(map[ID]struct{})
	for _, id := range allowed {
		set[id] = struct{}{}
	}
	return Validator(func(actual ID) error {
		if _, ok := set[actual]; !ok {
			return fmt.Errorf("unexpected ID %q", actual)
		}
		return nil
	})
}

// AllowIn allows any SPIFFE ID in the given trust domain.
func AllowIn(allowed TrustDomain) Validator {
	return Validator(func(actual ID) error {
		if td := actual.TrustDomain(); td != allowed {
			return fmt.Errorf("unexpected trust domain %q", td)
		}
		return nil
	})
}
