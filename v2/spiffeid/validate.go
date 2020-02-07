package spiffeid

import "fmt"

type Validator func(ID) error

func AllowAny() Validator {
	return Validator(func(actual ID) error {
		return nil
	})
}

func AllowID(allowed ID) Validator {
	return Validator(func(actual ID) error {
		if actual != allowed {
			return fmt.Errorf("unexpected ID %q", actual)
		}
		return nil
	})
}

func AllowIDIn(allowed ...ID) Validator {
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

func AllowTrustDomain(allowed TrustDomain) Validator {
	return Validator(func(actual ID) error {
		if td := actual.TrustDomain(); td != allowed {
			return fmt.Errorf("unexpected trust domain %q", td)
		}
		return nil
	})
}
