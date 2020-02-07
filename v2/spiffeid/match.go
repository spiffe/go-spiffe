package spiffeid

import "fmt"

// Matcher is used to match a SPIFFE ID.
type Matcher func(ID) error

// MatchAny matches any SPIFFE ID.
func MatchAny() Matcher {
	return Matcher(func(actual ID) error {
		return nil
	})
}

// MatchID matches a specific SPIFFE ID.
func MatchID(expected ID) Matcher {
	return Matcher(func(actual ID) error {
		if actual != expected {
			return fmt.Errorf("unexpected ID %q", actual)
		}
		return nil
	})
}

// MatchIDs matches any SPIFFE ID in the given list of IDs.
func MatchIDs(expected ...ID) Matcher {
	set := make(map[ID]struct{})
	for _, id := range expected {
		set[id] = struct{}{}
	}
	return Matcher(func(actual ID) error {
		if _, ok := set[actual]; !ok {
			return fmt.Errorf("unexpected ID %q", actual)
		}
		return nil
	})
}

// MatchMemberOf matches any SPIFFE ID in the given trust domain.
func MatchMemberOf(expected TrustDomain) Matcher {
	expected = normalizeTrustDomain(expected)
	return Matcher(func(actual ID) error {
		if td := actual.TrustDomain(); td != expected {
			return fmt.Errorf("unexpected trust domain %q", td)
		}
		return nil
	})
}
