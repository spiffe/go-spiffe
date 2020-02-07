package spiffeid

import "strings"

// TrustDomain is the name of a SPIFFE trust domain (e.g. domain.test).
type TrustDomain string

// ID returns a SPIFFE ID with the given path segments in the trust domain.
func (td TrustDomain) ID(segments ...string) ID {
	return Make(td, segments...)
}

// normalizeTrustDomain normalizes the trust domain by converting it to
// lowercase.
func normalizeTrustDomain(td TrustDomain) TrustDomain {
	return TrustDomain(strings.ToLower(string(td)))
}
