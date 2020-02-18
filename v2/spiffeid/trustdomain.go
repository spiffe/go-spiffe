package spiffeid

// TrustDomain is the name of a SPIFFE trust domain (e.g. domain.test).
type TrustDomain string

// ID returns a SPIFFE ID with the given path in the trust domain.
func (td TrustDomain) ID(path ...string) ID {
	panic("not implemented")
}
