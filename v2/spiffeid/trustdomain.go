package spiffeid

// TrustDomain is the name of a SPIFFE trust domain (e.g. domain.test)
type TrustDomain string

func (td TrustDomain) ID(path ...string) ID {
	panic("not implemented")
}
