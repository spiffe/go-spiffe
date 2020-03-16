package spiffeid

import (
	"net/url"
)

// TrustDomain is the name of a SPIFFE trust domain (e.g. example.org).
type TrustDomain struct {
}

// TrustDomainFromString returns a new TrustDomain from a string. The string
// can either be the host part of a URI authority component (e.g. example.org),
// or a valid SPIFFE ID URI (e.g. spiffe://example.org), otherwise an error is
// returned.  The trust domain is normalized to lower case.
func TrustDomainFromString(s string) (TrustDomain, error) {
	panic("not implemented")
}

// RequireTrustDomainFromString is similar to TrustDomainFromString except that
// instead of returning an error on malformed input, it panics. It should only
// be used when given string is statically verifiable.
func RequireTrustDomainFromString(s string) TrustDomain {
	panic("not implemented")
}

// TrustDomainFromURI returns a new TrustDomain from a URI. The URI must be a
// valid SPIFFE ID (see FromURI) or an error is returned. The trust domain is
// extracted from the host field and normalized to lower case.
func TrustDomainFromURI(uri *url.URL) (TrustDomain, error) {
	panic("not implemented")
}

// RequireTrustDomainFromURI is similar to TrustDomainFromURI except that
// instead of returning an error on malformed input, it panics. It should only
// be used when the given URI is statically verifiable.
func RequireTrustDomainFromURI(uri *url.URL) TrustDomain {
	panic("not implemented")
}

// String returns the trust domain as a string, e.g. example.org.
func (td TrustDomain) String() string {
	panic("not implemented")
}

// ID returns the SPIFFE ID of the trust domain.
func (td TrustDomain) ID() ID {
	panic("not implemented")
}

// ID returns a string representation of the the SPIFFE ID of the trust domain,
// e.g. "spiffe://example.org".
func (td TrustDomain) IDString() string {
	panic("not implemented")
}

// NewID returns a SPIFFE ID with the given path inside the trust domain.
func (td TrustDomain) NewID(path string) ID {
	panic("not implemented")
}

// Empty returns true if the trust domain value is empty.
func (td TrustDomain) Empty() bool {
	panic("not implemented")
}
