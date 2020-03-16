package spiffeid

import (
	"net/url"
)

// ID is a SPIFFE ID
type ID struct {
}

// New creates a new ID using the trust domain (e.g. example.org) and path
// segments. An error is returned if the trust domain is not valid (see
// ParseTrustDomain).
func New(trustDomain string, segments ...string) (ID, error) {
	panic("not implemented")
}

// Must creates a new ID using the trust domain (e.g. example.org) and path
// segments. The function panics if the trust domain is not valid (see
// ParseTrustDomain).
func Must(trustDomain string, segments ...string) ID {
	panic("not implemented")
}

// Join returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. An error is returned
// if the trust domain is not valid (see ParseTrustDomain).
func Join(trustDomain string, segments ...string) (string, error) {
	panic("not implemented")
}

// MustJoin returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. The function panics
// if the trust domain is not valid (see ParseTrustDomain).
func MustJoin(trustDomain string, segments ...string) string {
	panic("not implemented")
}

// FromString parses a SPIFFE ID from a string.
func FromString(s string) (ID, error) {
	panic("not implemented")
}

// FromURI parses a SPIFFE ID from a URI.
func FromURI(u *url.URL) (ID, error) {
	panic("not implemented")
}

// TrustDomain returns the trust domain of the SPIFFE ID.
func (id ID) TrustDomain() TrustDomain {
	panic("not implemented")
}

// MemberOf returns true if the SPIFFE ID is a member of the given trust domain.
func (id ID) MemberOf(td TrustDomain) bool {
	panic("not implemented")
}

// Path returns the path of the SPIFFE ID inside the trust domain.
func (id ID) Path() string {
	panic("not implemented")
}

// String returns the string representation of the SPIFFE ID, e.g.,
// "spiffe://example.org/foo/bar".
func (id ID) String() string {
	panic("not implemented")
}

// URL returns a URL for SPIFFE ID.
func (id ID) URL() *url.URL {
	panic("not implemented")
}

// Empty returns true if the SPIFFE ID is empty.
func (id ID) Empty() bool {
	panic("not implemented")
}
