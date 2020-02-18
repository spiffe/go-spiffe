package spiffeid

import (
	"net/url"
)

type ID struct {
	td   TrustDomain
	path string
}

// String returns a SPIFFE ID given the trust domain and path components. For
// example, String("example.org", "foo", "bar") returns
// "spiffe://example.org/foo/bar".
func String(td TrustDomain, path ...string) string {
	panic("not implemented")
}

// Make makes a SPIFFE ID with the given trust domain and path.
func Make(td TrustDomain, path ...string) ID {
	panic("not implemented")
}

// Parse parses a SPIFFE ID URI from a string.
func Parse(s string) (ID, error) {
	panic("not implemented")
}

// Parse parses a SPIFFE ID URI from a URL.
func ParseURL(u *url.URL) (ID, error) {
	panic("not implemented")
}

// TrustDomain returns the trust domain of the SPIFFE ID.
func (id ID) TrustDomain() TrustDomain {
	return id.td
}

// In returns true if the SPIFFE ID is in the given trust domain.
func (id ID) In(td TrustDomain) bool {
	// Does a case insensitive comparison of the trust domain component
	panic("not implemented")
}

// Path returns the path of the SPIFFE ID inside the trust domain.
func (id ID) Path() string {
	return id.path
}

// String returns the URI representation of the SPIFFE ID, e.g.,
// "spiffe://example.org/foo/bar".
func (id ID) String() string {
	return "spiffe://" + string(id.td) + id.path
}

// URL returns a URL for SPIFFE ID.
func (id ID) URL() *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   string(id.td),
		Path:   id.path,
	}
}

// Empty returns true if the SPIFFE ID is empty.
func (id ID) Empty() bool {
	// Don't bother checking the path. An ID isn't valid without a trust domain.
	return id.td == ""
}
