package spiffeid

import (
	"net/url"
	"path"
)

// ID is a SPIFFE ID
type ID struct {
	td   TrustDomain
	path string
}

// String returns the string representation of a SPIFFE ID given the trust
// domain and path segments. For example, String("example.org", "foo", "bar")
// returns "spiffe://example.org/foo/bar".
func String(td TrustDomain, segments ...string) string {
	return Make(td, segments...).String()
}

// Make makes a SPIFFE ID with the given trust domain and path segments.
func Make(td TrustDomain, segments ...string) ID {
	path := path.Join(segments...)
	if len(path) > 0 && path[0] != '/' {
		path = "/" + path
	}
	return ID{
		td:   normalizeTrustDomain(td),
		path: path,
	}
}

// Parse parses a SPIFFE ID from a string.
func Parse(s string) (ID, error) {
	panic("not implemented")
}

// ParseURI parses a SPIFFE ID from a URI.
func ParseURI(u *url.URL) (ID, error) {
	panic("not implemented")
}

// TrustDomain returns the trust domain of the SPIFFE ID.
func (id ID) TrustDomain() TrustDomain {
	return id.td
}

// MemberOf returns true if the SPIFFE ID is a member of the given trust domain.
func (id ID) MemberOf(td TrustDomain) bool {
	return id.td == normalizeTrustDomain(td)
}

// Path returns the path of the SPIFFE ID inside the trust domain.
func (id ID) Path() string {
	return id.path
}

// String returns the string representation of the SPIFFE ID, e.g.,
// "spiffe://example.org/foo/bar".
func (id ID) String() string {
	if id.Empty() {
		return ""
	}
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
