package spiffeid

import (
	"net/url"
)

type ID struct {
	td   TrustDomain
	path string
}

// Strings returns a SPIFFE ID given the trust domain and path components
// String("example.org", "foo", "bar") ==> "spiffe://example.org/foo/bar"
func String(td TrustDomain, path ...string) string {
	panic("not implemented")
}

func Make(td TrustDomain, path ...string) ID {
	panic("not implemented")
}

func Parse(s string) (ID, error) {
	panic("not implemented")
}

func ParseURL(u *url.URL) (ID, error) {
	panic("not implemented")
}

func (id ID) TrustDomain() TrustDomain {
	return id.td
}

func (id ID) In(td TrustDomain) bool {
	// Does a case insensitive comparison of the trust domain component
	panic("not implemented")
}

func (id ID) Path() string {
	return id.path
}

func (id ID) String() string {
	return "spiffe://" + string(id.td) + id.path
}

func (id ID) URL() *url.URL {
	return &url.URL{
		Host: string(id.td),
		Path: id.path,
	}
}

func (id ID) Empty() bool {
	// Don't bother checking the path. An ID isn't valid without a trust domain.
	return id.td == ""
}
