package spiffeid

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ID is a SPIFFE ID
type ID struct {
	uri *url.URL
}

// New creates a new ID using the trust domain (e.g. example.org) and path
// segments. An error is returned if the trust domain is not valid (see
// TrustDomainFromString).
// Warning: Percent encoded characters on path segments are
// not decoded, instead this function will percent encode symbols
// when the ID is converted to a string.
func New(trustDomain string, segments ...string) (ID, error) {
	td, err := TrustDomainFromString(trustDomain)
	if err != nil {
		return ID{}, err
	}

	path := strings.Join(segments, "/")
	if len(path) > 0 {
		path = "/" + path
	}

	return ID{
		uri: &url.URL{
			Scheme: "spiffe",
			Host:   td.String(),
			Path:   path,
		},
	}, nil
}

// Must creates a new ID using the trust domain (e.g. example.org) and path
// segments. The function panics if the trust domain is not valid (see
// TrustDomainFromString).
func Must(trustDomain string, segments ...string) ID {
	id, err := New(trustDomain, segments...)
	if err != nil {
		panic(err)
	}
	return id
}

// Join returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. An error is returned
// if the trust domain is not valid (see TrustDomainFromString).
func Join(trustDomain string, segments ...string) (string, error) {
	id, err := New(trustDomain, segments...)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

// MustJoin returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. The function panics
// if the trust domain is not valid (see TrustDomainFromString).
func MustJoin(trustDomain string, segments ...string) string {
	idstr, err := Join(trustDomain, segments...)
	if err != nil {
		panic(err)
	}
	return idstr
}

// FromString parses a SPIFFE ID from a string.
func FromString(s string) (ID, error) {
	uri, err := url.Parse(s)
	if err != nil {
		return ID{}, fmt.Errorf("invalid SPIFFE ID: %v", err)
	}

	return FromURI(uri)
}

// FromURI parses a SPIFFE ID from a URI.
func FromURI(uri *url.URL) (ID, error) {
	if uri == nil || *uri == (url.URL{}) {
		return ID{}, errors.New("invalid SPIFFE ID: SPIFFE ID is empty")
	}

	// General validation
	switch {
	case strings.ToLower(uri.Scheme) != "spiffe":
		return ID{}, errors.New("invalid SPIFFE ID: invalid scheme")
	case uri.User != nil:
		return ID{}, errors.New("invalid SPIFFE ID: user info is not allowed")
	case uri.Host == "":
		return ID{}, errors.New("invalid SPIFFE ID: trust domain is empty")
	case uri.Port() != "":
		return ID{}, errors.New("invalid SPIFFE ID: port is not allowed")
	case uri.Fragment != "":
		return ID{}, errors.New("invalid SPIFFE ID: fragment is not allowed")
	case uri.RawQuery != "":
		return ID{}, errors.New("invalid SPIFFE ID: query is not allowed")
	}

	return ID{
		uri: normalizeURI(uri),
	}, nil
}

// TrustDomain returns the trust domain of the SPIFFE ID.
func (id ID) TrustDomain() TrustDomain {
	// We built the TrustDomain directly because the ID has always a URI with a valid trust domain.
	return TrustDomain{
		name: id.uri.Host,
	}
}

// MemberOf returns true if the SPIFFE ID is a member of the given trust domain.
func (id ID) MemberOf(td TrustDomain) bool {
	return id.uri.Host == td.name
}

// Path returns the path of the SPIFFE ID inside the trust domain.
func (id ID) Path() string {
	return id.uri.Path
}

// String returns the string representation of the SPIFFE ID, e.g.,
// "spiffe://example.org/foo/bar".
func (id ID) String() string {
	if id.Empty() {
		return ""
	}
	return id.uri.String()
}

// URL returns a URL for SPIFFE ID.
func (id ID) URL() *url.URL {
	if id.Empty() {
		return &url.URL{}
	}

	return &url.URL{
		Scheme: "spiffe",
		Host:   id.uri.Host,
		Path:   id.uri.Path,
	}
}

// Empty returns true if the SPIFFE ID is empty.
func (id ID) Empty() bool {
	return id.uri == nil || id.uri.Host == ""
}

func normalizeURI(uri *url.URL) *url.URL {
	c := *uri
	c.Scheme = strings.ToLower(c.Scheme)
	// SPIFFE ID's can't contain ports so don't bother handling that here.
	c.Host = strings.ToLower(c.Hostname())
	return &c
}
