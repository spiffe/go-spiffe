package spiffeid

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ID is a SPIFFE ID
type ID struct {
}

// New creates a new ID using the trust domain (e.g. example.org) and path
// segments. An error is returned if the trust domain is not valid (see
// TrustDomainFromString).
func New(trustDomain string, segments ...string) (ID, error) {
	panic("not implemented")
}

// Must creates a new ID using the trust domain (e.g. example.org) and path
// segments. The function panics if the trust domain is not valid (see
// TrustDomainFromString).
func Must(trustDomain string, segments ...string) ID {
	panic("not implemented")
}

// Join returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. An error is returned
// if the trust domain is not valid (see TrustDomainFromString).
func Join(trustDomain string, segments ...string) (string, error) {
	panic("not implemented")
}

// MustJoin returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. The function panics
// if the trust domain is not valid (see TrustDomainFromString).
func MustJoin(trustDomain string, segments ...string) string {
	panic("not implemented")
}

// FromString parses a SPIFFE ID from a string.
func FromString(s string) (ID, error) {
	switch {
	case s == "":
		return ID{}, errors.New("empty string")
	case len(strings.Split(s, "#")) > 1:
		return ID{}, errors.New("fragment not allowed")
	case len(strings.Split(s, "?")) > 1:
		return ID{}, errors.New("query not allowed")
	case !strings.HasPrefix(strings.ToLower(s), "spiffe:"):
		return ID{}, errors.New("wrong or missing scheme")
	case !strings.HasPrefix(s[7:], "//"):
		return ID{}, errors.New("missing '//' characters")
	}

	// Remove 'spiffe://'
	authority := s[9:]
	path := ""
	slashi := strings.Index(authority, "/")
	// If there is a slash, the authority is the string before it, and the path
	// is the string after it (slash included).
	if slashi >= 0 {
		path = authority[slashi:]
		authority = authority[:slashi]
	}

	if err := validateTrustDomain(authority); err != nil {
		return ID{}, err
	}

	if err := validatePath(path, len(authority)+9); err != nil {
		return ID{}, err
	}

	return ID{
		td:   normalizeTrustDomain(TrustDomain(authority)),
		path: path,
	}, nil
}

// FromURI parses a SPIFFE ID from a URI.
func FromURI(u *url.URL) (ID, error) {
	switch {
	case u == nil:
		return ID{}, errors.New("nil URI")
	case *u == url.URL{}:
		return ID{}, errors.New("empty URI")
	}

	return Parse(u.String())
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

func validateTrustDomain(trustDomain string) error {
	switch {
	case strings.TrimSpace(trustDomain) == "":
		return errors.New("empty trust domain")
	case strings.Contains(trustDomain, "@"):
		return errors.New("user info is not allowed")
	case strings.Contains(trustDomain, ":"):
		return errors.New("port is not allowed")
	}
	return nil
}

func validatePath(path string, basei int) error {
	pathrunes := []rune(path)
	for i := 0; i < len(pathrunes); i++ {
		switch {
		case pathrunes[i] == '/':
		case pathrunes[i] == '%':
			if i+2 >= len(pathrunes) {
				return fmt.Errorf("invalid percent encoded char at index %d", basei+i)
			}

			_, err := strconv.ParseInt(string(pathrunes[i+1])+string(pathrunes[i+2]), 16, 8)
			if err != nil {
				return fmt.Errorf("invalid percent encoded char at index %d", basei+i)
			}
			i += 2
		case !isCharAllowed(pathrunes[i]):
			return fmt.Errorf("invalid character at index %d", basei+i)
		}
	}
	return nil
}

func isCharAllowed(r rune) bool {
	return isUnreservedChar(r) || isSubDelim(r) ||
		strings.ContainsRune(":@", r)
}

func isUnreservedChar(r rune) bool {
	return r >= 0x41 && r <= 0x5A || r >= 0x61 && r <= 0x7A || // is in the range of ALPHA chars
		r >= 0x30 && r <= 0x39 || // is a DIGIT
		strings.ContainsRune("-._~", r)
}

func isSubDelim(r rune) bool {
	return strings.ContainsRune("!$&'()*+,;=", r)
}
