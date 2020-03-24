package spiffeid_test

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

func TestMust(t *testing.T) {
	tests := []struct {
		name          string
		td            string
		segments      []string
		expectedId    string
		expectedPanic string
	}{
		{
			name:       "happy_path",
			td:         "domain.test",
			segments:   []string{"path", "element"},
			expectedId: "spiffe://domain.test/path/element",
		},
		{
			name:       "empty_segments",
			td:         "domain.test",
			expectedId: "spiffe://domain.test",
		},
		{
			name:       "trust_domain_with_scheme",
			td:         "spiffe://domain.test",
			segments:   []string{"path", "element"},
			expectedId: "spiffe://domain.test/path/element",
		},
		{
			name:          "trust_domain_empty",
			td:            "spiffe://",
			segments:      []string{"path", "element"},
			expectedPanic: "spiffeid: trust domain is empty",
		},
		{
			name:       "path_with_colon_and_@",
			td:         "spiffe://domain.test",
			segments:   []string{"pa:th", "elem@ent"},
			expectedId: "spiffe://domain.test/pa:th/elem@ent",
		},
		{
			name:       "segments_starting_with_slash",
			td:         "spiffe://domain.test",
			segments:   []string{"/path", "/element"},
			expectedId: "spiffe://domain.test/path/element",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					assert.Equal(t, test.expectedPanic, fmt.Sprintf("%v", p))
				}
			}()
			id := spiffeid.Must(test.td, test.segments...)
			assert.Equal(t, test.expectedId, id.String())
		})
	}
}

func TestMustJoin(t *testing.T) {
	tests := []struct {
		name          string
		td            string
		segments      []string
		expectedId    string
		expectedPanic string
	}{
		{
			name:       "happy_path",
			td:         "domain.test",
			segments:   []string{"path", "element"},
			expectedId: "spiffe://domain.test/path/element",
		},
		{
			name:       "empty_segments",
			td:         "domain.test",
			expectedId: "spiffe://domain.test",
		},
		{
			name:       "trust_domain_with_scheme",
			td:         "spiffe://domain.test",
			segments:   []string{"path", "element"},
			expectedId: "spiffe://domain.test/path/element",
		},
		{
			name:          "trust_domain_empty",
			td:            "spiffe://",
			segments:      []string{"path", "element"},
			expectedPanic: "spiffeid: trust domain is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					assert.Equal(t, test.expectedPanic, fmt.Sprintf("%v", p))
				}
			}()
			idstr := spiffeid.MustJoin(test.td, test.segments...)
			assert.Equal(t, test.expectedId, idstr)
		})
	}
}

func TestFromString(t *testing.T) {
	tests := []struct {
		name          string
		inputId       string
		expectedId    spiffeid.ID
		expectedError string
	}{
		{
			name:       "happy_path",
			inputId:    "spiffe://domain.test/path/element",
			expectedId: spiffeid.Must("domain.test", "path", "element"),
		},
		{
			name:          "empty_input_string",
			inputId:       "",
			expectedError: "spiffeid: ID is empty",
		},
		{
			name:          "invalid_uri",
			inputId:       "192.168.2.2:6688",
			expectedError: "spiffeid: unable to parse: parse \"192.168.2.2:6688\": first path segment in URL cannot contain colon",
		},
		{
			name:          "invalid_scheme",
			inputId:       "http://domain.test/path/element",
			expectedError: "spiffeid: invalid scheme",
		},
		{
			name:       "scheme_mixed_case",
			inputId:    "SPIFFE://domain.test/path/element",
			expectedId: spiffeid.Must("domain.test", "path", "element"),
		},
		{
			name:          "empty_host",
			inputId:       "spiffe:///path/element",
			expectedError: "spiffeid: trust domain is empty",
		},
		{
			name:          "query_not_allowed",
			inputId:       "spiffe://domain.test/path/element?query=1",
			expectedError: "spiffeid: query is not allowed",
		},
		{
			name:          "fragment_not_allowed",
			inputId:       "spiffe://domain.test/path/element?#fragment-1",
			expectedError: "spiffeid: fragment is not allowed",
		},
		{
			name:          "port_not_allowed",
			inputId:       "spiffe://domain.test:8080/path/element",
			expectedError: "spiffeid: port is not allowed",
		},
		{
			name:          "user_info_not_allowed",
			inputId:       "spiffe://user:password@test.org/path/element",
			expectedError: "spiffeid: user info is not allowed",
		},
		{
			name:       "empty_path",
			inputId:    "spiffe://domain.test",
			expectedId: spiffeid.Must("domain.test"),
		},
		{
			name:          "missing_double_slash_1",
			inputId:       "spiffe:path/element",
			expectedError: "spiffeid: trust domain is empty",
		},
		{
			name:          "missing_double_slash_2",
			inputId:       "spiffe:/path/element",
			expectedError: "spiffeid: trust domain is empty",
		},
		{
			name:       "path_with_colons",
			inputId:    "spiffe://domain.test/pa:th/element:",
			expectedId: spiffeid.Must("domain.test", "pa:th", "element:"),
		},
		{
			name:       "path_with_@",
			inputId:    "spiffe://domain.test/pa@th/element:",
			expectedId: spiffeid.Must("domain.test", "pa@th", "element:"),
		},
		{
			name:       "path_has_encoded_subdelims",
			inputId:    "spiffe://domain.test/p!a$t&h'/(e)l*e+m,e;n=t",
			expectedId: spiffeid.Must("domain.test", "p!a$t&h'", "(e)l*e+m,e;n=t"),
		},
		{
			name:          "path_has_invalid_percent_encoded_char",
			inputId:       "spiffe://domain.test/path/elem%5uent",
			expectedError: "spiffeid: unable to parse: parse \"spiffe://domain.test/path/elem%5uent\": invalid URL escape \"%5u\"",
		},
		{
			name:          "path_has_invalid_percent_encoded_char_at_end_of_path",
			inputId:       "spiffe://domain.test/path/element%5",
			expectedError: "spiffeid: unable to parse: parse \"spiffe://domain.test/path/element%5\": invalid URL escape \"%5\"",
		},
		{
			name:       "path_has_encoded_gendelim_[",
			inputId:    "spiffe://domain.test/path/elem[ent",
			expectedId: spiffeid.Must("domain.test", "path", "elem[ent"),
		},
		{
			name:       "path_has_encoded_gendelim_]",
			inputId:    "spiffe://domain.test/path/elem]ent",
			expectedId: spiffeid.Must("domain.test", "path", "elem]ent"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := spiffeid.FromString(test.inputId)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}

			assert.Equal(t, test.expectedId, id)
		})
	}
}

func TestFromURI(t *testing.T) {
	tests := []struct {
		name          string
		input         *url.URL
		expectedId    spiffeid.ID
		expectedError string
	}{
		{
			name:       "happy_path",
			input:      parseURI(t, "spiffe://domain.test/path/element"),
			expectedId: spiffeid.Must("domain.test", "path", "element"),
		},
		{
			name:          "nil_uri",
			input:         nil,
			expectedError: "spiffeid: ID is nil",
		},
		{
			name:          "empty_uri",
			input:         &url.URL{},
			expectedError: "spiffeid: ID is empty",
		},
		{
			name:          "invalid_uri",
			input:         &url.URL{Host: "192.168.2.2:6688"},
			expectedError: "spiffeid: invalid scheme",
		},
		{
			name:          "invalid_scheme",
			input:         parseURI(t, "http://domain.test/path/element"),
			expectedError: "spiffeid: invalid scheme",
		},
		{
			name:       "scheme_mixed_case",
			input:      parseURI(t, "SPIFFE://domain.test/path/element"),
			expectedId: spiffeid.Must("domain.test", "path", "element"),
		},
		{
			name:          "empty_host",
			input:         parseURI(t, "spiffe:///path/element"),
			expectedError: "spiffeid: trust domain is empty",
		},
		{
			name:          "empty_port",
			input:         parseURI(t, "spiffe://domain.test:/path/element"),
			expectedError: "spiffeid: colon is not allowed in trust domain",
		},
		{
			name:          "query_not_allowed",
			input:         parseURI(t, "spiffe://domain.test/path/element?query=1"),
			expectedError: "spiffeid: query is not allowed",
		},
		{
			name:          "fragment_not_allowed",
			input:         parseURI(t, "spiffe://domain.test/path/element?#fragment-1"),
			expectedError: "spiffeid: fragment is not allowed",
		},
		{
			name:          "port_not_allowed",
			input:         parseURI(t, "spiffe://domain.test:8080/path/element"),
			expectedError: "spiffeid: port is not allowed",
		},
		{
			name:          "user_info_not_allowed",
			input:         parseURI(t, "spiffe://user:password@test.org/path/element"),
			expectedError: "spiffeid: user info is not allowed",
		},
		{
			name:       "empty_path",
			input:      parseURI(t, "spiffe://domain.test"),
			expectedId: spiffeid.Must("domain.test"),
		},
		{
			name:          "missing_double_slash_1",
			input:         parseURI(t, "spiffe:path/element"),
			expectedError: "spiffeid: trust domain is empty",
		},
		{
			name:          "missing_double_slash_2",
			input:         parseURI(t, "spiffe:/path/element"),
			expectedError: "spiffeid: trust domain is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := spiffeid.FromURI(test.input)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}
			assert.Equal(t, test.expectedId, id)
		})
	}
}

func TestIDTrustDomain(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	// Common case
	id := spiffeid.Must("domain.test", "path", "element")
	assert.Equal(t, td, id.TrustDomain())

	// Empty path
	id = spiffeid.Must("domain.test")
	assert.Equal(t, td, id.TrustDomain())
}

func TestIDMemberOf(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	// Common case
	id := spiffeid.Must("domain.test", "path", "element")
	assert.True(t, id.MemberOf(td))

	// Empty path
	id = spiffeid.Must("domain.test")
	assert.True(t, id.MemberOf(td))

	// Is not member of
	id = spiffeid.Must("other.domain.test", "path", "element")
	assert.False(t, id.MemberOf(td))
}

func TestIDPath(t *testing.T) {
	// Common case
	id := spiffeid.Must("domain.test", "path", "element")
	assert.Equal(t, "/path/element", id.Path())

	// Empty path
	id = spiffeid.Must("domain.test")
	assert.Equal(t, "", id.Path())

	// A single empty segment
	id = spiffeid.Must("domain.test", "")
	assert.Equal(t, "", id.Path())

	// Couple of empty segment
	id = spiffeid.Must("domain.test", "", "")
	assert.Equal(t, "", id.Path())

	// First segment empty
	id = spiffeid.Must("domain.test", "", "path", "element")
	assert.Equal(t, "/path/element", id.Path())

	// Last segment empty
	id = spiffeid.Must("domain.test", "path", "element", "")
	assert.Equal(t, "/path/element", id.Path())
}

func TestIDString(t *testing.T) {
	// Common case
	id := spiffeid.Must("domain.test", "path", "element")
	assert.Equal(t, "spiffe://domain.test/path/element", id.String())

	// Empty path
	id = spiffeid.Must("domain.test")
	assert.Equal(t, "spiffe://domain.test", id.String())

	// A single empty segment
	id = spiffeid.Must("domain.test", "")
	assert.Equal(t, "spiffe://domain.test", id.String())

	// Couple of empty segment
	id = spiffeid.Must("domain.test", "", "")
	assert.Equal(t, "spiffe://domain.test", id.String())

	// Segment with sub-delims
	id = spiffeid.Must("domain.test", "!p$a&t'h", "(e)l*e+m,e;n=t")
	assert.Equal(t, "spiffe://domain.test/%21p$a&t%27h/%28e%29l%2Ae+m,e;n=t", id.String())

	// Empty ID
	id = spiffeid.ID{}
	assert.Equal(t, "", id.String())

	// Path is a spiffe id
	id, err := spiffeid.FromString("spiffe://domain.test/spiffe://domain.test/path/element")
	assert.NoError(t, err)
	assert.Equal(t, "spiffe://domain.test/spiffe://domain.test/path/element", id.String())

	// Path starts with double slash
	id, err = spiffeid.FromString("spiffe://domain.test//path/element")
	assert.NoError(t, err)
	assert.Equal(t, "spiffe://domain.test//path/element", id.String())
}

func TestIDURL(t *testing.T) {
	asURL := func(td, path string) *url.URL {
		return &url.URL{
			Scheme: "spiffe",
			Host:   td,
			Path:   path,
		}
	}
	// Common case
	id := spiffeid.Must("domain.test", "path", "element")
	assert.Equal(t, asURL("domain.test", "/path/element"), id.URL())

	// Empty path
	id = spiffeid.Must("domain.test")
	assert.Equal(t, asURL("domain.test", ""), id.URL())

	// Segment with sub-delims
	id = spiffeid.Must("domain.test", "!p$a&t'h", "(e)l*e+m,e;n=t")
	assert.Equal(t, asURL("domain.test", "/!p$a&t'h/(e)l*e+m,e;n=t"), id.URL())

	// Empty ID
	id = spiffeid.ID{}
	assert.Equal(t, &url.URL{}, id.URL())
}

func TestIDEmpty(t *testing.T) {
	assert.True(t, spiffeid.ID{}.Empty())
}

func parseURI(t *testing.T, id string) *url.URL {
	u, err := url.Parse(id)
	assert.NoError(t, err)
	return u
}
