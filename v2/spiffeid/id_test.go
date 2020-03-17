package spiffeid

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeAndIDString(t *testing.T) {
	tests := []struct {
		name       string
		td         string
		segments   []string
		expectedId string
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
			name:       "segments_with_slashes",
			td:         "domain.test",
			segments:   []string{"pa/th", "ele/ment"},
			expectedId: "spiffe://domain.test/pa%2fth/ele%2fment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id := Must(test.td, test.segments...)
			assert.Equal(t, test.expectedId, id.String())
		})
	}
}

func TestFromString(t *testing.T) {
	tests := []struct {
		name          string
		inputId       string
		expectedId    ID
		expectedError string
	}{
		{
			name:       "happy_path",
			inputId:    "spiffe://domain.test/path/element",
			expectedId: Must("domain.test", "path", "element"),
		},
		{
			name:          "empty_input_string",
			inputId:       "",
			expectedError: "invalid SPIFFE ID: SPIFFE ID is empty",
		},
		{
			name:          "invalid_uri",
			inputId:       "192.168.2.2:6688",
			expectedError: "invalid SPIFFE ID: parse \"192.168.2.2:6688\": first path segment in URL cannot contain colon",
		},
		{
			name:          "invalid_scheme",
			inputId:       "http://domain.test/path/element",
			expectedError: "invalid SPIFFE ID: invalid scheme",
		},
		{
			name:       "scheme_mixed_case",
			inputId:    "SPIFFE://domain.test/path/element",
			expectedId: Must("domain.test", "path", "element"),
		},
		{
			name:          "empty_host",
			inputId:       "spiffe:///path/element",
			expectedError: "invalid SPIFFE ID: trust domain is empty",
		},
		{
			name:          "query_not_allowed",
			inputId:       "spiffe://domain.test/path/element?query=1",
			expectedError: "invalid SPIFFE ID: query is not allowed",
		},
		{
			name:          "fragment_not_allowed",
			inputId:       "spiffe://domain.test/path/element?#fragment-1",
			expectedError: "invalid SPIFFE ID: fragment is not allowed",
		},
		{
			name:          "port_not_allowed",
			inputId:       "spiffe://domain.test:8080/path/element",
			expectedError: "invalid SPIFFE ID: port is not allowed",
		},
		{
			name:          "user_info_not_allowed",
			inputId:       "spiffe://user:password@test.org/path/element",
			expectedError: "invalid SPIFFE ID: user info is not allowed",
		},
		{
			name:       "empty_path",
			inputId:    "spiffe://domain.test",
			expectedId: Must("domain.test"),
		},
		{
			name:          "missing_double_slash_1",
			inputId:       "spiffe:path/element",
			expectedError: "invalid SPIFFE ID: trust domain is empty",
		},
		{
			name:          "missing_double_slash_2",
			inputId:       "spiffe:/path/element",
			expectedError: "invalid SPIFFE ID: trust domain is empty",
		},
		{
			name:       "encoded_slash_in_path",
			inputId:    "spiffe://domain.test/path%2felement%2f",
			expectedId: Must("domain.test", "path/element/"),
		},
		{
			name:       "path_with_colons",
			inputId:    "spiffe://domain.test/pa:th/element:",
			expectedId: Must("domain.test", "pa:th", "element:"),
		},
		{
			name:       "path_with_@",
			inputId:    "spiffe://domain.test/pa@th/element:",
			expectedId: Must("domain.test", "pa@th", "element:"),
		},
		{
			name:       "path_starts_with_double_slash",
			inputId:    "spiffe://domain.test//path/element",
			expectedId: Must("domain.test", "", "path", "element"),
		},

		{
			name:       "path_has_subdelims",
			inputId:    "spiffe://domain.test/p!a$t&h'/(e)l*e+m,e;n=t",
			expectedId: Must("domain.test", "p!a$t&h'", "(e)l*e+m,e;n=t"),
		},
		{
			name:          "path_has_invalid_percent_char",
			inputId:       "spiffe://domain.test/path/elem%5uent",
			expectedError: "invalid SPIFFE ID: parse \"spiffe://domain.test/path/elem%5uent\": invalid URL escape \"%5u\"",
		},
		{
			name:          "path_has_invalid_percent_char_at_end_of_path",
			inputId:       "spiffe://domain.test/path/element%5",
			expectedError: "invalid SPIFFE ID: parse \"spiffe://domain.test/path/element%5\": invalid URL escape \"%5\"",
		},
		{
			name:          "path_has_not_allowed_gendelim_[",
			inputId:       "spiffe://domain.test/path/elem[ent",
			expectedError: "invalid character at index 30",
		},
		{
			name:          "path_has_not_allowed_gendelim_]",
			inputId:       "spiffe://domain.test/path/elem]ent",
			expectedError: "invalid character at index 30",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := FromString(test.inputId)
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
	parse := func(id string) *url.URL {
		u, err := url.Parse(id)
		assert.NoError(t, err)
		return u
	}
	tests := []struct {
		name          string
		input         *url.URL
		expectedId    ID
		expectedError string
	}{
		{
			name:       "happy_path",
			input:      parse("spiffe://domain.test/path/element"),
			expectedId: Must("domain.test", "path", "element"),
		},
		{
			name:          "nil_uri",
			input:         nil,
			expectedError: "nil URI",
		},
		{
			name:          "empty_uri",
			input:         &url.URL{},
			expectedError: "empty URI",
		},
		{
			name:          "invalid_uri",
			input:         &url.URL{Host: "192.168.2.2:6688"},
			expectedError: "wrong or missing scheme",
		},
		{
			name:          "invalid_scheme",
			input:         parse("http://domain.test/path/element"),
			expectedError: "wrong or missing scheme",
		},
		{
			name:       "scheme_mixed_case",
			input:      parse("SPIFFE://domain.test/path/element"),
			expectedId: Must("domain.test", "path", "element"),
		},
		{
			name:          "empty_host",
			input:         parse("spiffe:///path/element"),
			expectedError: "empty trust domain",
		},
		{
			name:          "query_not_allowed",
			input:         parse("spiffe://domain.test/path/element?query=1"),
			expectedError: "query not allowed",
		},
		{
			name:          "fragment_not_allowed",
			input:         parse("spiffe://domain.test/path/element?#fragment-1"),
			expectedError: "fragment not allowed",
		},
		{
			name:          "port_not_allowed",
			input:         parse("spiffe://domain.test:8080/path/element"),
			expectedError: "port is not allowed",
		},
		{
			name:          "user_info_not_allowed",
			input:         parse("spiffe://user:password@test.org/path/element"),
			expectedError: "user info is not allowed",
		},
		{
			name:       "empty_path",
			input:      parse("spiffe://domain.test"),
			expectedId: Must("domain.test"),
		},
		{
			name:          "missing_double_slash_1",
			input:         parse("spiffe:path/element"),
			expectedError: "missing '//' characters",
		},
		{
			name:          "missing_double_slash_2",
			input:         parse("spiffe:/path/element"),
			expectedError: "empty trust domain",
		},
		{
			name:       "encoded_slash_in_path",
			input:      parse("spiffe://domain.test/path%2felement"),
			expectedId: Must("domain.test", "path%2felement"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := FromURI(test.input)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}

			assert.Equal(t, test.expectedId, id)
		})
	}
}
