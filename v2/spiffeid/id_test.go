package spiffeid

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeAndIDString(t *testing.T) {
	tests := []struct {
		name       string
		td         TrustDomain
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
			name:       "all_empty",
			expectedId: "",
		},
		{
			name:       "empty_trust_domain",
			segments:   []string{"path", "element"},
			expectedId: "",
		},
		{
			name:       "empty_trust_domain",
			segments:   []string{"path", "element"},
			expectedId: "",
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
			id := Make(test.td, test.segments...)
			assert.Equal(t, test.expectedId, id.String())
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		inputId       string
		expectedId    ID
		expectedError string
	}{

		{
			name:       "happy_path",
			inputId:    "spiffe://domain.test/path/element",
			expectedId: Make("domain.test", "path", "element"),
		},
		{
			name:          "empty_input_string",
			inputId:       "",
			expectedError: "empty string",
		},
		{
			name:          "invalid_uri",
			inputId:       "192.168.2.2:6688",
			expectedError: "wrong or missing scheme",
		},
		{
			name:          "invalid_scheme",
			inputId:       "http://domain.test/path/element",
			expectedError: "wrong or missing scheme",
		},
		{
			name:       "scheme_mixed_case",
			inputId:    "SPIFFE://domain.test/path/element",
			expectedId: Make("domain.test", "path", "element"),
		},
		{
			name:          "empty_host",
			inputId:       "spiffe:///path/element",
			expectedError: "empty trust domain",
		},
		{
			name:          "query_not_allowed",
			inputId:       "spiffe://domain.test/path/element?query=1",
			expectedError: "query not allowed",
		},
		{
			name:          "fragment_not_allowed",
			inputId:       "spiffe://domain.test/path/element?#fragment-1",
			expectedError: "fragment not allowed",
		},
		{
			name:          "port_not_allowed",
			inputId:       "spiffe://domain.test:8080/path/element",
			expectedError: "port is not allowed",
		},
		{
			name:          "user_info_not_allowed",
			inputId:       "spiffe://user:password@test.org/path/element",
			expectedError: "user info is not allowed",
		},
		{
			name:       "empty_path",
			inputId:    "spiffe://domain.test",
			expectedId: Make("domain.test"),
		},
		{
			name:          "missing_double_slash_1",
			inputId:       "spiffe:path/element",
			expectedError: "missing '//' characters",
		},
		{
			name:          "missing_double_slash_2",
			inputId:       "spiffe:/path/element",
			expectedError: "missing '//' characters",
		},
		{
			name:       "encoded_slash_in_path",
			inputId:    "spiffe://domain.test/path%2felement%2f",
			expectedId: Make("domain.test", "path%2felement%2f"),
		},
		{
			name:       "path_with_colons",
			inputId:    "spiffe://domain.test/pa:th/element:",
			expectedId: Make("domain.test", "pa:th", "element:"),
		},
		{
			name:       "path_with_@",
			inputId:    "spiffe://domain.test/pa@th/element:",
			expectedId: Make("domain.test", "pa@th", "element:"),
		},
		{
			name:       "path_starts_with_double_slash",
			inputId:    "spiffe://domain.test//path/element",
			expectedId: ID{td: "domain.test", path: "//path/element"},
		},
		{
			name:       "path_has_subdelims",
			inputId:    "spiffe://domain.test/p!a$t&h'/(e)l*e+m,e;n=t",
			expectedId: Make("domain.test", "p!a$t&h'", "(e)l*e+m,e;n=t"),
		},
		{
			name:          "path_has_invalid_percent_char",
			inputId:       "spiffe://domain.test/path/elem%5uent",
			expectedError: "invalid percent encoded char at index 30",
		},
		{
			name:          "path_has_invalid_percent_char_at_end_of_path",
			inputId:       "spiffe://domain.test/path/element%5",
			expectedError: "invalid percent encoded char at index 33",
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
			id, err := Parse(test.inputId)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}

			assert.Equal(t, test.expectedId, id)
		})
	}
}

func TestParseURI(t *testing.T) {
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
			expectedId: Make("domain.test", "path", "element"),
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
			expectedId: Make("domain.test", "path", "element"),
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
			expectedId: Make("domain.test"),
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
			expectedId: Make("domain.test", "path%2felement"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := ParseURI(test.input)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}

			assert.Equal(t, test.expectedId, id)
		})
	}
}
