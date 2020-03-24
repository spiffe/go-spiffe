package spiffeid_test

import (
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

func TestTrustDomainFromString(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedTd    string
		expectedError string
	}{
		{
			name:       "has_uppercase_chars",
			input:      "DomAin.TesT",
			expectedTd: "domain.test",
		},
		{
			name:       "has_valid_scheme",
			input:      "spiffe://domain.test",
			expectedTd: "domain.test",
		},
		{
			name:       "is_valid_spiffe_id",
			input:      "spiffe://domain.test/path/element",
			expectedTd: "domain.test",
		},
		{
			name:       "is_valid_spiffe_id_with_spiffe_id_as_path",
			input:      "spiffe://domain.test/spiffe://domain.test/path/element",
			expectedTd: "domain.test",
		},
		{
			name:       "is_valid_spiffe_id_with_invalid_spiffe_id_as_path",
			input:      "spiffe://domain.test/spiffe://domain.test:80/path/element",
			expectedTd: "domain.test",
		},
		{
			name:          "has_invalid_scheme",
			input:         "http://domain.test",
			expectedError: "spiffeid: invalid scheme",
		},
		{
			name:          "missing_scheme",
			input:         "://domain.test",
			expectedError: "spiffeid: unable to parse: parse \"://domain.test\": missing protocol scheme",
		},
		{
			name:          "has_port",
			input:         "spiffe://domain.test:80",
			expectedError: "spiffeid: port is not allowed",
		},
		{
			name:          "has_colon",
			input:         "spiffe://domain.test:",
			expectedError: "spiffeid: colon is not allowed in trust domain",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			td, err := spiffeid.TrustDomainFromString(test.input)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}

			assert.Equal(t, test.expectedTd, td.String())
		})
	}
}

func TestRequireTrustDomainFromString(t *testing.T) {
	// Just test the panic, the non panicing cases are already handled by TestTrustDomainFromString.
	assert.PanicsWithError(t, "spiffeid: colon is not allowed in trust domain", func() {
		spiffeid.RequireTrustDomainFromString("spiffe://domain.test:")
	})
}

func TestTrustDomainFromURI(t *testing.T) {
	tests := []struct {
		name          string
		input         *url.URL
		expectedTd    string
		expectedError string
	}{
		{
			name:       "happy_path",
			input:      parseURI(t, "spiffe://domain.test/path/element"),
			expectedTd: "domain.test",
		},
		{
			name:       "has_valid_scheme",
			input:      parseURI(t, "spiffe://domain.test"),
			expectedTd: "domain.test",
		},
		{
			name:       "is_valid_spiffe_id_with_spiffe_id_as_path",
			input:      parseURI(t, "spiffe://domain.test/spiffe://example.test/path/element"),
			expectedTd: "domain.test",
		},
		{
			name:       "is_valid_spiffe_id_with_invalid_spiffe_id_as_path",
			input:      parseURI(t, "spiffe://domain.test/spiffe://example.test:80/path/element"),
			expectedTd: "domain.test",
		},
		{
			name:       "has_uppercase_chars",
			input:      parseURI(t, "spiffe://DomAin.TesT"),
			expectedTd: "domain.test",
		},
		{
			name:          "has_invalid_scheme",
			input:         parseURI(t, "http://domain.test"),
			expectedError: "spiffeid: invalid scheme",
		},
		{
			name:          "missing_scheme",
			input:         &url.URL{Host: "domain.test"},
			expectedError: "spiffeid: invalid scheme",
		},
		{
			name:          "has_port",
			input:         parseURI(t, "spiffe://domain.test:80"),
			expectedError: "spiffeid: port is not allowed",
		},
		{
			name:          "has_colon",
			input:         parseURI(t, "spiffe://domain.test:"),
			expectedError: "spiffeid: colon is not allowed in trust domain",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			td, err := spiffeid.TrustDomainFromURI(test.input)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}

			assert.Equal(t, test.expectedTd, td.String())
		})
	}
}

func TestRequireTrustDomainFromURI(t *testing.T) {
	// Just test the panic, the non panicing cases are already handled by TestTrustDomainFromURI.
	assert.PanicsWithError(t, "spiffeid: colon is not allowed in trust domain", func() {
		spiffeid.RequireTrustDomainFromURI(parseURI(t, "spiffe://domain.test:"))
	})
}

func TestTrustDomainID(t *testing.T) {
	id := spiffeid.Must("domain.test")

	// Common case
	td := spiffeid.RequireTrustDomainFromString("spiffe://domain.test/path/element")
	assert.Equal(t, id, td.ID())

	// Empty path
	td = spiffeid.RequireTrustDomainFromString("domain.test")
	assert.Equal(t, id, td.ID())
}

func TestTrustDomainIDString(t *testing.T) {
	// Common case
	td := spiffeid.RequireTrustDomainFromString("spiffe://domain.test/path/element")
	assert.Equal(t, "spiffe://domain.test", td.IDString())

	// Empty path
	td = spiffeid.RequireTrustDomainFromString("domain.test")
	assert.Equal(t, "spiffe://domain.test", td.IDString())

	// With uppercase letters
	td = spiffeid.RequireTrustDomainFromString("DoMain.TesT")
	assert.Equal(t, "spiffe://domain.test", td.IDString())
}

func TestTrustDomainNewID(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	// Common case
	id := spiffeid.Must("domain.test", "path", "element")
	assert.Equal(t, id, td.NewID("/path/element"))

	// Without starting with a slash
	id = spiffeid.Must("domain.test", "path", "element")
	assert.Equal(t, id, td.NewID("path/element"))

	// Empty path
	id = spiffeid.Must("domain.test")
	assert.Equal(t, id, td.NewID(""))
}

func TestTrustDomainEmpty(t *testing.T) {
	assert.True(t, spiffeid.TrustDomain{}.Empty())
}
