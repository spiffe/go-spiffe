package spiffe

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateID(t *testing.T) {
	tests := []struct {
		name          string
		spiffeID      string
		mode          ValidationMode
		expectedError string
	}{
		// General validation
		{
			name:          "test_validate_id_empty_id",
			spiffeID:      "",
			mode:          AllowAny(),
			expectedError: `invalid SPIFFE ID "": SPIFFE ID is empty`,
		},
		{
			name:          "test_validate_id_invalid_uri",
			spiffeID:      "192.168.2.2:6688",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID: parse 192.168.2.2:6688: first path segment in URL cannot contain colon",
		},
		{
			name:          "test_validate_id_invalid_scheme",
			spiffeID:      "http://domain.test/path/validate",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID \"http://domain.test/path/validate\": invalid scheme",
		},
		{
			name:     "test_validate_id_scheme_mixed_case",
			spiffeID: "SPIFFE://domain.test/path/validate",
			mode:     AllowAny(),
		},
		{
			name:          "test_validate_id_empty_host",
			spiffeID:      "spiffe:///path/validate",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID \"spiffe:///path/validate\": trust domain is empty",
		},
		{
			name:          "test_validate_id_query_not_allowed",
			spiffeID:      "spiffe://domain.test/path/validate?query=1",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID \"spiffe://domain.test/path/validate?query=1\": query is not allowed",
		},
		{
			name:          "test_validate_id_fragmentnot_allowed",
			spiffeID:      "spiffe://domain.test/path/validate?#fragment-1",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID \"spiffe://domain.test/path/validate?#fragment-1\": fragment is not allowed",
		},
		{
			name:          "test_validate_id_port_not_allowed",
			spiffeID:      "spiffe://domain.test:8080/path/validate",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID \"spiffe://domain.test:8080/path/validate\": port is not allowed",
		},
		{
			name:          "test_validate_id_user_info_not_allowed",
			spiffeID:      "spiffe://user:password@test.org/path/validate",
			mode:          AllowAny(),
			expectedError: "invalid SPIFFE ID \"spiffe://user:password@test.org/path/validate\": user info is not allowed",
		},
		// AllowAny() mode
		{
			name:     "test_allow_any_with_trust_domain_id",
			spiffeID: "spiffe://domain.test",
			mode:     AllowAny(),
		},
		{
			name:     "test_allow_any_with_trust_domain_workload_id",
			spiffeID: "spiffe://domain.test/path",
			mode:     AllowAny(),
		},
		// AllowTrustDomain() mode
		{
			name:     "test_allow_trust_domain_good",
			spiffeID: "spiffe://domain.test",
			mode:     AllowTrustDomain("domain.test"),
		},
		{
			name:          "test_allow_trust_domain_empty_domain_to_validate",
			spiffeID:      "spiffe://domain.test",
			mode:          AllowTrustDomain(""),
			expectedError: "trust domain to validate against cannot be empty",
		},
		{
			name:          "test_allow_trust_domain_invalid",
			spiffeID:      "spiffe://otherdomain.test",
			mode:          AllowTrustDomain("domain.test"),
			expectedError: `"spiffe://otherdomain.test" does not belong to trust domain "domain.test"`,
		},
		{
			name:          "test_allow_trust_domain_with_a_workload",
			spiffeID:      "spiffe://domain.test/path",
			mode:          AllowTrustDomain("domain.test"),
			expectedError: `invalid trust domain SPIFFE ID "spiffe://domain.test/path": path is not empty`,
		},
		// AllowTrustDomainWorkload() mode
		{
			name:     "test_allow_trust_domain_workload_good",
			spiffeID: "spiffe://domain.test/path",
			mode:     AllowTrustDomainWorkload("domain.test"),
		},
		{
			name:          "test_allow_trust_domain_workload_invalid_trust_domain",
			spiffeID:      "spiffe://otherdomain.test/path",
			mode:          AllowTrustDomainWorkload("domain.test"),
			expectedError: `"spiffe://otherdomain.test/path" does not belong to trust domain "domain.test"`,
		},
		{
			name:          "test_allow_trust_domain_workload_missing_path",
			spiffeID:      "spiffe://domain.test",
			mode:          AllowTrustDomainWorkload("domain.test"),
			expectedError: `invalid workload SPIFFE ID "spiffe://domain.test": path is empty`,
		},
		// AllowAnyTrustDomain() mode
		{
			name:     "test_allow_any_trust_domain_good",
			spiffeID: "spiffe://otherdomain.test",
			mode:     AllowAnyTrustDomain(),
		},
		{
			name:          "test_allow_any_trust_domain_with_a_workload",
			spiffeID:      "spiffe://otherdomain.test/path",
			mode:          AllowAnyTrustDomain(),
			expectedError: `invalid trust domain SPIFFE ID "spiffe://otherdomain.test/path": path is not empty`,
		},
		// AllowAnyTrustDomainWorkload() mode
		{
			name:     "test_allow_any_trust_domain_workload_good",
			spiffeID: "spiffe://otherdomain.test/path",
			mode:     AllowAnyTrustDomainWorkload(),
		},
		{
			name:          "test_allow_any_trust_domain_workload_missing path",
			spiffeID:      "spiffe://otherdomain.test",
			mode:          AllowAnyTrustDomainWorkload(),
			expectedError: `invalid workload SPIFFE ID "spiffe://otherdomain.test": path is empty`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateID(test.spiffeID, test.mode)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestNormalizeID(t *testing.T) {
	tests := []struct {
		name          string
		in            string
		out           string
		expectedError string
	}{
		{name: "scheme and host are lowercased", in: "SpIfFe://HoSt", out: "spiffe://host"},
		{name: "path casing is preserved", in: "SpIfFe://HoSt/PaTh", out: "spiffe://host/PaTh"},
		// url.Parse calls ToLower on scheme
		{name: "invalid id returns error", in: "spOOfy://HoSt/PaTh", expectedError: `invalid SPIFFE ID "spoofy://HoSt/PaTh": invalid scheme`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := NormalizeID(test.in, AllowAny())
			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
				assert.Empty(t, out)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, test.out, out)
		})
	}
}

func TestNormalizeURI(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		in := &url.URL{
			Scheme: "spOOfy",
			Host:   "HoSt",
			Path:   "PaTh",
		}
		out, err := NormalizeURI(in, AllowAny())
		assert.Nil(t, out)
		assert.EqualError(t, err, `invalid SPIFFE ID "spOOfy://HoSt/PaTh": invalid scheme`)
	})

	t.Run("valid", func(t *testing.T) {
		in := &url.URL{
			Scheme: "SpIfFe",
			Host:   "HoSt",
			Path:   "PaTh",
		}
		want := &url.URL{
			Scheme: "spiffe",
			Host:   "host",
			Path:   "PaTh",
		}

		out, err := NormalizeURI(in, AllowAny())
		assert.NoError(t, err)
		assert.Equal(t, want, out)
	})
}
