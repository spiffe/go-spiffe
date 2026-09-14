package witwpt_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptAudience(t *testing.T) {
	tests := []struct {
		name     string
		accepted []string
		aud      string
		err      string
	}{
		{
			name:     "exact match",
			accepted: []string{"https://server.example.org"},
			aud:      "https://server.example.org",
		},
		{
			name:     "path on the received audience is ignored",
			accepted: []string{"https://server.example.org"},
			aud:      "https://server.example.org/v2/orders",
		},
		{
			name:     "query and fragment on the received audience are ignored",
			accepted: []string{"https://server.example.org"},
			aud:      "https://server.example.org/v2/orders?page=2#top",
		},
		{
			name:     "path on the configured value is ignored",
			accepted: []string{"https://server.example.org/v2/"},
			aud:      "https://server.example.org/v2/orders",
		},
		{
			name:     "trailing slash on either side is ignored",
			accepted: []string{"https://server.example.org/"},
			aud:      "https://server.example.org",
		},
		{
			name:     "default https port is dropped from the received audience",
			accepted: []string{"https://server.example.org"},
			aud:      "https://server.example.org:443/v2/orders",
		},
		{
			name:     "default https port is dropped from the configured value",
			accepted: []string{"https://server.example.org:443"},
			aud:      "https://server.example.org",
		},
		{
			name:     "default http port is dropped",
			accepted: []string{"http://server.example.org"},
			aud:      "http://server.example.org:80/health",
		},
		{
			name:     "scheme and host compare case-insensitively",
			accepted: []string{"https://Server.Example.ORG"},
			aud:      "HTTPS://server.example.org",
		},
		{
			name:     "non-default port must match",
			accepted: []string{"https://server.example.org:50051"},
			aud:      "https://server.example.org:50051/helloworld.Greeter",
		},
		{
			name:     "one of several configured values matches",
			accepted: []string{"https://a.example.org", "https://b.example.org"},
			aud:      "https://b.example.org/api",
		},
		{
			name:     "different host is rejected",
			accepted: []string{"https://b.example.org"},
			aud:      "https://a.example.org",
			err: `witwpt: proof audience "https://a.example.org" is not accepted here ` +
				`(expected one of ["https://b.example.org"])`,
		},
		{
			name:     "different port is rejected",
			accepted: []string{"https://server.example.org:8443"},
			aud:      "https://server.example.org:9443",
			err: `witwpt: proof audience "https://server.example.org:9443" is not accepted here ` +
				`(expected one of ["https://server.example.org:8443"])`,
		},
		{
			name:     "different scheme is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "http://server.example.org",
			err: `witwpt: proof audience "http://server.example.org" is not accepted here ` +
				`(expected one of ["https://server.example.org"])`,
		},
		{
			name:     "empty audience is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "",
			err:      "witwpt: proof is missing the aud claim",
		},
		{
			name:     "audience without a scheme is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "server.example.org",
			err:      `witwpt: proof audience "server.example.org" is not a valid absolute URI`,
		},
		{
			name:     "no configured values accepts nothing",
			accepted: nil,
			aud:      "https://server.example.org",
			err: `witwpt: proof audience "https://server.example.org" is not accepted here ` +
				`(expected one of [])`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := witwpt.AcceptAudience(tt.accepted...)(tt.aud)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAcceptAudienceReportsMalformedConfiguredValue(t *testing.T) {
	// A configured value the library cannot normalize must never match, and the
	// error has to show the operator what they configured so it is diagnosable.
	err := witwpt.AcceptAudience("not a uri")("https://server.example.org")
	assert.ErrorContains(t, err, `"not a uri"`)
}
