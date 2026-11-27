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
			err: `proof audience "https://a.example.org" is not accepted here ` +
				`(expected one of ["https://b.example.org"])`,
		},
		{
			name:     "different port is rejected",
			accepted: []string{"https://server.example.org:8443"},
			aud:      "https://server.example.org:9443",
			err: `proof audience "https://server.example.org:9443" is not accepted here ` +
				`(expected one of ["https://server.example.org:8443"])`,
		},
		{
			name:     "different scheme is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "http://server.example.org",
			err: `proof audience "http://server.example.org" is not accepted here ` +
				`(expected one of ["https://server.example.org"])`,
		},
		{
			name:     "empty audience is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "",
			err:      `proof audience "" is not an absolute http(s) URI`,
		},
		{
			name:     "audience without a scheme is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "server.example.org",
			err:      `proof audience "server.example.org" is not an absolute http(s) URI`,
		},
		{
			name:     "IPv6 host with a port matches",
			accepted: []string{"https://[::1]:8443"},
			aud:      "https://[::1]:8443/v2/orders",
		},
		{
			name:     "IPv6 host with a default port matches without it",
			accepted: []string{"https://[::1]"},
			aud:      "https://[::1]:443",
		},
		{
			name:     "IPv6 host does not collide with a longer address",
			accepted: []string{"https://[::1]:8443"},
			aud:      "https://[::1:8443]",
			err: `proof audience "https://[::1:8443]" is not accepted here ` +
				`(expected one of ["https://[::1]:8443"])`,
		},
		{
			name:     "SPIFFE ID audience is rejected rather than collapsed to its trust domain",
			accepted: []string{"https://server.example.org"},
			aud:      "spiffe://example.org/server-b",
			err:      `proof audience "spiffe://example.org/server-b" is not an absolute http(s) URI`,
		},
		{
			name:     "URN audience is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "urn:example:server",
			err:      `proof audience "urn:example:server" is not an absolute http(s) URI`,
		},
		{
			name:     "audience without a host is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "https://:443",
			err:      `proof audience "https://:443" is not an absolute http(s) URI`,
		},
		{
			name:     "unparsable audience is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "https://%zz",
			err:      `proof audience "https://%zz" is not an absolute http(s) URI`,
		},
		{
			name:     "audience with userinfo is rejected",
			accepted: []string{"https://server.example.org"},
			aud:      "https://evil@server.example.org",
			err:      `proof audience "https://evil@server.example.org" is not an absolute http(s) URI`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := witwpt.AcceptAudience(tt.accepted...)
			require.NoError(t, err)

			err = matcher(tt.aud)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAcceptAudienceRejectsBadConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		err    string
	}{
		{
			name:   "no values",
			values: nil,
			err:    "witwpt: no audiences provided",
		},
		{
			name:   "value without a scheme",
			values: []string{"https://server.example.org", "not a uri"},
			err:    `witwpt: audience "not a uri" is not an absolute http(s) URI`,
		},
		{
			name:   "SPIFFE ID value",
			values: []string{"spiffe://example.org/server-a"},
			err:    `witwpt: audience "spiffe://example.org/server-a" is not an absolute http(s) URI`,
		},
		{
			name:   "value with userinfo",
			values: []string{"https://user@server.example.org"},
			err:    `witwpt: audience "https://user@server.example.org" is not an absolute http(s) URI`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := witwpt.AcceptAudience(tt.values...)
			require.EqualError(t, err, tt.err)
			assert.Nil(t, matcher)
		})
	}
}

func TestAcceptTargetURI(t *testing.T) {
	tests := []struct {
		name     string
		accepted string
		aud      string
		err      string
	}{
		{
			name:     "same route",
			accepted: "https://server.example.org/v2/orders",
			aud:      "https://server.example.org/v2/orders",
		},
		{
			name:     "query and fragment are ignored",
			accepted: "https://server.example.org/v2/orders",
			aud:      "https://server.example.org:443/v2/orders?page=2#top",
		},
		{
			name:     "empty path is the root path",
			accepted: "https://Server.Example.org/",
			aud:      "https://server.example.org",
		},
		{
			name:     "another route on the same host is rejected",
			accepted: "https://server.example.org/v2/orders",
			aud:      "https://server.example.org/v2/admin",
			err: `proof audience "https://server.example.org/v2/admin" is not accepted here ` +
				`(expected one of ["https://server.example.org/v2/orders"])`,
		},
		{
			name:     "path compares case-sensitively",
			accepted: "https://server.example.org/v2/orders",
			aud:      "https://server.example.org/V2/Orders",
			err: `proof audience "https://server.example.org/V2/Orders" is not accepted here ` +
				`(expected one of ["https://server.example.org/v2/orders"])`,
		},
		{
			name:     "trailing slash names another route",
			accepted: "https://server.example.org/v2/orders",
			aud:      "https://server.example.org/v2/orders/",
			err: `proof audience "https://server.example.org/v2/orders/" is not accepted here ` +
				`(expected one of ["https://server.example.org/v2/orders"])`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := witwpt.AcceptTargetURI(tt.accepted)
			require.NoError(t, err)

			err = matcher(tt.aud)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}

	_, err := witwpt.AcceptTargetURI()
	require.EqualError(t, err, "witwpt: no audiences provided")
}
