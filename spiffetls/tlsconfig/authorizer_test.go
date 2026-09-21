package tlsconfig_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeIDPrefix(t *testing.T) {
	authorizer := tlsconfig.AuthorizeIDPrefix(spiffeid.RequireFromString("spiffe://example.org/spire/agent"))

	testCases := []struct {
		name string
		id   spiffeid.ID
		err  string
	}{
		{
			name: "exact match",
			id:   spiffeid.RequireFromString("spiffe://example.org/spire/agent"),
		},
		{
			name: "path on a segment boundary",
			id:   spiffeid.RequireFromString("spiffe://example.org/spire/agent/node-a"),
		},
		{
			name: "path not on a segment boundary",
			id:   spiffeid.RequireFromString("spiffe://example.org/spire/agentish"),
			err:  `unexpected ID "spiffe://example.org/spire/agentish"`,
		},
		{
			name: "different trust domain",
			id:   spiffeid.RequireFromString("spiffe://other.org/spire/agent"),
			err:  `unexpected ID "spiffe://other.org/spire/agent"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := authorizer(testCase.id, nil)
			if testCase.err != "" {
				assert.EqualError(t, err, testCase.err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestAuthorizeIDPrefix_WithoutPath(t *testing.T) {
	authorizer := tlsconfig.AuthorizeIDPrefix(spiffeid.RequireFromString("spiffe://example.org"))

	assert.EqualError(t,
		authorizer(spiffeid.RequireFromString("spiffe://example.org/spire/agent"), nil),
		"prefix must have a path",
	)
}
