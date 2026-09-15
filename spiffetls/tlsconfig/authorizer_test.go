package tlsconfig_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeIDPrefix(t *testing.T) {
	authorizer := tlsconfig.AuthorizeIDPrefix(spiffeid.RequireFromString("spiffe://example.org/spire/agent"))

	assert.NoError(t, authorizer(spiffeid.RequireFromString("spiffe://example.org/spire/agent"), nil))
	assert.NoError(t, authorizer(spiffeid.RequireFromString("spiffe://example.org/spire/agent/node-a"), nil))
	assert.EqualError(t,
		authorizer(spiffeid.RequireFromString("spiffe://example.org/spire/agentish"), nil),
		`unexpected ID "spiffe://example.org/spire/agentish"`,
	)
}
