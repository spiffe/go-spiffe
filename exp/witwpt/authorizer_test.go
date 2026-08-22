package witwpt_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/exp/witwpt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizers(t *testing.T) {
	var (
		exampleTD = spiffeid.RequireTrustDomainFromString("example.org")
		otherTD   = spiffeid.RequireTrustDomainFromString("other.org")
		client    = spiffeid.RequireFromPath(exampleTD, "/client")
		server    = spiffeid.RequireFromPath(exampleTD, "/server")
		stranger  = spiffeid.RequireFromPath(otherTD, "/client")
	)

	tests := []struct {
		name       string
		authorizer witwpt.Authorizer
		id         spiffeid.ID
		err        string
	}{
		{name: "any allows anyone", authorizer: witwpt.AuthorizeAny(), id: stranger},
		{name: "id allows the match", authorizer: witwpt.AuthorizeID(client), id: client},
		{
			name:       "id rejects another id",
			authorizer: witwpt.AuthorizeID(client),
			id:         server,
			err:        `unexpected ID "spiffe://example.org/server"`,
		},
		{
			name:       "one of allows a listed id",
			authorizer: witwpt.AuthorizeOneOf(client, server),
			id:         server,
		},
		{
			name:       "one of rejects an unlisted id",
			authorizer: witwpt.AuthorizeOneOf(client, server),
			id:         stranger,
			err:        `unexpected ID "spiffe://other.org/client"`,
		},
		{
			name:       "member of allows the trust domain",
			authorizer: witwpt.AuthorizeMemberOf(exampleTD),
			id:         client,
		},
		{
			name:       "member of rejects another trust domain",
			authorizer: witwpt.AuthorizeMemberOf(exampleTD),
			id:         stranger,
			err:        `unexpected trust domain "other.org"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.authorizer(&witsvid.SVID{ID: tt.id})
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAuthorizerReceivesTheWholeCredential(t *testing.T) {
	// Passing the SVID rather than a bare ID is what lets an authorizer read
	// issuer-supplied claims, which tlsconfig.Authorizer cannot do.
	svid := &witsvid.SVID{
		ID:     spiffeid.RequireFromString("spiffe://example.org/client"),
		Claims: map[string]interface{}{"groups": []any{"admin"}},
	}

	var seen *witsvid.SVID
	authorizer := witwpt.Authorizer(func(s *witsvid.SVID) error {
		seen = s
		return nil
	})

	require.NoError(t, authorizer(svid))
	require.Same(t, svid, seen)
	assert.Equal(t, []any{"admin"}, seen.Claims["groups"])
}

func TestAdaptMatcher(t *testing.T) {
	client := spiffeid.RequireFromString("spiffe://example.org/client")

	authorizer := witwpt.AdaptMatcher(spiffeid.MatchID(client))
	require.NoError(t, authorizer(&witsvid.SVID{ID: client}))

	err := authorizer(&witsvid.SVID{ID: spiffeid.RequireFromString("spiffe://example.org/other")})
	require.EqualError(t, err, `unexpected ID "spiffe://example.org/other"`)
}

func TestAuthorizersRejectNilCredential(t *testing.T) {
	// A nil SVID means verification did not actually produce one; the built-in
	// authorizers must refuse rather than dereference it.
	require.Error(t, witwpt.AuthorizeAny()(nil))
	require.Error(t, witwpt.AuthorizeID(spiffeid.RequireFromString("spiffe://example.org/a"))(nil))
}
