package witbundle_test

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td  = spiffeid.RequireTrustDomainFromString("example.org")
	td2 = spiffeid.RequireTrustDomainFromString("other.org")
)

func TestNew(t *testing.T) {
	b := witbundle.New(td)
	assert.Equal(t, td, b.TrustDomain())
	assert.Empty(t, b.WITAuthorities())
}

func TestFromWITAuthorities(t *testing.T) {
	key := test.NewEC256Key(t)
	input := map[string]crypto.PublicKey{"key-1": key.Public()}

	b := witbundle.FromWITAuthorities(td, input)
	assert.Equal(t, td, b.TrustDomain())
	assert.Equal(t, input, b.WITAuthorities())

	// Mutating the input map must not affect the bundle.
	input["key-2"] = key.Public()
	assert.Len(t, b.WITAuthorities(), 1)
}

func TestWITAuthority(t *testing.T) {
	key1 := test.NewEC256Key(t)
	key2 := test.NewEC256Key(t)

	t.Run("add and find", func(t *testing.T) {
		b := witbundle.New(td)
		require.NoError(t, b.AddWITAuthority("key-1", key1.Public()))
		got, ok := b.FindWITAuthority("key-1")
		require.True(t, ok)
		assert.Equal(t, key1.Public(), got)
	})

	t.Run("add replaces existing", func(t *testing.T) {
		b := witbundle.New(td)
		require.NoError(t, b.AddWITAuthority("key-1", key1.Public()))
		require.NoError(t, b.AddWITAuthority("key-1", key2.Public()))
		got, ok := b.FindWITAuthority("key-1")
		require.True(t, ok)
		assert.Equal(t, key2.Public(), got)
	})

	t.Run("add rejects empty key ID", func(t *testing.T) {
		b := witbundle.New(td)
		require.EqualError(t, b.AddWITAuthority("", key1.Public()), "witbundle: keyID cannot be empty")
	})

	t.Run("find returns false for unknown key ID", func(t *testing.T) {
		b := witbundle.New(td)
		got, ok := b.FindWITAuthority("missing")
		assert.False(t, ok)
		assert.Nil(t, got)
	})
}

func TestWITAuthorities_DefensiveCopy(t *testing.T) {
	key := test.NewEC256Key(t)
	b := witbundle.New(td)
	require.NoError(t, b.AddWITAuthority("key-1", key.Public()))

	// Mutating the returned map must not affect the bundle.
	m := b.WITAuthorities()
	m["key-2"] = key.Public()
	assert.Len(t, b.WITAuthorities(), 1)
}

func TestParse(t *testing.T) {
	t.Run("round-trips with Marshal", func(t *testing.T) {
		key1 := test.NewEC256Key(t)
		key2 := test.NewEC256Key(t)
		original := witbundle.New(td)
		require.NoError(t, original.AddWITAuthority("key-1", key1.Public()))
		require.NoError(t, original.AddWITAuthority("key-2", key2.Public()))

		data, err := original.Marshal()
		require.NoError(t, err)

		parsed, err := witbundle.Parse(td, data)
		require.NoError(t, err)
		assert.Equal(t, td, parsed.TrustDomain())
		assert.Equal(t, original.WITAuthorities(), parsed.WITAuthorities())
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := witbundle.Parse(td, []byte("not json"))
		require.ErrorContains(t, err, "witbundle: unable to parse JWKS")
	})

	t.Run("key with empty kid", func(t *testing.T) {
		// A JWKS entry with no kid triggers AddWITAuthority("", …) → error.
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: test.NewEC256Key(t).Public()}},
		}
		data, err := json.Marshal(jwks)
		require.NoError(t, err)
		_, err = witbundle.Parse(td, data)
		require.ErrorContains(t, err, "witbundle: error adding authority")
	})
}

func TestGetWITBundleForTrustDomain(t *testing.T) {
	b := witbundle.New(td)

	t.Run("matching trust domain", func(t *testing.T) {
		got, err := b.GetWITBundleForTrustDomain(td)
		require.NoError(t, err)
		assert.Same(t, b, got)
	})

	t.Run("mismatched trust domain", func(t *testing.T) {
		_, err := b.GetWITBundleForTrustDomain(td2)
		require.EqualError(t, err, `witbundle: no WIT bundle for trust domain "other.org"`)
	})
}
