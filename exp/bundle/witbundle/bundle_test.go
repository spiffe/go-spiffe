package witbundle_test

import (
	"crypto"
	"encoding/json"
	"os"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/errstrings"
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

	t.Run("has", func(t *testing.T) {
		b := witbundle.New(td)
		require.NoError(t, b.AddWITAuthority("key-1", key1.Public()))
		assert.True(t, b.HasWITAuthority("key-1"))
		assert.False(t, b.HasWITAuthority("missing"))
	})

	t.Run("remove", func(t *testing.T) {
		b := witbundle.New(td)
		require.NoError(t, b.AddWITAuthority("key-1", key1.Public()))
		require.NoError(t, b.AddWITAuthority("key-2", key2.Public()))

		// Removing an unknown key ID is a no-op.
		b.RemoveWITAuthority("missing")
		assert.Len(t, b.WITAuthorities(), 2)

		b.RemoveWITAuthority("key-2")
		assert.Len(t, b.WITAuthorities(), 1)
		assert.True(t, b.HasWITAuthority("key-1"))
	})

	t.Run("set replaces existing authorities", func(t *testing.T) {
		b := witbundle.New(td)
		require.NoError(t, b.AddWITAuthority("key-1", key1.Public()))

		input := map[string]crypto.PublicKey{"key-2": key2.Public()}
		b.SetWITAuthorities(input)
		assert.Equal(t, input, b.WITAuthorities())

		// Mutating the input map must not affect the bundle.
		input["key-3"] = key1.Public()
		assert.Len(t, b.WITAuthorities(), 1)
	})
}

func TestEmpty(t *testing.T) {
	b := witbundle.New(td)
	assert.True(t, b.Empty())

	key := test.NewEC256Key(t)
	require.NoError(t, b.AddWITAuthority("key-1", key.Public()))
	assert.False(t, b.Empty())
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

func TestLoad(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expectedCount int
		expectedErr   string
	}{
		{
			name:          "valid with one key",
			path:          "testdata/jwks_valid_1.json",
			expectedCount: 1,
		},
		{
			name:          "valid with two keys",
			path:          "testdata/jwks_valid_2.json",
			expectedCount: 2,
		},
		{
			name:        "non existent file",
			path:        "testdata/does-not-exist.json",
			expectedErr: "witbundle: unable to read WIT bundle: open testdata/does-not-exist.json: " + errstrings.FileNotFound,
		},
		{
			name:        "missing kid",
			path:        "testdata/jwks_missing_kid.json",
			expectedErr: "witbundle: error adding authority 1 of JWKS: keyID cannot be empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := witbundle.Load(td, tt.path)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, td, b.TrustDomain())
			assert.Len(t, b.WITAuthorities(), tt.expectedCount)
		})
	}
}

func TestRead(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expectedCount int
		expectedErr   string
	}{
		{
			name:          "valid with one key",
			path:          "testdata/jwks_valid_1.json",
			expectedCount: 1,
		},
		{
			name:          "valid with two keys",
			path:          "testdata/jwks_valid_2.json",
			expectedCount: 2,
		},
		{
			name:        "unreadable reader",
			path:        "testdata/does-not-exist.json",
			expectedErr: "witbundle: unable to read: invalid argument",
		},
		{
			name:        "missing kid",
			path:        "testdata/jwks_missing_kid.json",
			expectedErr: "witbundle: error adding authority 1 of JWKS: keyID cannot be empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The Open call is expected to fail in the unreadable reader
			// case, which makes Read fail when reading from the nil file.
			file, _ := os.Open(tt.path)
			defer file.Close()

			b, err := witbundle.Read(td, file)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, td, b.TrustDomain())
			assert.Len(t, b.WITAuthorities(), tt.expectedCount)
		})
	}
}

func TestEqual(t *testing.T) {
	key1 := test.NewEC256Key(t)
	key2 := test.NewEC256Key(t)

	empty := witbundle.New(td)
	empty2 := witbundle.New(td2)

	authorities1 := witbundle.FromWITAuthorities(td, map[string]crypto.PublicKey{"key-1": key1.Public()})
	authorities2 := witbundle.FromWITAuthorities(td, map[string]crypto.PublicKey{"key-2": key2.Public()})

	tests := []struct {
		name        string
		a           *witbundle.Bundle
		b           *witbundle.Bundle
		expectEqual bool
	}{
		{
			name:        "empty equal",
			a:           empty,
			b:           empty,
			expectEqual: true,
		},
		{
			name:        "different trust domains",
			a:           empty,
			b:           empty2,
			expectEqual: false,
		},
		{
			name:        "WIT authorities equal",
			a:           authorities1,
			b:           authorities1,
			expectEqual: true,
		},
		{
			name:        "WIT authorities empty and not empty",
			a:           empty,
			b:           authorities1,
			expectEqual: false,
		},
		{
			name:        "WIT authorities not empty but not equal",
			a:           authorities1,
			b:           authorities2,
			expectEqual: false,
		},
		{
			name:        "nil and not nil",
			a:           nil,
			b:           empty,
			expectEqual: false,
		},
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			expectEqual: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectEqual, tt.a.Equal(tt.b))
		})
	}
}

func TestClone(t *testing.T) {
	key := test.NewEC256Key(t)
	original := witbundle.FromWITAuthorities(td, map[string]crypto.PublicKey{"key-1": key.Public()})

	cloned := original.Clone()
	require.True(t, original.Equal(cloned))

	// Mutating the clone must not affect the original.
	cloned.RemoveWITAuthority("key-1")
	assert.True(t, original.HasWITAuthority("key-1"))
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
