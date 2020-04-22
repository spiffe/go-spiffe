package jwtbundle_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	b1  = jwtbundle.New(td)
	td2 = spiffeid.RequireTrustDomainFromString("example-2.org")
)

func TestNewSet(t *testing.T) {
	s := jwtbundle.NewSet(b1)
	require.True(t, s.Has(td))

	s = jwtbundle.NewSet(jwtbundle.New(td), jwtbundle.New(td2))
	require.True(t, s.Has(td))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := jwtbundle.NewSet()
	require.False(t, s.Has(td))
	s.Add(b1)
	require.True(t, s.Has(td))
}

func TestRemove(t *testing.T) {
	s := jwtbundle.NewSet(b1)
	require.True(t, s.Has(td))
	s.Remove(td2)
	require.True(t, s.Has(td))
	s.Remove(td)
	require.False(t, s.Has(td))
}

func TestHas(t *testing.T) {
	s := jwtbundle.NewSet(jwtbundle.New(td))
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td))
}

func TestSetGetJWTBundleForTrustDomain(t *testing.T) {
	s := jwtbundle.NewSet(b1)
	_, err := s.GetJWTBundleForTrustDomain(td2)
	require.EqualError(t, err, `jwtbundle: no JWT bundle for trust domain "example-2.org"`)

	b, err := s.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}
