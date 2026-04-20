package witbundle_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

// td and td2 are defined in bundle_test.go (same package).

var b1 = witbundle.New(td)

func TestNewSet(t *testing.T) {
	s := witbundle.NewSet(b1)
	require.True(t, s.Has(td))

	s = witbundle.NewSet(witbundle.New(td), witbundle.New(td2))
	require.True(t, s.Has(td))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := witbundle.NewSet()
	require.False(t, s.Has(td))
	s.Add(b1)
	require.True(t, s.Has(td))
}

func TestRemove(t *testing.T) {
	s := witbundle.NewSet(b1)
	require.True(t, s.Has(td))
	s.Remove(td2)
	require.True(t, s.Has(td))
	s.Remove(td)
	require.False(t, s.Has(td))
}

func TestHas(t *testing.T) {
	s := witbundle.NewSet(witbundle.New(td))
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td))
}

func TestGet(t *testing.T) {
	s := witbundle.NewSet(b1)

	b, ok := s.Get(td)
	require.True(t, ok)
	require.Equal(t, b1, b)

	b, ok = s.Get(td2)
	require.False(t, ok)
	require.Nil(t, b)
}

func TestLen(t *testing.T) {
	s := witbundle.NewSet()
	require.Equal(t, 0, s.Len())

	s.Add(witbundle.New(td))
	require.Equal(t, 1, s.Len())

	s.Add(witbundle.New(td2))
	require.Equal(t, 2, s.Len())

	s.Remove(td)
	require.Equal(t, 1, s.Len())
}

func TestBundles(t *testing.T) {
	td3 := spiffeid.RequireTrustDomainFromString("third.org")
	s := witbundle.NewSet(witbundle.New(td3), witbundle.New(td), witbundle.New(td2))

	bundles := s.Bundles()
	require.Len(t, bundles, 3)
	require.Equal(t, td, bundles[0].TrustDomain())
	require.Equal(t, td2, bundles[1].TrustDomain())
	require.Equal(t, td3, bundles[2].TrustDomain())
}

func TestSetGetWITBundleForTrustDomain(t *testing.T) {
	s := witbundle.NewSet(b1)
	_, err := s.GetWITBundleForTrustDomain(td2)
	require.EqualError(t, err, `witbundle: no WIT bundle for trust domain "other.org"`)

	b, err := s.GetWITBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}
